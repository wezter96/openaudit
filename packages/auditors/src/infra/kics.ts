import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import {
	type AuditContext,
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord, kebab, scrubLine, truncate } from "../codebase/util";
import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { targetFiles } from "./shared";

/** Files KICS has queries for: Terraform, Dockerfiles, Kubernetes/CFN/Ansible/Compose YAML, Bicep. */
const KICS_RE =
	/\.(tf|tfvars|hcl|bicep)$|(^|\/)(Dockerfile[^/]*|[^/]*\.dockerfile)$|\.ya?ml$/;

/** A path on disk or relative to the scanned root. */
type FilePath = string;

const SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MEDIUM: "medium",
	LOW: "low",
	INFO: "info",
	TRACE: "info",
};

const CATEGORY = new Map<string | undefined, Category>([
	["Best Practices", "best-practices"],
	["Build Process", "best-practices"],
	["Structure and Semantics", "best-practices"],
	["Availability", "reliability"],
	["Backup", "reliability"],
	["Resource Management", "reliability"],
	["Observability", "reliability"],
	["Supply-Chain", "supply-chain"],
]);

const categoryOf = (kicsCategory: string | undefined): Category =>
	CATEGORY.get(kicsCategory) ?? "security";

const isReplacementFix = (
	fix: unknown,
): fix is { before: unknown; after: unknown } =>
	isRecord(fix) && fix.before !== undefined && fix.after !== undefined;

/**
 * KICS `remediation` is either plain replacement text or, for
 * `replacement` fixes, a JSON string like `{"before":"true","after":"false"}`.
 */
const remediationText = (raw: string | undefined): string | undefined => {
	if (!raw) return undefined;
	if (raw.startsWith("{"))
		try {
			const fix: unknown = JSON.parse(raw);
			if (isReplacementFix(fix))
				return `Change ${scrubLine(String(fix.before))} to ${scrubLine(String(fix.after))}.`;
		} catch {
			// Not JSON after all; use the raw text.
		}
	return raw;
};

/** The per-query fields every file-level finding shares. */
interface KicsQuery {
	readonly name: string;
	readonly queryId: string | undefined;
	readonly platform: string;
	readonly url: string | undefined;
	readonly cwe: string | undefined;
	readonly description: string | undefined;
	readonly severity: Severity;
	readonly category: Category;
}

const kicsQuery = (rawQuery: Record<string, unknown>): KicsQuery => ({
	name: str(rawQuery.query_name) ?? "Unknown query",
	queryId: str(rawQuery.query_id),
	platform: str(rawQuery.platform) ?? "iac",
	url: str(rawQuery.query_url),
	cwe: str(rawQuery.cwe),
	description: str(rawQuery.description),
	severity: SEVERITY[String(rawQuery.severity).toUpperCase()] ?? "medium",
	category: categoryOf(str(rawQuery.category)),
});

/** Relative `file_name`s are relative to `root`. */
const kicsFile = (
	rawFile: Record<string, unknown>,
	root: FilePath,
): FilePath | undefined => {
	const fileName = str(rawFile.file_name)?.split("\\").join("/");
	if (!fileName) return undefined;
	return relPath(
		root,
		isAbsolute(fileName) ? fileName : resolve(root, fileName),
	);
};

const fallbackRemediation = (expected: string | undefined): string =>
	expected ? `Expected: ${expected}` : "See the KICS query documentation.";

const kicsFinding = (
	query: KicsQuery,
	rawFile: Record<string, unknown>,
	root: FilePath,
): FindingInput => {
	const actual = str(rawFile.actual_value);
	const searchKey = str(rawFile.search_key);
	return {
		ruleId: `iac.kics/${kebab(query.platform)}-${kebab(query.name)}`,
		title: query.name,
		severity: query.severity,
		category: query.category,
		message: [query.description, actual && `Found: ${actual}`]
			.filter(Boolean)
			.join(". "),
		remediation:
			remediationText(str(rawFile.remediation)) ||
			fallbackRemediation(str(rawFile.expected_value)),
		location: { file: kicsFile(rawFile, root), line: num(rawFile.line) },
		evidence: searchKey ? scrubLine(truncate(searchKey)) : undefined,
		references: query.url ? [query.url] : undefined,
		confidence: "medium",
		tags: [
			"kics",
			query.platform.toLowerCase(),
			...(query.cwe ? [`cwe-${query.cwe}`] : []),
			...(query.queryId ? [query.queryId] : []),
		],
	};
};

/** Parses KICS `results.json`. Relative `file_name`s are relative to `root`. */
export const parseKicsReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.queries).flatMap((rawQuery): FindingInput[] => {
		if (!isRecord(rawQuery)) return [];
		const query = kicsQuery(rawQuery);
		return arr(rawQuery.files)
			.filter(isRecord)
			.map((rawFile) => kicsFinding(query, rawFile, root));
	});
};

const createOutDir = Effect.tryPromise({
	try: () => mkdtemp(join(tmpdir(), "openaudit-kics-")),
	catch: (cause) =>
		new AuditorError({
			message: "Could not create KICS output dir",
			cause,
		}),
});

const readReport = (outDir: FilePath) =>
	Effect.tryPromise({
		try: () => readFile(join(outDir, "results.json"), "utf8"),
		catch: (cause) =>
			new AuditorError({
				message: "KICS did not write a report",
				cause,
			}),
	});

const scanPathOf = (ctx: AuditContext, root: FilePath): FilePath =>
	ctx.target.type === "file" && ctx.target.file
		? resolve(root, ctx.target.file)
		: root;

const kicsArgs = (bin: FilePath, scanPath: FilePath, outDir: FilePath) => [
	bin,
	"scan",
	"-p",
	scanPath,
	"-o",
	outDir,
	"--report-formats",
	"json",
	"--output-name",
	"results",
	"--no-progress",
	"--silent",
	"--no-color",
	"--disable-secrets",
	"--ignore-on-exit",
	"results",
];

/** Wraps KICS (Checkmarx), an IaC scanner with a large query library. */
export const kics = defineAuditor({
	id: "iac.kics",
	title: "KICS",
	description:
		"Runs KICS over Terraform, Dockerfiles, Kubernetes, CloudFormation, Ansible, Bicep and Compose files. Secrets scanning is disabled (use the secret scanners); KICS 2.x scans entirely offline. Results go to a temporary directory, never the target.",
	categories: ["security", "best-practices", "reliability"],
	targets: ["iac"],
	engine: "external",
	tool: "kics",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, KICS_RE);
			if (files.length === 0) return yield* skip("No IaC files found");
			const bin = yield* requireTool(
				ctx,
				"kics",
				"Install: brew install checkmarx/kics/kics or use the Docker image (https://docs.kics.io/latest/getting-started/). The binary needs its assets/queries directory (set KICS_QUERIES_PATH if it is not found).",
			);
			const outDir = yield* createOutDir;
			const text = yield* runTool(
				ctx,
				kicsArgs(bin, scanPathOf(ctx, ws.root), outDir),
				ws.root,
				// 0 = clean; 20/30/40/50/60 = highest severity found (info..critical).
				[0, 20, 30, 40, 50, 60],
			).pipe(
				Effect.andThen(readReport(outDir)),
				Effect.ensuring(
					Effect.promise(() => rm(outDir, { recursive: true, force: true })),
				),
			);
			return parseKicsReport(yield* parseJson(text, "kics"), ws.root);
		}),
});
