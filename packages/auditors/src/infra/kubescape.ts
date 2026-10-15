import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import {
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord, scrubLine, truncate } from "../codebase/util";
import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { kubernetesManifests } from "./shared";

/** Controls about capacity and availability rather than security. */
const RELIABILITY = new Set(["C-0004", "C-0050", "C-0018", "C-0056"]);

type JsonRecord = Record<string, unknown>;

const recordAt = (value: unknown): JsonRecord => (isRecord(value) ? value : {});

/**
 * Kubescape control `scoreFactor` (0-10) to severity, using Kubescape's own
 * buckets: 9+ critical, 7-8 high, 4-6 medium, 1-3 low, otherwise unknown.
 */
const severityOf = (scoreFactor: number | undefined): Severity => {
	if (scoreFactor === undefined) return "medium";
	if (scoreFactor >= 9) return "critical";
	if (scoreFactor >= 7) return "high";
	if (scoreFactor >= 4) return "medium";
	if (scoreFactor >= 1) return "low";
	return "info";
};

const fixText = (paths: ReadonlyArray<Record<string, unknown>>): string => {
	const fixes = paths.flatMap((p) => {
		const fix = recordAt(p.fixPath);
		const path = str(fix.path);
		if (path) return [`set ${path} to ${JSON.stringify(fix.value ?? "")}`];
		// Real reports leave fixPath empty and name the field to remove instead.
		const remove = str(p.deletePath);
		return remove ? [`remove ${remove}`] : [];
	});
	return fixes.length > 0 ? `Suggested: ${fixes.slice(0, 3).join("; ")}.` : "";
};

/** An absolute or root-relative path as Kubescape reports it. */
type FilePath = string;

/** Where a scanned resource lives and how to name it in messages. */
interface ResourceContext {
	readonly controls: JsonRecord;
	readonly file: FilePath | undefined;
	readonly label: string;
}

const indexResources = (raw: unknown): Map<string, JsonRecord> => {
	const resources = new Map<string, JsonRecord>();
	for (const r of arr(raw))
		if (isRecord(r) && typeof r.resourceID === "string")
			resources.set(r.resourceID, r);
	return resources;
};

/**
 * Kubescape reports the manifest's directory as `path` and only its
 * basename as `relativePath`; older builds put the file in `path`.
 */
const absoluteFileOf = (
	abs: FilePath | undefined,
	base: FilePath | undefined,
): FilePath | undefined => {
	if (!abs || !base) return abs;
	return abs.endsWith(base) ? abs : join(abs, base);
};

const isInsideRoot = (root: FilePath, absFile: FilePath): boolean =>
	isAbsolute(absFile) && !relative(root, absFile).startsWith("..");

const fileOf = (root: FilePath, source: JsonRecord): FilePath | undefined => {
	const base = str(source.relativePath);
	const absFile = absoluteFileOf(str(source.path), base);
	if (absFile && isInsideRoot(root, absFile)) return relPath(root, absFile);
	return base ?? absFile;
};

const resourceContext = (
	root: FilePath,
	controls: JsonRecord,
	resource: JsonRecord | undefined,
): ResourceContext => {
	const object = recordAt(resource?.object);
	const meta = recordAt(object.metadata);
	return {
		controls,
		file: fileOf(root, recordAt(resource?.source)),
		label: [str(object.kind), str(meta.name)].filter(Boolean).join("/"),
	};
};

const failedPaths = (paths: ReadonlyArray<JsonRecord>): string[] =>
	paths
		.map((p) => str(p.failedPath) ?? str(p.reviewPath) ?? str(p.deletePath))
		.filter((p): p is string => Boolean(p));

const evidenceOf = (
	failed: ReadonlyArray<string>,
	label: string,
): string | undefined =>
	failed.length > 0
		? scrubLine(truncate(failed.slice(0, 3).join(", ")))
		: label || undefined;

const isFailed = (control: JsonRecord): boolean =>
	recordAt(control.status).status === "failed";

const controlFinding = (
	rawControl: unknown,
	{ controls, file, label }: ResourceContext,
): FindingInput[] => {
	if (!isRecord(rawControl) || !isFailed(rawControl)) return [];
	const id = str(rawControl.controlID);
	if (!id) return [];
	const name = str(rawControl.name) ?? id;
	const summaryControl = recordAt(controls[id]);
	const paths = arr(rawControl.rules)
		.filter(isRecord)
		.flatMap((rule) => arr(rule.paths).filter(isRecord));
	const fixes = fixText(paths);
	const category: Category = RELIABILITY.has(id) ? "reliability" : "security";
	return [
		{
			ruleId: `iac.kubescape/${id.toLowerCase()}`,
			title: `${id}: ${name}`,
			severity: severityOf(num(summaryControl.scoreFactor)),
			category,
			message: `${name} failed${label ? ` for ${label}` : ""}.`,
			remediation:
				`${fixes} See the Kubescape control ${id} documentation.`.trim(),
			// Kubescape reports YAML paths, not line numbers.
			location: { file },
			evidence: evidenceOf(failedPaths(paths), label),
			references: [`https://hub.armosec.io/docs/${id.toLowerCase()}`],
			tags: ["kubescape", id.toLowerCase()],
		},
	];
};

/** Parses Kubescape `--format json` (v2 posture report) output. */
export const parseKubescapeReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const controls = recordAt(recordAt(json.summaryDetails).controls);
	const resources = indexResources(json.resources);
	return arr(json.results).flatMap((rawResult): FindingInput[] => {
		if (!isRecord(rawResult)) return [];
		const resource = resources.get(str(rawResult.resourceID) ?? "");
		const context = resourceContext(root, controls, resource);
		return arr(rawResult.controls).flatMap((rawControl) =>
			controlFinding(rawControl, context),
		);
	});
};

/** Wraps Kubescape for Kubernetes manifest misconfiguration scanning. */
export const kubescape = defineAuditor({
	id: "iac.kubescape",
	title: "Kubescape",
	description:
		"Runs Kubescape over plain Kubernetes manifests (NSA, MITRE and CIS style controls). Kubescape downloads its control library from GitHub on each run. The scan passes --keep-local, so results are never submitted to the Kubescape cloud backend, even when an account is configured on this machine.",
	categories: ["security", "reliability"],
	targets: ["iac"],
	engine: "external",
	tool: "kubescape",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, manifests: byFile } = yield* kubernetesManifests(ctx);
			const manifests = [...byFile.keys()];
			if (manifests.length === 0)
				return yield* skip("No Kubernetes manifests found");
			const bin = yield* requireTool(
				ctx,
				"kubescape",
				"Install: brew install kubescape or curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash (https://kubescape.io/docs/install-cli/).",
			);
			const outDir = yield* Effect.tryPromise({
				try: () => mkdtemp(join(tmpdir(), "openaudit-kubescape-")),
				catch: (cause) =>
					new AuditorError({
						message: "Could not create Kubescape output dir",
						cause,
					}),
			});
			const report = join(outDir, "report.json");
			const text = yield* runTool(
				ctx,
				[
					bin,
					"scan",
					// "./" keeps hostile file names from being read as flags.
					...manifests.map((f) => `./${f}`),
					"--format",
					"json",
					"--output",
					report,
					// Never report results to a Kubescape cloud backend.
					"--keep-local",
				],
				ws.root,
				// 1 is returned when a compliance threshold is exceeded; the report is still written.
				[0, 1],
			).pipe(
				Effect.andThen(
					Effect.tryPromise({
						try: () => readFile(report, "utf8"),
						catch: (cause) =>
							new AuditorError({
								message: "Kubescape did not write a report",
								cause,
							}),
					}),
				),
				Effect.ensuring(
					Effect.promise(() => rm(outDir, { recursive: true, force: true })),
				),
			);
			return parseKubescapeReport(yield* parseJson(text, "kubescape"), ws.root);
		}),
});
