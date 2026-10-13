import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
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

import { isRecord, kebab, scrubLine, truncate } from "../codebase/util";
import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { targetFiles } from "./shared";

/** Files KICS has queries for: Terraform, Dockerfiles, Kubernetes/CFN/Ansible/Compose YAML, Bicep. */
const KICS_RE =
	/\.(tf|tfvars|hcl|bicep)$|(^|\/)(Dockerfile[^/]*|[^/]*\.dockerfile)$|\.ya?ml$/;

const SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MEDIUM: "medium",
	LOW: "low",
	INFO: "info",
	TRACE: "info",
};

const categoryOf = (kicsCategory: string | undefined): Category => {
	switch (kicsCategory) {
		case "Best Practices":
		case "Build Process":
		case "Structure and Semantics":
			return "best-practices";
		case "Availability":
		case "Backup":
		case "Resource Management":
		case "Observability":
			return "reliability";
		case "Supply-Chain":
			return "supply-chain";
		default:
			return "security";
	}
};

/** Parses KICS `results.json`. Relative `file_name`s are relative to `root`. */
export const parseKicsReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.queries).flatMap((rawQuery): FindingInput[] => {
		if (!isRecord(rawQuery)) return [];
		const name = str(rawQuery.query_name) ?? "Unknown query";
		const queryId = str(rawQuery.query_id);
		const platform = str(rawQuery.platform) ?? "iac";
		const url = str(rawQuery.query_url);
		const cwe = str(rawQuery.cwe);
		const description = str(rawQuery.description);
		return arr(rawQuery.files).flatMap((rawFile): FindingInput[] => {
			if (!isRecord(rawFile)) return [];
			const fileName = str(rawFile.file_name)?.split("\\").join("/");
			const file = fileName
				? relPath(
						root,
						isAbsolute(fileName) ? fileName : resolve(root, fileName),
					)
				: undefined;
			const expected = str(rawFile.expected_value);
			const actual = str(rawFile.actual_value);
			const searchKey = str(rawFile.search_key);
			const remediation = str(rawFile.remediation);
			return [
				{
					ruleId: `iac.kics/${kebab(platform)}-${kebab(name)}`,
					title: name,
					severity:
						SEVERITY[String(rawQuery.severity).toUpperCase()] ?? "medium",
					category: categoryOf(str(rawQuery.category)),
					message: [description, actual && `Found: ${actual}`]
						.filter(Boolean)
						.join(". "),
					remediation:
						remediation ||
						(expected
							? `Expected: ${expected}`
							: "See the KICS query documentation."),
					location: { file, line: num(rawFile.line) },
					evidence: searchKey ? scrubLine(truncate(searchKey)) : undefined,
					references: url ? [url] : undefined,
					confidence: "medium",
					tags: [
						"kics",
						platform.toLowerCase(),
						...(cwe ? [`cwe-${cwe}`] : []),
						...(queryId ? [queryId] : []),
					],
				},
			];
		});
	});
};

/** Wraps KICS (Checkmarx), an IaC scanner with a large query library. */
export const kics = defineAuditor({
	id: "iac.kics",
	title: "KICS",
	description:
		"Runs KICS over Terraform, Dockerfiles, Kubernetes, CloudFormation, Ansible, Bicep and Compose files. Secrets scanning is disabled (use the secret scanners) and full-description downloads are off, so KICS makes no network requests. Results go to a temporary directory, never the target.",
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
			const outDir = yield* Effect.tryPromise({
				try: () => mkdtemp(join(tmpdir(), "openaudit-kics-")),
				catch: (cause) =>
					new AuditorError({
						message: "Could not create KICS output dir",
						cause,
					}),
			});
			const scanPath =
				ctx.target.type === "file" && ctx.target.file
					? resolve(ws.root, ctx.target.file)
					: ws.root;
			const text = yield* runTool(
				ctx,
				[
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
					"--disable-full-descriptions",
					"--ignore-on-exit",
					"results",
				],
				ws.root,
				// 0 = clean; 20/30/40/50/60 = highest severity found (info..critical).
				[0, 20, 30, 40, 50, 60],
			).pipe(
				Effect.andThen(
					Effect.tryPromise({
						try: () => readFile(join(outDir, "results.json"), "utf8"),
						catch: (cause) =>
							new AuditorError({
								message: "KICS did not write a report",
								cause,
							}),
					}),
				),
				Effect.ensuring(
					Effect.promise(() => rm(outDir, { recursive: true, force: true })),
				),
			);
			return parseKicsReport(yield* parseJson(text, "kics"), ws.root);
		}),
});
