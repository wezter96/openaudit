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
import { readOptional, targetFiles } from "./shared";

const YAML_RE = /\.ya?ml$/;
const NOT_K8S_RE =
	/(^|\/)(\.github\/|\.gitlab-ci|(docker-)?compose[^/]*\.ya?ml$|pnpm-lock|\.pre-commit|mkdocs|openapi|swagger)/;

/** Controls about capacity and availability rather than security. */
const RELIABILITY = new Set(["C-0004", "C-0050", "C-0018", "C-0056"]);

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
		const fix = isRecord(p.fixPath) ? p.fixPath : {};
		const path = str(fix.path);
		if (path) return [`set ${path} to ${JSON.stringify(fix.value ?? "")}`];
		// Real reports leave fixPath empty and name the field to remove instead.
		const remove = str(p.deletePath);
		return remove ? [`remove ${remove}`] : [];
	});
	return fixes.length > 0 ? `Suggested: ${fixes.slice(0, 3).join("; ")}.` : "";
};

/** Parses Kubescape `--format json` (v2 posture report) output. */
export const parseKubescapeReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const summary = isRecord(json.summaryDetails) ? json.summaryDetails : {};
	const controls = isRecord(summary.controls) ? summary.controls : {};
	const resources = new Map<string, Record<string, unknown>>();
	for (const r of arr(json.resources))
		if (isRecord(r) && typeof r.resourceID === "string")
			resources.set(r.resourceID, r);

	return arr(json.results).flatMap((rawResult): FindingInput[] => {
		if (!isRecord(rawResult)) return [];
		const resourceId = str(rawResult.resourceID) ?? "";
		const resource = resources.get(resourceId);
		const source = isRecord(resource?.source) ? resource.source : {};
		const object = isRecord(resource?.object) ? resource.object : {};
		const meta = isRecord(object.metadata) ? object.metadata : {};
		const label = [str(object.kind), str(meta.name)].filter(Boolean).join("/");
		// Kubescape reports the manifest's directory as `path` and only its
		// basename as `relativePath`; older builds put the file in `path`.
		const abs = str(source.path);
		const base = str(source.relativePath);
		const absFile = abs && base && !abs.endsWith(base) ? join(abs, base) : abs;
		const file =
			absFile &&
			isAbsolute(absFile) &&
			!relative(root, absFile).startsWith("..")
				? relPath(root, absFile)
				: (base ?? absFile);

		return arr(rawResult.controls).flatMap((rawControl): FindingInput[] => {
			if (!isRecord(rawControl)) return [];
			const status = isRecord(rawControl.status) ? rawControl.status : {};
			if (status.status !== "failed") return [];
			const id = str(rawControl.controlID);
			if (!id) return [];
			const name = str(rawControl.name) ?? id;
			const summaryControl = isRecord(controls[id]) ? controls[id] : {};
			const paths = arr(rawControl.rules)
				.filter(isRecord)
				.flatMap((rule) => arr(rule.paths).filter(isRecord));
			const failed = paths
				.map((p) => str(p.failedPath) ?? str(p.reviewPath) ?? str(p.deletePath))
				.filter((p): p is string => Boolean(p));
			const fixes = fixText(paths);
			const category: Category = RELIABILITY.has(id)
				? "reliability"
				: "security";
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
					evidence:
						failed.length > 0
							? scrubLine(truncate(failed.slice(0, 3).join(", ")))
							: label || undefined,
					references: [`https://hub.armosec.io/docs/${id.toLowerCase()}`],
					tags: ["kubescape", id.toLowerCase()],
				},
			];
		});
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
			const { ws, files } = yield* targetFiles(ctx, YAML_RE);
			const manifests: string[] = [];
			for (const file of files) {
				if (ctx.target.type !== "file" && NOT_K8S_RE.test(file)) continue;
				const text = yield* readOptional(ws, file);
				if (
					text === undefined ||
					!/^apiVersion:\s*\S/m.test(text) ||
					!/^kind:\s*\S/m.test(text) ||
					text.includes("{{")
				)
					continue;
				manifests.push(file);
			}
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
