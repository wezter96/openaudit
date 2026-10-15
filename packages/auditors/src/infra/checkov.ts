import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { escapeRegex, gitignoredPaths } from "../tool";

import { DOCKERFILE_RE } from "./dockerfile";
import { asArray, asRecord } from "./shared";

const SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MEDIUM: "medium",
	LOW: "low",
	INFO: "info",
};

type FilePath = string;
type Framework = string;
type CheckovCheck = Record<string, unknown> & { check_id: string };

const optionalString = (value: unknown): string | undefined =>
	typeof value === "string" ? value : undefined;

/** First line of the reported range, or 1 when it is missing or invalid. */
const startLine = (range: unknown): number => {
	const first = asArray(range)[0];
	return typeof first === "number" && first > 0 ? first : 1;
};

const severityOf = (severity: unknown): Severity =>
	(typeof severity === "string"
		? SEVERITY[severity.toUpperCase()]
		: undefined) ?? "medium";

/**
 * Checkov treats any path containing "dockerfile" as one, source files such
 * as dockerfile.ts included.
 */
const isMisdetectedDockerfile = (
	framework: Framework,
	file: FilePath | undefined,
): boolean => {
	if (framework !== "dockerfile" || !file) return false;
	return !DOCKERFILE_RE.test(file);
};

const checkovFinding = (
	c: CheckovCheck,
	framework: Framework,
	file: FilePath | undefined,
): FindingInput => {
	const resource = optionalString(c.resource);
	const title = optionalString(c.check_name) ?? c.check_id;
	const guideline = optionalString(c.guideline);
	return {
		ruleId: `iac.checkov/${c.check_id.toLowerCase().replace(/_/g, "-")}`,
		title,
		severity: severityOf(c.severity),
		category: "security",
		message: `${title}${resource ? ` (${resource})` : ""} [${c.check_id}, ${framework}]`,
		remediation: guideline
			? `Follow the Checkov guideline: ${guideline}`
			: `See the Checkov policy ${c.check_id}.`,
		location: { file, line: startLine(c.file_line_range) },
		evidence: resource,
		references: guideline ? [guideline] : undefined,
		tags: ["checkov", framework, c.check_id],
		confidence: c.severity ? "high" : "medium",
	};
};

/** Findings for the failed checks of one framework report. */
const reportFindings = (report: unknown): FindingInput[] => {
	const rec = asRecord(report);
	const failed = asArray(asRecord(rec?.results)?.failed_checks);
	const framework = optionalString(rec?.check_type) ?? "iac";
	return failed.flatMap((raw): FindingInput[] => {
		const c = asRecord(raw);
		if (typeof c?.check_id !== "string") return [];
		const file = optionalString(c.file_path)?.replace(/^\.?\//, "");
		if (isMisdetectedDockerfile(framework, file)) return [];
		return [checkovFinding(c as CheckovCheck, framework, file)];
	});
};

/**
 * Parses `checkov -o json` output: a single report object, an array of them
 * (one per framework), or a bare summary when nothing was scanned.
 */
export const parseCheckovOutput = (
	stdout: string,
): ReadonlyArray<FindingInput> => {
	const start = stdout.search(/[[{]/);
	if (start === -1) return [];
	const parsed: unknown = JSON.parse(stdout.slice(start));
	const reports = Array.isArray(parsed) ? parsed : [parsed];
	return reports.flatMap(reportFindings);
};

/** Wraps Checkov for broad IaC policy coverage (Terraform, K8s, CloudFormation, ...). */
export const checkov = defineAuditor({
	id: "iac.checkov",
	title: "Checkov",
	description:
		"Runs Checkov's policy library over Terraform, Kubernetes, CloudFormation, Helm, Dockerfiles and CI configs.",
	categories: ["security", "best-practices"],
	targets: ["iac"],
	engine: "external",
	tool: "checkov",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"checkov",
				"Install with `pip install checkov` or `brew install checkov`.",
			);
			const scope =
				ctx.target.type === "file" && ctx.target.file
					? ["-f", ctx.target.file]
					: ["-d", "."];
			// --skip-path takes a regex over paths relative to the cwd (the root).
			const skip = (yield* gitignoredPaths(ws)).flatMap((p) => [
				"--skip-path",
				`^(\\./|/)?${escapeRegex(p)}${p.endsWith("/") ? "" : "$"}`,
			]);
			const result = yield* ctx.exec.run(
				[bin, ...scope, ...skip, "-o", "json", "--quiet", "--compact"],
				{ cwd: ws.root, timeoutMs: 280_000 },
			);
			// Exit code 1 means "failed checks"; anything else non-zero is a crash.
			if (result.code > 1 && !result.stdout.trim())
				return yield* new AuditorError({
					message: `checkov exited with ${result.code}: ${result.stderr.slice(0, 500)}`,
				});
			return yield* Effect.try({
				try: () => parseCheckovOutput(result.stdout),
				catch: (cause) =>
					new AuditorError({
						message: "Could not parse checkov output",
						cause,
					}),
			});
		}),
});
