import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { DOCKERFILE_RE } from "./dockerfile";
import { asArray, asRecord } from "./shared";

const SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MEDIUM: "medium",
	LOW: "low",
	INFO: "info",
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
	const findings: FindingInput[] = [];
	for (const report of reports) {
		const rec = asRecord(report);
		const failed = asArray(asRecord(rec?.results)?.failed_checks);
		const framework =
			typeof rec?.check_type === "string" ? rec.check_type : "iac";
		for (const raw of failed) {
			const c = asRecord(raw);
			if (!c || typeof c.check_id !== "string") continue;
			const range = asArray(c.file_line_range);
			const line = typeof range[0] === "number" && range[0] > 0 ? range[0] : 1;
			const file =
				typeof c.file_path === "string"
					? c.file_path.replace(/^\.?\//, "")
					: undefined;
			// Checkov treats any path containing "dockerfile" as one, source files
			// such as dockerfile.ts included.
			if (framework === "dockerfile" && file && !DOCKERFILE_RE.test(file))
				continue;
			const resource = typeof c.resource === "string" ? c.resource : undefined;
			const title =
				typeof c.check_name === "string" ? c.check_name : c.check_id;
			const guideline =
				typeof c.guideline === "string" ? c.guideline : undefined;
			const severity =
				(typeof c.severity === "string"
					? SEVERITY[c.severity.toUpperCase()]
					: undefined) ?? "medium";
			findings.push({
				ruleId: `iac.checkov/${c.check_id.toLowerCase().replace(/_/g, "-")}`,
				title,
				severity,
				category: "security",
				message: `${title}${resource ? ` (${resource})` : ""} [${c.check_id}, ${framework}]`,
				remediation: guideline
					? `Follow the Checkov guideline: ${guideline}`
					: `See the Checkov policy ${c.check_id}.`,
				location: { file, line },
				evidence: resource,
				references: guideline ? [guideline] : undefined,
				tags: ["checkov", framework, c.check_id],
				confidence: c.severity ? "high" : "medium",
			});
		}
	}
	return findings;
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
			const result = yield* ctx.exec.run(
				[bin, ...scope, "-o", "json", "--quiet", "--compact"],
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
