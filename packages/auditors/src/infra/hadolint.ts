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

import { DOCKERFILE_RE } from "./dockerfile";
import { asArray, asRecord, targetFiles } from "./shared";

const LEVELS: Record<string, Severity> = {
	error: "medium",
	warning: "low",
	info: "info",
	style: "info",
};

/** Hadolint rules with a security impact; the rest are hygiene. */
const SECURITY_RULES = new Set([
	"DL3002",
	"DL3004",
	"DL3006",
	"DL3007",
	"DL3020",
	"DL3026",
	"DL4006",
]);

const referenceFor = (code: string) =>
	code.startsWith("SC")
		? `https://www.shellcheck.net/wiki/${code}`
		: `https://github.com/hadolint/hadolint/wiki/${code}`;

/** Parses `hadolint --format json` output. Exported for tests. */
export const parseHadolintOutput = (stdout: string): FindingInput[] => {
	const items = asArray(JSON.parse(stdout || "[]"));
	return items.flatMap((raw): FindingInput[] => {
		const item = asRecord(raw);
		if (!item) return [];
		const code = String(item.code ?? "unknown");
		const message = String(item.message ?? code);
		const category: Category = SECURITY_RULES.has(code)
			? "security"
			: "best-practices";
		return [
			{
				ruleId: `container.hadolint/${code.toLowerCase()}`,
				title: `${code}: ${message.length > 80 ? `${message.slice(0, 80)}…` : message}`,
				severity: LEVELS[String(item.level)] ?? "info",
				category,
				message,
				remediation: `See the ${code.startsWith("SC") ? "ShellCheck" : "hadolint"} rule documentation for the fix.`,
				location: {
					file: String(item.file ?? ""),
					line: typeof item.line === "number" ? item.line : undefined,
					column: typeof item.column === "number" ? item.column : undefined,
				},
				references: [referenceFor(code)],
				tags: [code.toLowerCase()],
			},
		];
	});
};

/** Wraps hadolint (Dockerfile linter with ShellCheck for RUN steps). */
export const hadolint = defineAuditor({
	id: "container.hadolint",
	title: "Hadolint",
	description:
		"Runs hadolint on Dockerfiles: Dockerfile best practices plus ShellCheck on RUN instructions.",
	categories: ["best-practices", "security"],
	targets: ["container"],
	engine: "external",
	tool: "hadolint",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, DOCKERFILE_RE);
			if (files.length === 0) return yield* skip("No Dockerfiles found");
			const bin = yield* requireTool(
				ctx,
				"hadolint",
				"Install: https://github.com/hadolint/hadolint#install",
			);
			const res = yield* ctx.exec.run(
				[bin, "--format", "json", "--no-fail", ...files],
				{ cwd: ws.root, timeoutMs: 120_000 },
			);
			return yield* Effect.try({
				try: () => parseHadolintOutput(res.stdout),
				catch: (cause) =>
					new AuditorError({
						message: `hadolint failed (exit ${res.code}): ${res.stderr.trim().slice(0, 300)}`,
						cause,
					}),
			});
		}),
});
