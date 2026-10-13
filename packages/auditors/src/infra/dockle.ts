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
import { arr, parseJson, str } from "../tool";

const CHECKPOINTS =
	"https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md";

/** FATAL/WARN/INFO are findings; SKIP and PASS are not. */
const LEVEL: Record<string, Severity> = {
	FATAL: "high",
	WARN: "medium",
	INFO: "low",
};

/** Hygiene checks that are not security controls. */
const BEST_PRACTICES = new Set([
	"CIS-DI-0005",
	"CIS-DI-0007",
	"CIS-DI-0009",
	"DKL-DI-0006",
]);
const RELIABILITY = new Set(["CIS-DI-0006"]);

/** Parses `dockle -f json` output for the image `ref`. */
export const parseDockleReport = (
	json: unknown,
	ref: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.details).flatMap((raw): FindingInput[] => {
		if (!isRecord(raw)) return [];
		const code = str(raw.code);
		const severity = LEVEL[String(raw.level).toUpperCase()];
		if (!code || !severity) return [];
		const title = str(raw.title) ?? code;
		const category: Category = BEST_PRACTICES.has(code)
			? "best-practices"
			: RELIABILITY.has(code)
				? "reliability"
				: "security";
		const alerts = arr(raw.alerts).filter(
			(a): a is string => typeof a === "string",
		);
		// One finding per alert so each offending file/key stays distinct.
		return (alerts.length > 0 ? alerts : [title]).map(
			(alert): FindingInput => ({
				ruleId: `container.dockle/${code.toLowerCase()}`,
				title,
				severity,
				category,
				message: `${title}: ${truncate(scrubLine(alert), 300)}`,
				remediation: `See the Dockle checkpoint ${code} for how to fix this.`,
				location: { file: ref },
				evidence: truncate(scrubLine(alert), 200),
				references: [`${CHECKPOINTS}#${code.toLowerCase()}`],
				tags: ["dockle", code.toLowerCase()],
			}),
		);
	});
};

/** Wraps Dockle, a container image linter for CIS Docker Benchmark checks. */
export const dockle = defineAuditor({
	id: "container.dockle",
	title: "Dockle",
	description:
		"Runs Dockle on an image (image:<ref>): CIS Docker Benchmark checks on image config and contents (root user, secrets in ENV or files, setuid files, ADD, latest tag). Dockle pulls the image from its registry when it is not available locally.",
	categories: ["security", "best-practices"],
	targets: ["container"],
	engine: "external",
	tool: "dockle",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ref = ctx.target.image;
			if (ctx.target.type !== "image" || !ref)
				return yield* skip("Only runs for image:<ref> targets");
			const bin = yield* requireTool(
				ctx,
				"dockle",
				"Install: brew install goodwithtech/r/dockle (https://github.com/goodwithtech/dockle#installation).",
			);
			const res = yield* ctx.exec.run(
				[bin, "-f", "json", "--exit-code", "0", ref],
				{ timeoutMs: 280_000 },
			);
			if (res.code !== 0 || !res.stdout.trim())
				return yield* new AuditorError({
					message: `dockle exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
				});
			return parseDockleReport(yield* parseJson(res.stdout, "dockle"), ref);
		}),
});
