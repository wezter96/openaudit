import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireUrl,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, str } from "../tool";
import { truncate } from "./util";

export interface Pa11yIssue {
	readonly code?: string;
	readonly type?: string;
	readonly message?: string;
	readonly context?: string;
	readonly selector?: string;
	readonly runner?: string;
	readonly runnerExtras?: {
		readonly impact?: string | null;
		readonly help?: string;
		readonly helpUrl?: string;
		readonly needsFurtherReview?: boolean;
	};
}

const RANK: Record<Severity, number> = {
	critical: 4,
	high: 3,
	medium: 2,
	low: 1,
	info: 0,
};

const kebab = (s: string) =>
	s
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");

/** pa11y types map to error → medium, warning → low, notice → info. */
const severityOf = (issue: Pa11yIssue): Severity => {
	const { needsFurtherReview, impact } = issue.runnerExtras ?? {};
	if (issue.type === "error") {
		// Items axe could not decide on are not confirmed failures.
		if (needsFurtherReview) return "low";
		return impact === "critical" ? "high" : "medium";
	}
	return issue.type === "warning" ? "low" : "info";
};

interface Parsed {
	readonly ruleKey: string;
	readonly title: string;
	readonly references: string[];
	readonly tags: string[];
	readonly message: string;
}

const describeAxe = (
	issue: Pa11yIssue,
	code: string,
	message: string,
): Parsed => {
	const { help, helpUrl, impact } = issue.runnerExtras ?? {};
	return {
		ruleKey: `axe-${kebab(code)}`,
		title: help ?? truncate(message, 90),
		references: helpUrl ? [helpUrl] : [],
		tags: ["axe", ...(impact ? [`axe-impact-${impact}`] : [])],
		message,
	};
};

/** WCAG technique links for an HTML_CodeSniffer technique list like `H37` or `G94,G95`. */
const techniqueRefs = (technique: string): string[] | undefined =>
	technique
		.split(".")[0]
		?.split(",")
		.filter((t) => /^[A-Z]+\d+$/.test(t))
		.map((t) => `https://www.w3.org/TR/WCAG20-TECHS/${t}.html`);

const htmlcsTags = (
	level: string | undefined,
	sc: string | undefined,
): string[] => [
	"htmlcs",
	...(level?.startsWith("wcag") ? [level] : []),
	...(sc && /^\d+\.\d+\.\d+$/.test(sc) ? [`wcag-${sc}`] : []),
];

// HTML_CodeSniffer: WCAG2AA.Principle1.Guideline1_1.1_1_1.H37
const describeHtmlcs = (code: string, message: string): Parsed => {
	const parts = code.split(".");
	const criterion = parts[3];
	const technique = parts.slice(4).join(".");
	return {
		ruleKey: `htmlcs-${kebab(`${criterion ?? ""}-${technique}`).slice(0, 60)}`,
		title: truncate(message.split(/(?<=\.)\s/)[0] ?? message, 90),
		references: techniqueRefs(technique) ?? [],
		tags: htmlcsTags(
			parts[0]?.toLowerCase(),
			criterion?.split("_").slice(0, 3).join("."),
		),
		message,
	};
};

const describe = (issue: Pa11yIssue): Parsed | undefined => {
	const code = issue.code;
	if (!code) return undefined;
	const message = (issue.message ?? code)
		.replace(/\s*\(https?:\/\/[^)\s]+\)\s*$/, "")
		.trim();
	return issue.runner === "axe"
		? describeAxe(issue, code, message)
		: describeHtmlcs(code, message);
};

interface Group {
	readonly parsed: Parsed;
	severity: Severity;
	readonly issues: Pa11yIssue[];
}

const addIssue = (groups: Map<string, Group>, issue: Pa11yIssue): void => {
	const parsed = describe(issue);
	if (!parsed) return;
	const severity = severityOf(issue);
	const g = groups.get(parsed.ruleKey);
	if (!g) {
		groups.set(parsed.ruleKey, { parsed, severity, issues: [issue] });
		return;
	}
	g.issues.push(issue);
	if (RANK[severity] > RANK[g.severity]) g.severity = severity;
};

const evidenceOf = (first: Pa11yIssue, issues: Pa11yIssue[]): string => {
	const selectors = [
		...new Set(issues.map((i) => str(i.selector)).filter(Boolean)),
	];
	return [
		first.context ? truncate(first.context.replace(/\s+/g, " "), 120) : "",
		selectors.length > 1
			? `${selectors.length} elements: ${truncate(selectors.slice(0, 4).join(", "), 120)}${selectors.length > 4 ? ", …" : ""}`
			: "",
	]
		.filter(Boolean)
		.join(" · ");
};

const toFinding = (
	{ parsed, severity, issues }: Group,
	url: string | undefined,
): FindingInput => {
	const first = issues[0] as Pa11yIssue;
	const evidence = evidenceOf(first, issues);
	const referenced = parsed.references.length > 0;
	return {
		ruleId: `web.pa11y/${parsed.ruleKey}`,
		title: parsed.title,
		severity,
		category: "accessibility",
		message: `${parsed.message}${first.type ? ` (pa11y ${first.type}${first.runner ? `, ${first.runner}` : ""})` : ""}.`,
		location: { url, selector: first.selector },
		evidence: evidence || undefined,
		remediation: referenced
			? "Fix the markup as described by the linked guidance."
			: "Fix the markup so it satisfies the WCAG criterion named in the message.",
		references: referenced ? parsed.references : undefined,
		tags: parsed.tags,
	};
};

/**
 * Maps pa11y JSON issues to findings. Issues sharing a rule are grouped into
 * one finding (first selector as location, the rest listed as evidence).
 */
export const parsePa11yReport = (
	json: unknown,
	url?: string,
): FindingInput[] => {
	const groups = new Map<string, Group>();
	for (const raw of arr(json)) addIssue(groups, raw as Pa11yIssue);
	return [...groups.values()].map((g) => toFinding(g, url));
};

/** Runs pa11y (axe-core + HTML_CodeSniffer in headless Chrome) and reports accessibility issues. */
export const pa11y = defineAuditor({
	id: "web.pa11y",
	title: "pa11y accessibility",
	description:
		"Runs pa11y with the axe and HTML_CodeSniffer runners in headless Chrome and reports WCAG errors and warnings (notices are ignored). Loads the page once like a browser, so it is low-volume; authenticated pages are not supported because pa11y would send custom headers to every origin the page loads.",
	categories: ["accessibility"],
	targets: ["url", "webapp"],
	engine: "external",
	tool: "pa11y",
	run: (ctx) =>
		Effect.gen(function* () {
			const url = yield* requireUrl(ctx);
			const bin = yield* requireTool(
				ctx,
				"pa11y",
				"Install it with `npm i -g pa11y` (downloads Chrome via Puppeteer).",
			);
			if (ctx.options.headers && Object.keys(ctx.options.headers).length > 0)
				yield* ctx.log(
					"web.pa11y: custom headers are not forwarded to pa11y (they would reach every origin)",
				);
			// pa11y auto-loads ./pa11y.json and ./.pa11yrc from the working
			// directory, so run it from a fresh empty directory.
			const cwd = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-pa11y-")),
			);
			const res = yield* ctx.exec
				.run(
					[
						bin,
						"--reporter",
						"json",
						"--runner",
						"axe",
						"--runner",
						"htmlcs",
						"--include-warnings",
						"--timeout",
						"60000",
						url,
					],
					{ cwd, timeoutMs: 180_000 },
				)
				.pipe(
					Effect.ensuring(
						Effect.promise(() => rm(cwd, { recursive: true, force: true })),
					),
				);
			// Exit code 2 means "accessibility issues found".
			if (res.code !== 0 && res.code !== 2)
				return yield* Effect.fail(
					new AuditorError({
						message: `pa11y exited with code ${res.code}: ${truncate(res.stderr.trim() || res.stdout.trim(), 300)}`,
					}),
				);
			const start = res.stdout.indexOf("[");
			const json = yield* Effect.try({
				try: () => JSON.parse(start < 0 ? "[]" : res.stdout.slice(start)),
				catch: (cause) =>
					new AuditorError({
						message: "pa11y produced invalid JSON output",
						cause,
					}),
			});
			return parsePa11yReport(json, url);
		}),
});
