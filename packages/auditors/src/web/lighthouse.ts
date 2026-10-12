import {
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireUrl,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { truncate } from "./util";

interface LhAudit {
	readonly id: string;
	readonly title?: string;
	readonly description?: string;
	readonly score?: number | null;
	readonly scoreDisplayMode?: string;
	readonly displayValue?: string;
	readonly details?: {
		readonly items?: ReadonlyArray<Record<string, unknown>>;
	};
}

interface LhCategory {
	readonly id: string;
	readonly title?: string;
	readonly score?: number | null;
	readonly auditRefs?: ReadonlyArray<{
		readonly id: string;
		readonly weight?: number;
		readonly group?: string;
	}>;
}

export interface LighthouseReport {
	readonly finalUrl?: string;
	readonly finalDisplayedUrl?: string;
	readonly requestedUrl?: string;
	readonly categories?: Record<string, LhCategory>;
	readonly audits?: Record<string, LhAudit>;
}

const CATEGORY: Record<string, Category> = {
	performance: "performance",
	accessibility: "accessibility",
	seo: "seo",
	"best-practices": "best-practices",
};

const SCORED = new Set(["binary", "numeric", "metricSavings"]);

const severityOf = (
	category: Category,
	score: number,
	weight: number,
	group?: string,
): Severity => {
	if (group === "metrics") return score < 0.5 ? "high" : "medium";
	if (category === "accessibility")
		return weight >= 7 ? "high" : weight >= 3 ? "medium" : "low";
	// Performance opportunities carry weight 0 in Lighthouse 10+; rank by score.
	if (category === "performance") return score < 0.5 ? "medium" : "low";
	return weight >= 3 ? "medium" : "low";
};

/** `[Learn more](https://…)` links in Lighthouse descriptions, and the text without them. */
const splitDescription = (text = "") => {
	const links = [...text.matchAll(/\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/g)].map(
		(m) => m[1] as string,
	);
	const plain = text
		.replace(/\[([^\]]*)\]\((https?:\/\/[^)\s]+)\)/g, "$1")
		.replace(/\s*Learn (more|how)[^.]*\.?\s*$/i, "")
		.trim();
	return { links, plain };
};

const nodeOf = (item: Record<string, unknown>) => {
	const node = item.node as { selector?: string; snippet?: string } | undefined;
	return node && typeof node === "object" ? node : undefined;
};

/** Maps failing audits of a Lighthouse JSON report to findings. Exported for tests. */
export const parseLighthouse = (report: LighthouseReport): FindingInput[] => {
	const findings: FindingInput[] = [];
	const url =
		report.finalDisplayedUrl ?? report.finalUrl ?? report.requestedUrl;
	const seen = new Set<string>();
	for (const [key, cat] of Object.entries(report.categories ?? {})) {
		const category = CATEGORY[key];
		if (!category) continue;
		for (const ref of cat.auditRefs ?? []) {
			const audit = report.audits?.[ref.id];
			if (!audit || seen.has(audit.id)) continue;
			if (!SCORED.has(audit.scoreDisplayMode ?? "")) continue;
			const score = audit.score;
			if (score === null || score === undefined || score >= 0.9) continue;
			seen.add(audit.id);
			const { links, plain } = splitDescription(audit.description);
			const items = audit.details?.items ?? [];
			const nodes = items
				.map(nodeOf)
				.filter((n): n is NonNullable<typeof n> => !!n);
			const firstUrl = items
				.map((i) => i.url)
				.find((u): u is string => typeof u === "string");
			const severity = severityOf(category, score, ref.weight ?? 0, ref.group);
			const evidence = [
				audit.displayValue,
				nodes[0]?.snippet,
				!nodes[0] && firstUrl ? firstUrl : undefined,
				items.length > 1 ? `${items.length} items` : undefined,
			]
				.filter(Boolean)
				.join(" · ");
			findings.push({
				ruleId: `web.lighthouse/${audit.id}`,
				title: audit.title ?? audit.id,
				severity,
				category,
				message: `${plain || audit.title || audit.id}${audit.displayValue ? ` (${audit.displayValue})` : ""} — Lighthouse score ${Math.round(score * 100)}/100.`,
				location: { url, selector: nodes[0]?.selector },
				evidence: evidence ? truncate(evidence, 200) : undefined,
				remediation: plain
					? `See the Lighthouse guidance: ${truncate(plain, 200)}`
					: "See the linked Lighthouse documentation.",
				references: links.length > 0 ? links : undefined,
				tags: [`lighthouse-${key}`],
			});
		}
	}
	return findings;
};

/** Runs the Lighthouse CLI when installed and reports its failing audits. */
export const lighthouse = defineAuditor({
	id: "web.lighthouse",
	title: "Lighthouse",
	description:
		"Runs Google Lighthouse (performance, accessibility, SEO, best practices) and reports failing audits.",
	categories: ["performance", "accessibility", "seo", "best-practices"],
	targets: ["url"],
	engine: "external",
	tool: "lighthouse",
	run: (ctx) =>
		Effect.gen(function* () {
			const url = yield* requireUrl(ctx);
			const bin = yield* requireTool(
				ctx,
				"lighthouse",
				"Install it with `npm i -g lighthouse` (requires Chrome).",
			);
			const args = [
				bin,
				url,
				"--output=json",
				"--output-path=stdout",
				"--quiet",
				"--only-categories=performance,accessibility,seo,best-practices",
				"--chrome-flags=--headless=new --no-sandbox",
			];
			// Lighthouse's --extra-headers applies to every origin, which would leak
			// user credentials to third parties, so user headers are not forwarded.
			if (ctx.options.headers && Object.keys(ctx.options.headers).length > 0)
				yield* ctx.log(
					"web.lighthouse: custom headers are not forwarded to Lighthouse",
				);
			const res = yield* ctx.exec.run(args, { timeoutMs: 180_000 });
			const json = res.stdout.slice(res.stdout.indexOf("{"));
			const report = yield* Effect.try({
				try: () => JSON.parse(json) as LighthouseReport,
				catch: (cause) =>
					new AuditorError({
						message: `Lighthouse exited with code ${res.code} and no JSON report: ${truncate(res.stderr.trim() || res.stdout.trim(), 300)}`,
						cause,
					}),
			});
			return parseLighthouse(report);
		}),
});
