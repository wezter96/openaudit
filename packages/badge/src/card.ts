/** The larger badge card: repo, scores per target and the severity counts. */
import type { TargetSummary } from "./api";
import {
	escapeXml,
	FAILED,
	formatDate,
	GREY,
	gradeColour,
	type Text,
	truncate,
} from "./svg";
import { type BadgeView, headline } from "./view";

const INK = "#1f2328";
const MUTED = "#57606a";
const FONT =
	"-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";

const MESSAGES: Record<string, Text> = {
	pending: "Waiting for the first scan",
	failed: "The last scan failed",
	removed: "This badge was removed",
	notfound: "No such badge",
};

/** The top right corner: the scan date, or what went wrong. */
const corner = (view: BadgeView) => {
	if (view.state === "failed") return { text: "scan failed", colour: FAILED };
	if (!view.scan) return { text: "", colour: MUTED };
	const date = formatDate(view.scan.finishedAt);
	return view.state === "stale"
		? { text: `last scan ${date}`, colour: GREY }
		: { text: `scanned ${date}`, colour: MUTED };
};

const block = (
	name: Text,
	summary: TargetSummary,
	x: number,
	grey: boolean,
) => {
	const score = String(summary.score);
	const cx = x + score.length * 21 + 18;
	const colour = grey ? GREY : gradeColour(summary.grade);
	return `<text x="${x}" y="104" font-size="36" font-weight="700" fill="${grey ? GREY : INK}">${score}</text><circle cx="${cx}" cy="92" r="13" fill="${colour}"/><text x="${cx}" y="97" font-size="14" font-weight="700" fill="#fff" text-anchor="middle">${summary.grade}</text><text x="${x}" y="126" font-size="12" fill="${MUTED}">${name}</text>`;
};

const SEVERITY_COLOURS = {
	critical: "#a1123a",
	high: "#e04a1f",
	medium: "#f0a22b",
	low: "#dfbc4f",
} as const;

const severities = (summary: TargetSummary) =>
	Object.entries(SEVERITY_COLOURS)
		.map(([name, colour], i) => {
			const count = summary.severities[name as keyof typeof SEVERITY_COLOURS];
			const y = 78 + i * 18;
			return `<circle cx="306" cy="${y - 4}" r="4" fill="${colour}"/><text x="316" y="${y}" font-size="12" fill="${MUTED}">${count} ${name}</text>`;
		})
		.join("");

const scores = (view: BadgeView) => {
	const grey = view.state === "stale";
	const codebase = view.scan?.codebase;
	const site = view.scan?.site;
	const blocks = [
		codebase ? block("Codebase", codebase, 20, grey) : "",
		site ? block("Website", site, codebase ? 150 : 20, grey) : "",
	].join("");
	const top = headline(view);
	return blocks + (top ? severities(top) : "");
};

const body = (view: BadgeView) =>
	view.scan
		? scores(view)
		: `<text x="20" y="104" font-size="20" font-weight="600" fill="${MUTED}">${escapeXml(MESSAGES[view.state] ?? "")}</text>`;

const ariaLabel = (view: BadgeView, repo: Text) => {
	const top = headline(view);
	const score = top ? `, ${top.score} ${top.grade}` : "";
	const state = view.state === "ok" ? "" : `, ${view.state}`;
	return escapeXml(`openaudit verified: ${repo}${score}${state}`);
};

/** The card SVG for READMEs and websites. */
export const cardSvg = (view: BadgeView): Text => {
	const repo = view.project?.repo ?? "";
	const label = ariaLabel(view, repo);
	const top = corner(view);
	return `<svg xmlns="http://www.w3.org/2000/svg" width="440" height="150" viewBox="0 0 440 150" role="img" aria-label="${label}"><title>${label}</title><rect x=".5" y=".5" width="439" height="149" rx="10" fill="#fff" stroke="#d0d7de"/><g font-family="${FONT}"><text x="20" y="30" font-size="12" font-weight="600" fill="${MUTED}">openaudit verified</text><text x="420" y="30" font-size="12" fill="${top.colour}" text-anchor="end">${escapeXml(top.text)}</text><text x="20" y="56" font-size="16" font-weight="700" fill="${INK}">${escapeXml(truncate(repo, 44))}</text>${body(view)}</g></svg>`;
};
