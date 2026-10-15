/**
 * The badge (shields style: `openaudit | 96 A | 15 Oct 2026`) and the larger
 * card, as SVG text. Pure functions: every piece of text is escaped here.
 */
import type { TargetSummary } from "./api";
import {
	escapeXml,
	FAILED,
	formatDate,
	GREY,
	gradeColour,
	LABEL,
	type Text,
	textWidth,
} from "./svg";
import { type BadgeView, headline } from "./view";

export { cardSvg } from "./card";
export { verifyPageHtml } from "./page";

interface Segment {
	readonly text: Text;
	readonly colour: string;
}

const DATE = "#5d6b7d";
const STALE_DATE = "#7b7b7b";

const scoreText = (summary: TargetSummary) =>
	`${summary.score} ${summary.grade}`;

const scoreSegment = (view: BadgeView, colourless: boolean): Segment => {
	const summary = headline(view);
	if (!summary) return { text: "no score", colour: GREY };
	return {
		text: scoreText(summary),
		colour: colourless ? GREY : gradeColour(summary.grade),
	};
};

const dateSegment = (view: BadgeView, colour: string): Segment => ({
	text: view.scan ? formatDate(view.scan.finishedAt) : "",
	colour,
});

const failedSegments = (view: BadgeView): ReadonlyArray<Segment> => {
	const failed = { text: "scan failed", colour: FAILED };
	return view.scan ? [scoreSegment(view, false), failed] : [failed];
};

const SINGLE: Record<string, Text> = {
	pending: "pending",
	removed: "removed",
	notfound: "not found",
};

const segmentsOf = (view: BadgeView): ReadonlyArray<Segment> => {
	if (view.state === "ok")
		return [scoreSegment(view, false), dateSegment(view, DATE)];
	if (view.state === "stale")
		return [scoreSegment(view, true), dateSegment(view, STALE_DATE)];
	if (view.state === "failed") return failedSegments(view);
	return [{ text: SINGLE[view.state] ?? view.state, colour: GREY }];
};

const PAD = 10;

interface Placed extends Segment {
	readonly x: number;
	readonly width: number;
}

const place = (segments: ReadonlyArray<Segment>): ReadonlyArray<Placed> => {
	let x = 0;
	return segments.map((s) => {
		const width = textWidth(s.text) + PAD;
		const placed = { ...s, x, width };
		x += width;
		return placed;
	});
};

const rect = (p: Placed) =>
	`<rect x="${p.x}" width="${p.width}" height="20" fill="${p.colour}"/>`;

const label = (p: Placed) => {
	const text = escapeXml(p.text);
	const centre = (p.x + p.width / 2) * 10;
	const length = (p.width - PAD) * 10;
	return `<text aria-hidden="true" x="${centre}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${length}">${text}</text><text x="${centre}" y="140" transform="scale(.1)" fill="#fff" textLength="${length}">${text}</text>`;
};

/** The small badge for READMEs. */
export const badgeSvg = (view: BadgeView): Text => {
	const parts = place([
		{ text: "openaudit", colour: LABEL },
		...segmentsOf(view),
	]);
	const last = parts[parts.length - 1];
	const width = last ? last.x + last.width : 0;
	const title = escapeXml(parts.map((p) => p.text).join(" | "));
	return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${title}"><title>${title}</title><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="${width}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)">${parts.map(rect).join("")}<rect width="${width}" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">${parts.map(label).join("")}</g></svg>`;
};
