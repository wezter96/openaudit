import {
	type AuditorResult,
	type Grade,
	SEVERITIES,
	type SeverityCounts,
} from "../../model";
import { escapeHtml as e } from "../shared";

/*
 * Hand-built SVG for the report: the dial, the severity spectrum, the
 * per-category bars and the auditor runtime strip. All of it is decorative
 * (`aria-hidden`); the numbers are always written out as text nearby.
 * Final states are in the markup, so the page is complete without script;
 * the script only animates towards them.
 */

const f = (n: number): string => n.toFixed(2);

/** Arc from `a0` to `a1` degrees, clockwise, 0° at 12 o'clock. */
const arc = (cx: number, cy: number, r: number, a0: number, a1: number) => {
	const at = (a: number) => {
		const rad = (a * Math.PI) / 180;
		return [cx + r * Math.sin(rad), cy - r * Math.cos(rad)] as const;
	};
	const [x0, y0] = at(a0);
	const [x1, y1] = at(a1);
	return `M${f(x0)} ${f(y0)}A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${f(x1)} ${f(y1)}`;
};

/** The same arc, drawn anticlockwise from `a1` back to `a0`. */
const arcReverse = (
	cx: number,
	cy: number,
	r: number,
	a0: number,
	a1: number,
) => {
	const at = (a: number) => {
		const rad = (a * Math.PI) / 180;
		return [cx + r * Math.sin(rad), cy - r * Math.cos(rad)] as const;
	};
	const [x0, y0] = at(a1);
	const [x1, y1] = at(a0);
	return `M${f(x0)} ${f(y0)}A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 0 ${f(x1)} ${f(y1)}`;
};

const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

/** One major tick every 10 points, minor ticks every 2. */
const ticks = (cx: number, r0: number, r1: number, major: boolean) => {
	let d = "";
	for (let i = 0; i < 50; i++) {
		if ((i % 5 === 0) !== major) continue;
		const a = (i / 50) * 2 * Math.PI;
		const inner = major ? r0 - 2.5 : r0;
		d += `M${f(cx + inner * Math.sin(a))} ${f(cx - inner * Math.cos(a))}L${f(cx + r1 * Math.sin(a))} ${f(cx - r1 * Math.cos(a))}`;
	}
	return d;
};

/** The bead at the end of the score arc. */
const capAt = (c: number, r: number, score: number, grade: Grade) => {
	const a = (score / 100) * 2 * Math.PI;
	return `<circle class="cap a-${grade}" cx="${f(c + r * Math.sin(a))}" cy="${f(c - r * Math.cos(a))}" r="4"/>`;
};

export interface DialSegment {
	readonly label: string;
	readonly score: number;
	readonly grade: Grade;
}

/**
 * The overall dial: a thick score ring, a tick scale, and one outer segment
 * per category, each filled to its own score.
 */
export const dial = (
	score: number,
	grade: Grade,
	segments: ReadonlyArray<DialSegment>,
	label: string,
): string => {
	const c = 120;
	const gap = segments.length > 1 ? 4 : 0;
	const span = 360 / Math.max(1, segments.length);
	const segs = segments
		.map((s, i) => {
			const a0 = i * span + gap / 2;
			const a1 = (i + 1) * span - gap / 2 - (segments.length === 1 ? 0.01 : 0);
			const d = arc(c, c, 110, a0, a1);
			return `<path class="seg-track" d="${d}"/><path class="seg a-${s.grade}" d="${d}" pathLength="100" stroke-dasharray="${clamp(s.score)} 100" data-v="${clamp(s.score)}"><title>${e(s.label)}: ${clamp(s.score)}, grade ${s.grade}</title></path>`;
		})
		.join("");
	// Category names follow the rim; bottom ones run the other way to stay upright.
	const labels = segments
		.map((s, i) => {
			const a0 = i * span + gap / 2;
			const a1 = (i + 1) * span - gap / 2;
			const mid = (a0 + a1) / 2;
			const bottom = mid > 90 && mid < 270;
			const r = bottom ? 126 : 120;
			const room = (2 * Math.PI * r * (a1 - a0)) / 360;
			if (segments.length > 12 || s.label.length * 4.1 > room) return "";
			const d = bottom ? arcReverse(c, c, r, a0, a1) : arc(c, c, r, a0, a1);
			return `<path id="dial-l${i}" d="${d}" fill="none"/><text class="seg-label"><textPath href="#dial-l${i}" startOffset="50%" text-anchor="middle">${e(s.label)}</textPath></text>`;
		})
		.join("");
	return `<div class="dial" data-dial role="img" aria-label="${e(label)}">
<svg viewBox="0 0 240 240" aria-hidden="true" focusable="false">
<g class="seg-labels">${labels}</g>
<circle class="dial-plate" cx="${c}" cy="${c}" r="97"/>
<g class="segs">${segs}</g>
<path class="ticks" d="${ticks(c, 93, 96.5, false)}"/><path class="ticks-major" d="${ticks(c, 92, 97, true)}"/>
<circle class="ring-track" cx="${c}" cy="${c}" r="80"/>
<circle class="ring a-${grade}" cx="${c}" cy="${c}" r="80" pathLength="100" stroke-dasharray="${clamp(score)} 100" transform="rotate(-90 ${c} ${c})" data-v="${clamp(score)}"/>
${capAt(c, 80, clamp(score), grade)}
</svg>
<div class="dial-center" aria-hidden="true"><span class="dial-grade gm-${grade}">${grade}</span><span class="dial-score"><span data-count="${clamp(score)}">${clamp(score)}</span><small>/100</small></span></div>
</div>`;
};

/** A small single-ring dial for category panels. */
export const miniDial = (score: number, grade: Grade, label: string) =>
	`<div class="dial" data-dial role="img" aria-label="${e(label)}">
<svg viewBox="0 0 120 120" aria-hidden="true" focusable="false">
<circle class="ring-track" cx="60" cy="60" r="50"/>
<circle class="ring a-${grade}" cx="60" cy="60" r="50" pathLength="100" stroke-dasharray="${clamp(score)} 100" transform="rotate(-90 60 60)" data-v="${clamp(score)}"/>
</svg>
<div class="dial-center" aria-hidden="true"><span class="dial-grade gm-${grade}">${grade}</span></div>
</div>`;

/** The tiny ring in the sticky bar. */
export const tinyRing = (score: number, grade: Grade) =>
	`<svg viewBox="0 0 28 28" aria-hidden="true" focusable="false"><circle class="ring-track" cx="14" cy="14" r="11" stroke-width="4"/><circle class="ring a-${grade}" cx="14" cy="14" r="11" stroke-width="4" pathLength="100" stroke-dasharray="${clamp(score)} 100"/></svg>`;

const total = (c: SeverityCounts): number =>
	SEVERITIES.reduce((n, s) => n + c[s], 0);

/**
 * Severity spectrum: one rounded bar split by severity with hairline gaps.
 * `scale` (0–1) shortens the bar to compare volumes between categories.
 */
export const spectrum = (
	c: SeverityCounts,
	options: { readonly height?: number; readonly scale?: number } = {},
): string => {
	const h = options.height ?? 14;
	const width = 100 * (options.scale ?? 1);
	const n = total(c);
	const present = SEVERITIES.filter((s) => c[s] > 0);
	const gap = present.length > 1 ? 0.6 : 0;
	const usable = width - gap * (present.length - 1);
	let x = 0;
	const rects = n
		? present
				.map((s) => {
					const w = Math.max(0.8, (c[s] / n) * usable);
					const r = `<rect class="f-${s}" x="${f(x)}" y="0" width="${f(w)}" height="${h}"/>`;
					x += w + gap;
					return r;
				})
				.join("")
		: `<rect class="f-none" x="0" y="0" width="100" height="${h}"/>`;
	const track =
		n && width < 100
			? `<rect class="f-none" x="0" y="0" width="100" height="${h}"/>`
			: "";
	return `<svg class="spectrum" viewBox="0 0 100 ${h}" preserveAspectRatio="none" aria-hidden="true" focusable="false">${track}${rects}</svg>`;
};

/**
 * Runtime strip: every auditor that ran, longest first, as a segment whose
 * width follows its duration; skipped auditors are thin ticks at the end.
 */
export const runtimeStrip = (results: ReadonlyArray<AuditorResult>): string => {
	const ran = results
		.filter((r) => r.status !== "skipped")
		.sort((a, b) => b.durationMs - a.durationMs);
	const skipped = results.filter((r) => r.status === "skipped");
	const tick = 0.45;
	const gap = 0.25;
	const skippedWidth = skipped.length * (tick + gap);
	const budget = Math.max(0, 100 - skippedWidth - ran.length * gap);
	// Square-root scale keeps short runs visible next to a long one.
	const weights = ran.map((r) => Math.sqrt(Math.max(1, r.durationMs)));
	const sum = weights.reduce((a, b) => a + b, 0) || 1;
	let x = 0;
	const rect = (r: AuditorResult, w: number) => {
		const out = `<rect class="f-${r.status}" x="${f(x)}" y="0" width="${f(w)}" height="16" rx="1.5"><title>${e(r.auditor)}: ${e(r.status)}${r.status === "skipped" ? "" : `, ${Math.round(r.durationMs)} ms`}</title></rect>`;
		x += w + gap;
		return out;
	};
	const bars = [
		...ran.map((r, i) =>
			rect(r, Math.max(0.5, ((weights[i] ?? 1) / sum) * budget)),
		),
		...skipped.map((r) => rect(r, tick)),
	].join("");
	return `<svg class="strip" viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true" focusable="false">${bars}</svg>`;
};
