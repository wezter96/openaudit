/**
 * The grade dial, with the same geometry as the report's (packages/core
 * src/reporters/html/viz.ts): a thick score ring, a tick scale, and one outer
 * segment per area filled to its own score.
 */

const f = (n: number): string => n.toFixed(2);

const at = (c: number, r: number, a: number) => {
	const rad = (a * Math.PI) / 180;
	return [c + r * Math.sin(rad), c - r * Math.cos(rad)] as const;
};

/** Arc from `a0` to `a1` degrees, clockwise, 0° at 12 o'clock. */
export const arc = (c: number, r: number, a0: number, a1: number): string => {
	const [x0, y0] = at(c, r, a0);
	const [x1, y1] = at(c, r, a1);
	return `M${f(x0)} ${f(y0)}A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${f(x1)} ${f(y1)}`;
};

/** The same arc drawn anticlockwise, so text along it reads upright. */
export const arcReverse = (
	c: number,
	r: number,
	a0: number,
	a1: number,
): string => {
	const [x0, y0] = at(c, r, a1);
	const [x1, y1] = at(c, r, a0);
	return `M${f(x0)} ${f(y0)}A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 0 ${f(x1)} ${f(y1)}`;
};

export const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

/** One major tick every 10 points, minor ticks every 2. */
export const ticks = (c: number, r0: number, r1: number, major: boolean) => {
	let d = "";
	for (let i = 0; i < 50; i++) {
		if ((i % 5 === 0) !== major) continue;
		const a = (i / 50) * 2 * Math.PI;
		const inner = major ? r0 - 2.5 : r0;
		d += `M${f(c + inner * Math.sin(a))} ${f(c - inner * Math.cos(a))}L${f(c + r1 * Math.sin(a))} ${f(c - r1 * Math.cos(a))}`;
	}
	return d;
};

export const capPoint = (c: number, r: number, score: number) => {
	const a = (clamp(score) / 100) * 2 * Math.PI;
	return { x: f(c + r * Math.sin(a)), y: f(c - r * Math.cos(a)) };
};

/** Average glyph advance of a segment label at its font size (10 units), measured in Inter. */
export const LABEL_EM = 5.1;

export interface Segment {
	readonly label: string;
	readonly score: number | null;
	readonly grade: string | null;
}

export interface SegmentGeometry extends Segment {
	readonly d: string;
	readonly labelPath: string;
	readonly showLabel: boolean;
}

export const segments = (
	list: ReadonlyArray<Segment>,
	c = 120,
): SegmentGeometry[] => {
	const gap = list.length > 1 ? 4 : 0;
	const span = 360 / Math.max(1, list.length);
	return list.map((s, i) => {
		const a0 = i * span + gap / 2;
		const a1 = (i + 1) * span - gap / 2;
		const mid = (a0 + a1) / 2;
		const bottom = mid > 90 && mid < 270;
		// the label baseline: outside the segment on top, and further out at
		// the bottom, where the upright text hangs inwards from it
		const r = bottom ? 128 : 119;
		// labels may use the gap too, so long names fit at a readable size
		const l0 = i * span + 0.5;
		const l1 = (i + 1) * span - 0.5;
		const room = (2 * Math.PI * r * (l1 - l0)) / 360;
		return {
			...s,
			d: arc(c, 110, a0, a1),
			labelPath: bottom ? arcReverse(c, r, l0, l1) : arc(c, r, l0, l1),
			showLabel: list.length <= 12 && s.label.length * LABEL_EM <= room,
		};
	});
};
