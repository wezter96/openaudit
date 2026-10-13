/**
 * Minimal Android binary XML encoder for layout fixtures, with the typed
 * values `mobile-encoders.ts` lacks (dimensions, references, enum flags).
 */

export type LayoutValue =
	| string
	| boolean
	| number
	| {
			readonly dim: number;
			readonly unit: "px" | "dp" | "sp" | "pt" | "in" | "mm";
	  }
	| { readonly ref: number }
	| { readonly hex: number };

export interface LayoutEl {
	readonly name: string;
	readonly attrs?: Record<string, LayoutValue>;
	readonly children?: ReadonlyArray<LayoutEl>;
}

const NO_INDEX = 0xffffffff;
const ANDROID_NS = "http://schemas.android.com/apk/res/android";
const UNITS = { px: 0, dp: 1, sp: 2, pt: 3, in: 4, mm: 5 } as const;

const concat = (...parts: ReadonlyArray<Uint8Array>): Uint8Array => {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
};
const u8 = (...n: number[]) => Uint8Array.from(n);
const u16 = (n: number) => {
	const b = new Uint8Array(2);
	new DataView(b.buffer).setUint16(0, n, true);
	return b;
};
const u32 = (n: number) => {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, true);
	return b;
};

/** Complex dimension: mantissa in the top 24 bits, radix 23p0 (integers only). */
export const complexDimension = (value: number, unit: keyof typeof UNITS) =>
	((value << 8) | 0x00 | UNITS[unit]) >>> 0;

const utf16 = (s: string) => {
	const chars = new Uint8Array(s.length * 2);
	for (let i = 0; i < s.length; i++) {
		chars[i * 2] = s.charCodeAt(i) & 0xff;
		chars[i * 2 + 1] = s.charCodeAt(i) >> 8;
	}
	return concat(u16(s.length), chars, u16(0));
};

export const encodeLayout = (root: LayoutEl): Uint8Array => {
	const strings: string[] = [];
	const index = new Map<string, number>();
	const intern = (s: string) => {
		let i = index.get(s);
		if (i === undefined) {
			i = strings.length;
			strings.push(s);
			index.set(s, i);
		}
		return i;
	};
	const uri = intern(ANDROID_NS);
	const prefix = intern("android");
	const body: Uint8Array[] = [];
	let line = 1;
	const emit = (el: LayoutEl) => {
		const name = intern(el.name);
		const attrs = Object.entries(el.attrs ?? {}).map(([k, v]) => {
			const nameIdx = intern(k);
			const head = [u32(uri), u32(nameIdx)];
			const typed = (raw: number, type: number, data: number) =>
				concat(...head, u32(raw), u16(8), u8(0, type), u32(data));
			if (typeof v === "string") {
				const s = intern(v);
				return typed(s, 0x03, s);
			}
			if (typeof v === "boolean")
				return typed(NO_INDEX, 0x12, v ? NO_INDEX : 0);
			if (typeof v === "number") return typed(NO_INDEX, 0x10, v);
			if ("dim" in v)
				return typed(NO_INDEX, 0x05, complexDimension(v.dim, v.unit));
			if ("ref" in v) return typed(NO_INDEX, 0x01, v.ref);
			return typed(NO_INDEX, 0x11, v.hex);
		});
		const myLine = line++;
		body.push(
			concat(
				u16(0x0102),
				u16(16),
				u32(36 + 20 * attrs.length),
				u32(myLine),
				u32(NO_INDEX),
				u32(NO_INDEX),
				u32(name),
				u16(20),
				u16(20),
				u16(attrs.length),
				u16(0),
				u16(0),
				u16(0),
				...attrs,
			),
		);
		for (const c of el.children ?? []) emit(c);
		body.push(
			concat(
				u16(0x0103),
				u16(16),
				u32(24),
				u32(myLine),
				u32(NO_INDEX),
				u32(NO_INDEX),
				u32(name),
			),
		);
	};
	emit(root);
	const ns = (type: number) =>
		concat(
			u16(type),
			u16(16),
			u32(24),
			u32(1),
			u32(NO_INDEX),
			u32(prefix),
			u32(uri),
		);
	const encoded = strings.map(utf16);
	const offsets: number[] = [];
	let off = 0;
	for (const e of encoded) {
		offsets.push(off);
		off += e.length;
	}
	let data = concat(...encoded);
	if (data.length % 4)
		data = concat(data, new Uint8Array(4 - (data.length % 4)));
	const poolHeader = 28 + 4 * strings.length;
	const pool = concat(
		u16(0x0001),
		u16(28),
		u32(poolHeader + data.length),
		u32(strings.length),
		u32(0),
		u32(0),
		u32(poolHeader),
		u32(0),
		...offsets.map(u32),
		data,
	);
	const content = concat(pool, ns(0x0100), ...body, ns(0x0101));
	return concat(u16(0x0003), u16(8), u32(8 + content.length), content);
};
