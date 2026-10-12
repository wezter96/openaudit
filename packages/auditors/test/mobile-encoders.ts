import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zipSync } from "fflate";

/** Tiny encoders that build Android binary XML / aapt2 protobuf XML for tests. */

export interface El {
	readonly name: string;
	readonly attrs?: Record<string, string | number | boolean>;
	readonly children?: ReadonlyArray<El>;
	readonly text?: string;
}

const ANDROID_NS = "http://schemas.android.com/apk/res/android";
const NO_INDEX = 0xffffffff;

const ATTR_IDS: Record<string, number> = {
	name: 0x01010003,
	debuggable: 0x0101000f,
	exported: 0x01010010,
	allowBackup: 0x01010280,
	minSdkVersion: 0x0101020c,
	targetSdkVersion: 0x01010270,
};

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

const encodeString = (s: string, utf8: boolean): Uint8Array => {
	if (utf8) {
		const bytes = new TextEncoder().encode(s);
		return concat(u8(s.length, bytes.length), bytes, u8(0));
	}
	const chars = new Uint8Array(s.length * 2);
	for (let i = 0; i < s.length; i++) {
		chars[i * 2] = s.charCodeAt(i) & 0xff;
		chars[i * 2 + 1] = s.charCodeAt(i) >> 8;
	}
	return concat(u16(s.length), chars, u16(0));
};

/**
 * Encodes an element tree as AXML. All attributes go in the android
 * namespace. `stripAttrNames` blanks attribute name strings (as obfuscators
 * do) so decoding must fall back to the resource map.
 */
export const encodeAxml = (
	root: El,
	opts: { utf8?: boolean; stripAttrNames?: boolean } = {},
): Uint8Array => {
	const utf8 = opts.utf8 ?? false;
	// Attribute names come first so the resource map indexes line up.
	const attrNames: string[] = [];
	const collect = (el: El) => {
		for (const k of Object.keys(el.attrs ?? {}))
			if (!attrNames.includes(k)) attrNames.push(k);
		for (const c of el.children ?? []) collect(c);
	};
	collect(root);
	const strings = attrNames.map((n) => (opts.stripAttrNames ? "" : n));
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

	let line = 1;
	const body: Uint8Array[] = [];
	const emit = (el: El) => {
		const name = intern(el.name);
		const attrs = Object.entries(el.attrs ?? {}).map(([k, v]) => {
			const nameIdx = attrNames.indexOf(k);
			if (typeof v === "boolean")
				return concat(
					u32(uri),
					u32(nameIdx),
					u32(NO_INDEX),
					u16(8),
					u8(0, 0x12),
					u32(v ? NO_INDEX : 0),
				);
			if (typeof v === "number")
				return concat(
					u32(uri),
					u32(nameIdx),
					u32(NO_INDEX),
					u16(8),
					u8(0, 0x10),
					u32(v),
				);
			const s = intern(v);
			return concat(
				u32(uri),
				u32(nameIdx),
				u32(s),
				u16(8),
				u8(0, 0x03),
				u32(s),
			);
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
		if (el.text) {
			const t = intern(el.text);
			body.push(
				concat(
					u16(0x0104),
					u16(16),
					u32(28),
					u32(myLine),
					u32(NO_INDEX),
					u32(t),
					u16(8),
					u8(0, 0x03),
					u32(t),
				),
			);
		}
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

	const encoded = strings.map((s) => encodeString(s, utf8));
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
		u32(utf8 ? 0x100 : 0),
		u32(poolHeader),
		u32(0),
		...offsets.map(u32),
		data,
	);
	const ids = attrNames.map((n) => ATTR_IDS[n] ?? 0);
	const resMap = concat(
		u16(0x0180),
		u16(8),
		u32(8 + 4 * ids.length),
		...ids.map(u32),
	);
	const content = concat(pool, resMap, ns(0x0100), ...body, ns(0x0101));
	return concat(u16(0x0003), u16(8), u32(8 + content.length), content);
};

/* -------------------------------- protobuf -------------------------------- */

const varint = (n: number): Uint8Array => {
	const out: number[] = [];
	let v = n;
	while (v > 0x7f) {
		out.push((v & 0x7f) | 0x80);
		v = Math.floor(v / 128);
	}
	out.push(v);
	return Uint8Array.from(out);
};
const lenField = (field: number, payload: Uint8Array) =>
	concat(varint((field << 3) | 2), varint(payload.length), payload);
const strField = (field: number, s: string) =>
	lenField(field, new TextEncoder().encode(s));
const varField = (field: number, n: number) =>
	concat(varint(field << 3), varint(n));

/**
 * Encodes an element tree as an aapt2 `XmlNode`. Booleans and numbers are
 * written only as compiled items (no string value) to exercise that path.
 */
export const encodeProtoXml = (el: El): Uint8Array => {
	const attrs = Object.entries(el.attrs ?? {}).map(([k, v]) => {
		const parts = [strField(1, ANDROID_NS), strField(2, k)];
		if (typeof v === "string") parts.push(strField(3, v));
		else
			parts.push(
				lenField(
					6,
					lenField(
						7,
						typeof v === "boolean" ? varField(8, v ? 1 : 0) : varField(6, v),
					),
				),
			);
		return lenField(4, concat(...parts));
	});
	const children = (el.children ?? []).map((c) =>
		lenField(5, encodeProtoXml(c)),
	);
	const text = el.text ? [lenField(5, strField(2, el.text))] : [];
	return lenField(
		1,
		concat(strField(3, el.name), ...attrs, ...text, ...children),
	);
};

/** Writes a zip with the given entries to a fresh temp dir; returns its path. */
export const writeZip = (
	fileName: string,
	entries: Record<string, Uint8Array>,
): string => {
	const dir = mkdtempSync(join(tmpdir(), "openaudit-mobile-"));
	const path = join(dir, fileName);
	writeFileSync(path, zipSync(entries));
	return path;
};
