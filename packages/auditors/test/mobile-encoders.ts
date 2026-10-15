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

/** An index into the AXML string pool. */
type StringRef = number;

/** A typed attribute value: its raw string, value type and data. */
interface TypedValue {
	readonly raw: StringRef;
	readonly type: number;
	readonly data: number;
}

interface AxmlWriter {
	readonly uri: StringRef;
	readonly attrNames: ReadonlyArray<string>;
	readonly intern: (s: string) => StringRef;
	readonly body: Uint8Array[];
	line: number;
}

/** Attribute names in first-seen order, depth first. */
const collectAttrNames = (el: El, names: string[]): string[] => {
	for (const k of Object.keys(el.attrs ?? {}))
		if (!names.includes(k)) names.push(k);
	for (const c of el.children ?? []) collectAttrNames(c, names);
	return names;
};

/** A string pool that appends each new string once, after `initial`. */
const stringPool = (initial: string[]) => {
	const strings = [...initial];
	const index = new Map<string, StringRef>();
	const intern = (s: string) => {
		let i = index.get(s);
		if (i === undefined) {
			i = strings.length;
			strings.push(s);
			index.set(s, i);
		}
		return i;
	};
	return { strings, intern };
};

const typedValue = (
	w: AxmlWriter,
	v: string | number | boolean,
): TypedValue => {
	if (typeof v === "boolean")
		return { raw: NO_INDEX, type: 0x12, data: v ? NO_INDEX : 0 };
	if (typeof v === "number") return { raw: NO_INDEX, type: 0x10, data: v };
	const s = w.intern(v);
	return { raw: s, type: 0x03, data: s };
};

const attributeChunk = (
	w: AxmlWriter,
	[k, v]: [string, string | number | boolean],
): Uint8Array => {
	const nameIdx = w.attrNames.indexOf(k);
	const { raw, type, data } = typedValue(w, v);
	return concat(
		u32(w.uri),
		u32(nameIdx),
		u32(raw),
		u16(8),
		u8(0, type),
		u32(data),
	);
};

const startElementChunk = (
	line: number,
	name: StringRef,
	attrs: ReadonlyArray<Uint8Array>,
) =>
	concat(
		u16(0x0102),
		u16(16),
		u32(36 + 20 * attrs.length),
		u32(line),
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
	);

const textChunk = (line: number, text: StringRef) =>
	concat(
		u16(0x0104),
		u16(16),
		u32(28),
		u32(line),
		u32(NO_INDEX),
		u32(text),
		u16(8),
		u8(0, 0x03),
		u32(text),
	);

const endElementChunk = (line: number, name: StringRef) =>
	concat(
		u16(0x0103),
		u16(16),
		u32(24),
		u32(line),
		u32(NO_INDEX),
		u32(NO_INDEX),
		u32(name),
	);

const emitElement = (w: AxmlWriter, el: El) => {
	const name = w.intern(el.name);
	const attrs = Object.entries(el.attrs ?? {}).map((attr) =>
		attributeChunk(w, attr),
	);
	const myLine = w.line++;
	w.body.push(startElementChunk(myLine, name, attrs));
	if (el.text) w.body.push(textChunk(myLine, w.intern(el.text)));
	for (const c of el.children ?? []) emitElement(w, c);
	w.body.push(endElementChunk(myLine, name));
};

const namespaceChunk = (type: number, prefix: StringRef, uri: StringRef) =>
	concat(
		u16(type),
		u16(16),
		u32(24),
		u32(1),
		u32(NO_INDEX),
		u32(prefix),
		u32(uri),
	);

const stringPoolChunk = (strings: ReadonlyArray<string>, utf8: boolean) => {
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
	return concat(
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
};

const resourceMapChunk = (attrNames: ReadonlyArray<string>) => {
	const ids = attrNames.map((n) => ATTR_IDS[n] ?? 0);
	return concat(u16(0x0180), u16(8), u32(8 + 4 * ids.length), ...ids.map(u32));
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
	const attrNames = collectAttrNames(root, []);
	const pool = stringPool(attrNames.map((n) => (opts.stripAttrNames ? "" : n)));
	const uri = pool.intern(ANDROID_NS);
	const prefix = pool.intern("android");
	const w: AxmlWriter = {
		uri,
		attrNames,
		intern: pool.intern,
		body: [],
		line: 1,
	};
	emitElement(w, root);
	const content = concat(
		stringPoolChunk(pool.strings, utf8),
		resourceMapChunk(attrNames),
		namespaceChunk(0x0100, prefix, uri),
		...w.body,
		namespaceChunk(0x0101, prefix, uri),
	);
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
