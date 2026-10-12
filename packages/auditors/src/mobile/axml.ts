import { Parser } from "htmlparser2";

import { type Budget, makeBudget } from "./limits";

/**
 * A minimal XML element tree shared by text manifests, Android binary XML
 * (AXML, used inside APKs) and aapt2 protobuf XML (used inside AABs).
 * Attribute names carry no `android:` prefix, e.g. `exported`, `name`.
 */
export interface XmlElement {
	readonly name: string;
	readonly attrs: Record<string, string>;
	readonly children: XmlElement[];
	/** Concatenated, trimmed character data, e.g. a `<domain>` host name. */
	text?: string;
	/** 1-based source line (text XML; AXML keeps the original line too). */
	readonly line?: number;
}

export const ANDROID_NS = "http://schemas.android.com/apk/res/android";

/** Framework attribute ids, used when AXML attribute names are stripped. */
const ATTR_IDS: Record<number, string> = {
	16842755: "name",
	16842758: "permission",
	16842759: "readPermission",
	16842760: "writePermission",
	16842767: "debuggable",
	16842768: "exported",
	16842770: "taskAffinity",
	16842781: "launchMode",
	16842791: "scheme",
	16842792: "host",
	16843276: "minSdkVersion",
	16843376: "targetSdkVersion",
	16843377: "maxSdkVersion",
	16843392: "allowBackup",
	16844012: "usesCleartextTraffic",
	16844014: "autoVerify",
	16844071: "networkSecurityConfig",
};

/** Character data kept per element; manifests only need short host names. */
const MAX_TEXT = 64 * 1024;

const appendText = (el: XmlElement, text: string) => {
	const t = text.trim();
	if (!t || (el.text?.length ?? 0) >= MAX_TEXT) return;
	el.text = (el.text ? `${el.text}${t}` : t).slice(0, MAX_TEXT);
};

/* --------------------------------- AXML ----------------------------------- */

const RES_XML_TYPE = 0x0003;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE = 0x0180;
const RES_XML_START_ELEMENT_TYPE = 0x0102;
const RES_XML_END_ELEMENT_TYPE = 0x0103;
const RES_XML_CDATA_TYPE = 0x0104;
const UTF8_FLAG = 1 << 8;
const NO_INDEX = 0xffffffff;

const TYPE_REFERENCE = 0x01;
const TYPE_STRING = 0x03;
const TYPE_FLOAT = 0x04;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

const readStringPool = (
	view: DataView,
	start: number,
	end: number,
	budget: Budget,
): string[] => {
	const count = view.getUint32(start + 8, true);
	const flags = view.getUint32(start + 16, true);
	const stringsStart = start + view.getUint32(start + 20, true);
	const headerSize = view.getUint16(start + 2, true);
	if (start + headerSize + count * 4 > end)
		throw new Error("String pool index exceeds its chunk");
	const utf8 = (flags & UTF8_FLAG) !== 0;
	const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
	const decoder = new TextDecoder(utf8 ? "utf-8" : "utf-16le");
	const out: string[] = [];
	// Offsets may repeat; decode each once so shared strings cost nothing extra.
	const byOffset = new Map<number, string>();
	const slice = (from: number, len: number) => {
		if (from < stringsStart || from + len > end)
			throw new Error("String exceeds its pool");
		budget.bytes(len);
		return decoder.decode(bytes.subarray(from, from + len));
	};
	for (let i = 0; i < count; i++) {
		const offset = view.getUint32(start + headerSize + i * 4, true);
		const cached = byOffset.get(offset);
		if (cached !== undefined) {
			out.push(cached);
			continue;
		}
		let p = stringsStart + offset;
		if (utf8) {
			// Length in chars, then in bytes; each 1 or 2 bytes (high bit = 2).
			p += (view.getUint8(p) & 0x80) !== 0 ? 2 : 1;
			let len = view.getUint8(p);
			if ((len & 0x80) !== 0) {
				len = ((len & 0x7f) << 8) | view.getUint8(p + 1);
				p += 2;
			} else p += 1;
			out.push(slice(p, len));
		} else {
			let len = view.getUint16(p, true);
			if ((len & 0x8000) !== 0) {
				len = ((len & 0x7fff) << 16) | view.getUint16(p + 2, true);
				p += 4;
			} else p += 2;
			out.push(slice(p, len * 2));
		}
		byOffset.set(offset, out[i] ?? "");
	}
	return out;
};

const typedValue = (
	type: number,
	data: number,
	raw: string | undefined,
	strings: ReadonlyArray<string>,
): string => {
	switch (type) {
		case TYPE_STRING:
			return strings[data] ?? raw ?? "";
		case TYPE_INT_BOOLEAN:
			return data !== 0 ? "true" : "false";
		case TYPE_INT_DEC:
			return String(data | 0);
		case TYPE_INT_HEX:
			return `0x${(data >>> 0).toString(16)}`;
		case TYPE_REFERENCE:
			return `@0x${(data >>> 0).toString(16).padStart(8, "0")}`;
		case TYPE_FLOAT: {
			const f = new DataView(new ArrayBuffer(4));
			f.setUint32(0, data, true);
			return String(f.getFloat32(0, true));
		}
		default:
			return raw ?? String(data >>> 0);
	}
};

/** True when the bytes start with an AXML (RES_XML_TYPE) header. */
export const isAxml = (bytes: Uint8Array): boolean =>
	bytes.length >= 8 && bytes[0] === RES_XML_TYPE && bytes[1] === 0x00;

/** Decodes Android binary XML. Returns undefined for malformed input. */
export const decodeAxml = (bytes: Uint8Array): XmlElement | undefined => {
	if (!isAxml(bytes)) return undefined;
	try {
		const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		const end = Math.min(view.getUint32(4, true), bytes.length);
		const budget = makeBudget();
		let strings: string[] = [];
		let resourceIds: number[] = [];
		const stack: XmlElement[] = [];
		let root: XmlElement | undefined;
		let p = view.getUint16(2, true);
		while (p + 8 <= end) {
			const type = view.getUint16(p, true);
			const headerSize = view.getUint16(p + 2, true);
			const size = view.getUint32(p + 4, true);
			if (size < 8 || p + size > end) break;
			if (type === RES_STRING_POOL_TYPE) {
				strings = readStringPool(view, p, p + size, budget);
			} else if (type === RES_XML_RESOURCE_MAP_TYPE) {
				resourceIds = [];
				for (let q = p + headerSize; q + 4 <= p + size; q += 4)
					resourceIds.push(view.getUint32(q, true));
			} else if (type === RES_XML_START_ELEMENT_TYPE) {
				const line = view.getUint32(p + 8, true);
				const ext = p + headerSize;
				const name = strings[view.getUint32(ext + 4, true)] ?? "";
				const attrStart = view.getUint16(ext + 8, true);
				const attrSize = view.getUint16(ext + 10, true);
				const attrCount = view.getUint16(ext + 12, true);
				if (
					attrCount > 0 &&
					(attrSize < 20 || ext + attrStart + attrCount * attrSize > p + size)
				)
					throw new Error("Attributes exceed their chunk");
				budget.node();
				budget.depth(stack.length);
				const attrs: Record<string, string> = {};
				for (let i = 0; i < attrCount; i++) {
					budget.node();
					const a = ext + attrStart + i * attrSize;
					const nameIdx = view.getUint32(a + 4, true);
					const rawIdx = view.getUint32(a + 8, true);
					const valueType = view.getUint8(a + 15);
					const data = view.getUint32(a + 16, true);
					const attrName =
						strings[nameIdx] ||
						ATTR_IDS[resourceIds[nameIdx] ?? -1] ||
						`attr${nameIdx}`;
					const raw = rawIdx === NO_INDEX ? undefined : strings[rawIdx];
					attrs[attrName] = typedValue(valueType, data, raw, strings);
				}
				const el: XmlElement = {
					name,
					attrs,
					children: [],
					...(line > 0 ? { line } : {}),
				};
				const parent = stack[stack.length - 1];
				if (parent) parent.children.push(el);
				else root ??= el;
				stack.push(el);
			} else if (type === RES_XML_END_ELEMENT_TYPE) {
				stack.pop();
			} else if (type === RES_XML_CDATA_TYPE) {
				const current = stack[stack.length - 1];
				const data = strings[view.getUint32(p + headerSize, true)];
				if (current && data) appendText(current, data);
			}
			p += size;
		}
		return root;
	} catch {
		return undefined;
	}
};

/* ------------------------------ protobuf XML ------------------------------ */

interface ProtoField {
	readonly field: number;
	readonly wire: number;
	readonly value: number;
	readonly bytes?: Uint8Array;
}

const readVarint = (buf: Uint8Array, pos: number): [number, number] => {
	let result = 0;
	let shift = 0;
	let p = pos;
	for (;;) {
		const b = buf[p++];
		if (b === undefined) throw new Error("truncated varint");
		if (shift < 53) result += (b & 0x7f) * 2 ** shift;
		shift += 7;
		if ((b & 0x80) === 0) return [result, p];
	}
};

const protoFields = (buf: Uint8Array): ProtoField[] => {
	const out: ProtoField[] = [];
	let p = 0;
	while (p < buf.length) {
		const [key, afterKey] = readVarint(buf, p);
		const field = Math.floor(key / 8);
		const wire = key % 8;
		p = afterKey;
		if (wire === 0) {
			const [value, next] = readVarint(buf, p);
			out.push({ field, wire, value });
			p = next;
		} else if (wire === 2) {
			const [len, next] = readVarint(buf, p);
			if (next + len > buf.length) throw new Error("truncated field");
			out.push({
				field,
				wire,
				value: len,
				bytes: buf.subarray(next, next + len),
			});
			p = next + len;
		} else if (wire === 5) {
			out.push({ field, wire, value: 0, bytes: buf.subarray(p, p + 4) });
			p += 4;
		} else if (wire === 1) {
			out.push({ field, wire, value: 0, bytes: buf.subarray(p, p + 8) });
			p += 8;
		} else throw new Error(`unsupported wire type ${wire}`);
	}
	return out;
};

const protoText = (f: ProtoField | undefined) =>
	f?.bytes ? new TextDecoder().decode(f.bytes) : undefined;

/** Value of an aapt2 `Item` when the attribute has no string form. */
const protoItemValue = (item: Uint8Array): string | undefined => {
	for (const f of protoFields(item)) {
		// Item.str / raw_str → String { value = 1 }
		if ((f.field === 2 || f.field === 3) && f.bytes)
			return protoText(protoFields(f.bytes).find((g) => g.field === 1));
		// Item.prim → Primitive { int_decimal = 6, int_hex = 7, boolean = 8 }
		if (f.field === 7 && f.bytes) {
			for (const g of protoFields(f.bytes)) {
				if (g.field === 8) return g.value !== 0 ? "true" : "false";
				if (g.field === 6) return String(g.value | 0);
				if (g.field === 7) return `0x${g.value.toString(16)}`;
			}
		}
	}
	return undefined;
};

const decodeProtoElement = (
	buf: Uint8Array,
	budget: Budget,
	depth: number,
): XmlElement => {
	budget.node();
	budget.depth(depth);
	let name = "";
	const attrs: Record<string, string> = {};
	const children: XmlElement[] = [];
	let text = "";
	for (const f of protoFields(buf)) {
		if (f.field === 3) name = protoText(f) ?? "";
		else if (f.field === 4 && f.bytes) {
			budget.node();
			const af = protoFields(f.bytes);
			const resId = af.find((g) => g.field === 5)?.value;
			const attrName =
				protoText(af.find((g) => g.field === 2)) ||
				(resId !== undefined ? ATTR_IDS[resId] : undefined);
			if (!attrName) continue;
			const item = af.find((g) => g.field === 6)?.bytes;
			attrs[attrName] =
				protoText(af.find((g) => g.field === 3)) ||
				(item ? protoItemValue(item) : undefined) ||
				"";
		} else if (f.field === 5 && f.bytes) {
			const child = decodeProtoNode(f.bytes, budget, depth + 1);
			if (typeof child === "string") text += child;
			else if (child) children.push(child);
		}
	}
	const el: XmlElement = { name, attrs, children };
	appendText(el, text);
	return el;
};

/** An element, or the text of a text node. */
const decodeProtoNode = (
	buf: Uint8Array,
	budget: Budget,
	depth: number,
): XmlElement | string | undefined => {
	const fields = protoFields(buf);
	const element = fields.find((f) => f.field === 1)?.bytes;
	if (!element) return protoText(fields.find((f) => f.field === 2));
	const el = decodeProtoElement(element, budget, depth);
	// XmlNode.source = SourcePosition { line_number = 1 }
	const source = fields.find((f) => f.field === 3)?.bytes;
	const line = source
		? protoFields(source).find((f) => f.field === 1)?.value
		: undefined;
	return line ? { ...el, line } : el;
};

/** Decodes an aapt2 protobuf `XmlNode` (manifests inside .aab bundles). */
export const decodeProtoXml = (bytes: Uint8Array): XmlElement | undefined => {
	try {
		const root = decodeProtoNode(bytes, makeBudget(), 0);
		return typeof root === "object" && root.name ? root : undefined;
	} catch {
		return undefined;
	}
};

/* -------------------------------- text XML -------------------------------- */

/**
 * Parses a text XML document, stripping the `android:` attribute prefix.
 * Returns undefined when it exceeds the decode limits.
 */
export const parseXmlText = (text: string): XmlElement | undefined => {
	const budget = makeBudget();
	const lineStarts = [0];
	for (let i = 0; i < text.length; i++)
		if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
	const lineAt = (index: number) => {
		let lo = 0;
		let hi = lineStarts.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if ((lineStarts[mid] ?? 0) <= index) lo = mid;
			else hi = mid - 1;
		}
		return lo + 1;
	};
	let root: XmlElement | undefined;
	const stack: XmlElement[] = [];
	const parser: Parser = new Parser(
		{
			onopentag(name, attribs) {
				budget.node();
				budget.depth(stack.length);
				const attrs: Record<string, string> = {};
				for (const [k, v] of Object.entries(attribs))
					attrs[k.startsWith("android:") ? k.slice(8) : k] = v;
				const el: XmlElement = {
					name,
					attrs,
					children: [],
					line: lineAt(parser.startIndex),
				};
				const parent = stack[stack.length - 1];
				if (parent) parent.children.push(el);
				else root ??= el;
				stack.push(el);
			},
			ontext(data) {
				const current = stack[stack.length - 1];
				if (current) appendText(current, data);
			},
			onclosetag() {
				stack.pop();
			},
		},
		{ xmlMode: true },
	);
	try {
		parser.write(text);
		parser.end();
	} catch {
		return undefined;
	}
	return root;
};

/** Decodes AXML, protobuf XML or text XML, whichever the bytes contain. */
export const parseAndroidXml = (bytes: Uint8Array): XmlElement | undefined => {
	if (isAxml(bytes)) return decodeAxml(bytes);
	const head = new TextDecoder().decode(bytes.subarray(0, 64)).trimStart();
	if (head.startsWith("<") || head.startsWith("﻿<"))
		return parseXmlText(new TextDecoder().decode(bytes));
	return decodeProtoXml(bytes);
};

/* --------------------------------- helpers -------------------------------- */

/** Direct children named `name`. */
export const childrenNamed = (el: XmlElement, name: string): XmlElement[] =>
	el.children.filter((c) => c.name === name);

/** All descendants (depth-first) named `name`. */
export const descendants = (el: XmlElement, name: string): XmlElement[] => {
	const out: XmlElement[] = [];
	const visit = (e: XmlElement) => {
		for (const c of e.children) {
			if (c.name === name) out.push(c);
			visit(c);
		}
	};
	visit(el);
	return out;
};

/** A compact `<tag attr="…">` rendering for evidence. */
export const renderTag = (el: XmlElement, max = 160): string => {
	const attrs = Object.entries(el.attrs)
		.map(([k, v]) => ` ${k}="${v}"`)
		.join("");
	const s = `<${el.name}${attrs}>`;
	return s.length > max ? `${s.slice(0, max)}…` : s;
};
