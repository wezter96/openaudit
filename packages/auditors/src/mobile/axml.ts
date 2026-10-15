import { decodeProtoXml } from "./axml-proto";
import { type Budget, makeBudget } from "./limits";
import {
	ATTR_IDS,
	appendText,
	ElementStack,
	type Offset,
	parseXmlText,
	type XmlElement,
	type XmlName,
} from "./xml-tree";

export { decodeProtoXml } from "./axml-proto";
export { parseXmlText, type XmlElement, type XmlName } from "./xml-tree";

export const ANDROID_NS = "http://schemas.android.com/apk/res/android";

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
const TYPE_DIMENSION = 0x05;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

/** A chunk of an AXML document: its type, header size and byte range. */
interface Chunk {
	readonly type: number;
	readonly start: Offset;
	readonly headerSize: number;
	readonly end: Offset;
}

/** Start and byte length of one string in a string pool. */
type StringSpan = [Offset, number];

/** UTF-8: length in chars, then in bytes; each 1 or 2 bytes (high bit = 2). */
const utf8Span = (view: DataView, at: Offset): StringSpan => {
	const p = at + ((view.getUint8(at) & 0x80) !== 0 ? 2 : 1);
	const len = view.getUint8(p);
	if ((len & 0x80) === 0) return [p + 1, len];
	return [p + 2, ((len & 0x7f) << 8) | view.getUint8(p + 1)];
};

/** UTF-16: length in code units, in 2 or 4 bytes (high bit = 4). */
const utf16Span = (view: DataView, at: Offset): StringSpan => {
	const len = view.getUint16(at, true);
	if ((len & 0x8000) === 0) return [at + 2, len * 2];
	return [at + 4, (((len & 0x7fff) << 16) | view.getUint16(at + 2, true)) * 2];
};

interface StringPool {
	readonly view: DataView;
	readonly bytes: Uint8Array;
	readonly decoder: TextDecoder;
	readonly span: (view: DataView, at: Offset) => StringSpan;
	readonly stringsStart: Offset;
	readonly end: Offset;
	readonly budget: Budget;
}

const poolString = (pool: StringPool, offset: Offset): string => {
	const [from, len] = pool.span(pool.view, pool.stringsStart + offset);
	if (from < pool.stringsStart || from + len > pool.end)
		throw new Error("String exceeds its pool");
	pool.budget.bytes(len);
	return pool.decoder.decode(pool.bytes.subarray(from, from + len));
};

const readStringPool = (
	view: DataView,
	chunk: Chunk,
	budget: Budget,
): string[] => {
	const { start, headerSize, end } = chunk;
	const count = view.getUint32(start + 8, true);
	const utf8 = (view.getUint32(start + 16, true) & UTF8_FLAG) !== 0;
	const stringsStart = start + view.getUint32(start + 20, true);
	if (start + headerSize + count * 4 > end)
		throw new Error("String pool index exceeds its chunk");
	const pool: StringPool = {
		view,
		bytes: new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
		decoder: new TextDecoder(utf8 ? "utf-8" : "utf-16le"),
		span: utf8 ? utf8Span : utf16Span,
		stringsStart,
		end,
		budget,
	};
	const out: string[] = [];
	// Offsets may repeat; decode each once so shared strings cost nothing extra.
	const byOffset = new Map<number, string>();
	for (let i = 0; i < count; i++) {
		const offset = view.getUint32(start + headerSize + i * 4, true);
		const text = byOffset.get(offset) ?? poolString(pool, offset);
		byOffset.set(offset, text);
		out.push(text);
	}
	return out;
};

const DIMENSION_UNITS = ["px", "dp", "sp", "pt", "in", "mm"] as const;
/** Multipliers for the 4 radix encodings of a complex value's mantissa. */
const RADIX_MULTIPLIERS = [2 ** -8, 2 ** -15, 2 ** -23, 2 ** -31] as const;

/** The 32-bit `data` of a typed AXML value. */
type ValueData = number;

/**
 * Decodes a TYPE_DIMENSION complex value (`data` of a typed AXML value) into
 * text such as `48dp` or `14.5sp`. Returns undefined for unknown units.
 */
export const decodeDimension = (data: ValueData): string | undefined => {
	const unit = DIMENSION_UNITS[data & 0xf];
	if (!unit) return undefined;
	const mantissa = (data & 0xffffff00) | 0;
	const value = mantissa * (RADIX_MULTIPLIERS[(data >> 4) & 0x3] ?? 0);
	return `${Number(value.toFixed(2))}${unit}`;
};

/** A parsed dimension such as `48dp` (also accepts `-1`/`wrap_content` as undefined). */
export interface Dimension {
	readonly value: number;
	readonly unit: (typeof DIMENSION_UNITS)[number];
}

export const parseDimension = (
	text: string | undefined,
): Dimension | undefined => {
	const [, value, unit] =
		/^(-?\d+(?:\.\d+)?)(px|dp|dip|sp|pt|in|mm)$/.exec(text?.trim() ?? "") ?? [];
	if (!value || !unit) return undefined;
	return {
		value: Number(value),
		unit: (unit === "dip" ? "dp" : unit) as Dimension["unit"],
	};
};

/** Options for decoders; the defaults match the manifest-oriented behaviour. */
export interface AxmlOptions {
	/**
	 * Render TYPE_DIMENSION values as `48dp`. Off by default, where they fall
	 * back to the raw string (or the unsigned complex value).
	 */
	readonly dimensions?: boolean;
}

/** A typed attribute value: its type, data and raw string, if any. */
interface TypedValue {
	readonly type: number;
	readonly data: ValueData;
	readonly raw: string | undefined;
}

const floatOf = (data: ValueData) => {
	const f = new DataView(new ArrayBuffer(4));
	f.setUint32(0, data, true);
	return f.getFloat32(0, true);
};

const VALUE_FORMATS = new Map<
	number,
	(v: TypedValue, strings: ReadonlyArray<string>) => string
>([
	[TYPE_STRING, (v, strings) => strings[v.data] ?? v.raw ?? ""],
	[TYPE_INT_BOOLEAN, (v) => (v.data !== 0 ? "true" : "false")],
	[TYPE_INT_DEC, (v) => String(v.data | 0)],
	[TYPE_INT_HEX, (v) => `0x${(v.data >>> 0).toString(16)}`],
	[TYPE_REFERENCE, (v) => `@0x${(v.data >>> 0).toString(16).padStart(8, "0")}`],
	[TYPE_FLOAT, (v) => String(floatOf(v.data))],
]);

const typedValue = (
	v: TypedValue,
	strings: ReadonlyArray<string>,
	dimensions = false,
): string => {
	const dim =
		dimensions && v.type === TYPE_DIMENSION
			? decodeDimension(v.data)
			: undefined;
	if (dim) return dim;
	const format = VALUE_FORMATS.get(v.type);
	return format ? format(v, strings) : (v.raw ?? String(v.data >>> 0));
};

/** Where a start element's attributes sit, and how many there are. */
interface AttributeLayout {
	readonly start: Offset;
	readonly size: number;
	readonly count: number;
}

const attributesOverflow = (layout: AttributeLayout, end: Offset) => {
	if (layout.count === 0) return false;
	return layout.size < 20 || layout.start + layout.count * layout.size > end;
};

/** True when the bytes start with an AXML (RES_XML_TYPE) header. */
export const isAxml = (bytes: Uint8Array): boolean =>
	bytes.length >= 8 && bytes[0] === RES_XML_TYPE && bytes[1] === 0x00;

/** Decodes the chunks of one AXML document into an element tree. */
class AxmlDecoder {
	private readonly view: DataView;
	private readonly budget = makeBudget();
	private readonly tree = new ElementStack();
	private strings: string[] = [];
	private resourceIds: number[] = [];

	constructor(
		bytes: Uint8Array,
		private readonly options: AxmlOptions,
	) {
		this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	}

	decode(): XmlElement | undefined {
		const { view } = this;
		const end = Math.min(view.getUint32(4, true), view.byteLength);
		let p = view.getUint16(2, true);
		while (p + 8 <= end) {
			const type = view.getUint16(p, true);
			const headerSize = view.getUint16(p + 2, true);
			const size = view.getUint32(p + 4, true);
			if (size < 8 || p + size > end) break;
			this.chunk({ type, start: p, headerSize, end: p + size });
			p += size;
		}
		return this.tree.root;
	}

	private chunk(c: Chunk) {
		switch (c.type) {
			case RES_STRING_POOL_TYPE:
				this.strings = readStringPool(this.view, c, this.budget);
				break;
			case RES_XML_RESOURCE_MAP_TYPE:
				this.resourceMap(c);
				break;
			case RES_XML_START_ELEMENT_TYPE:
				this.startElement(c);
				break;
			case RES_XML_END_ELEMENT_TYPE:
				this.tree.close();
				break;
			case RES_XML_CDATA_TYPE:
				this.characterData(c);
				break;
		}
	}

	private resourceMap(c: Chunk) {
		this.resourceIds = [];
		for (let q = c.start + c.headerSize; q + 4 <= c.end; q += 4)
			this.resourceIds.push(this.view.getUint32(q, true));
	}

	private startElement(c: Chunk) {
		const { view } = this;
		const line = view.getUint32(c.start + 8, true);
		const ext = c.start + c.headerSize;
		const name = this.strings[view.getUint32(ext + 4, true)] ?? "";
		const layout: AttributeLayout = {
			start: ext + view.getUint16(ext + 8, true),
			size: view.getUint16(ext + 10, true),
			count: view.getUint16(ext + 12, true),
		};
		if (attributesOverflow(layout, c.end))
			throw new Error("Attributes exceed their chunk");
		this.budget.node();
		this.budget.depth(this.tree.depth);
		const attrs: Record<string, string> = {};
		for (let i = 0; i < layout.count; i++) {
			this.budget.node();
			const [attrName, value] = this.attribute(layout.start + i * layout.size);
			attrs[attrName] = value;
		}
		this.tree.open({
			name,
			attrs,
			children: [],
			...(line > 0 ? { line } : {}),
		});
	}

	private attribute(a: Offset): [XmlName, string] {
		const { view, strings } = this;
		const nameIdx = view.getUint32(a + 4, true);
		const rawIdx = view.getUint32(a + 8, true);
		const type = view.getUint8(a + 15);
		const data = view.getUint32(a + 16, true);
		const attrName =
			strings[nameIdx] ||
			ATTR_IDS[this.resourceIds[nameIdx] ?? -1] ||
			`attr${nameIdx}`;
		const raw = rawIdx === NO_INDEX ? undefined : strings[rawIdx];
		return [
			attrName,
			typedValue({ type, data, raw }, strings, this.options.dimensions),
		];
	}

	private characterData(c: Chunk) {
		const current = this.tree.current;
		const data =
			this.strings[this.view.getUint32(c.start + c.headerSize, true)];
		if (current && data) appendText(current, data);
	}
}

/** Decodes Android binary XML. Returns undefined for malformed input. */
export const decodeAxml = (
	bytes: Uint8Array,
	options: AxmlOptions = {},
): XmlElement | undefined => {
	if (!isAxml(bytes)) return undefined;
	try {
		return new AxmlDecoder(bytes, options).decode();
	} catch {
		return undefined;
	}
};

/** Decodes AXML, protobuf XML or text XML, whichever the bytes contain. */
export const parseAndroidXml = (
	bytes: Uint8Array,
	options: AxmlOptions = {},
): XmlElement | undefined => {
	if (isAxml(bytes)) return decodeAxml(bytes, options);
	const head = new TextDecoder().decode(bytes.subarray(0, 64)).trimStart();
	if (head.startsWith("<") || head.startsWith("\uFEFF<"))
		return parseXmlText(new TextDecoder().decode(bytes));
	return decodeProtoXml(bytes);
};

/* --------------------------------- helpers -------------------------------- */

/** Direct children named `name`. */
export const childrenNamed = (el: XmlElement, name: XmlName): XmlElement[] =>
	el.children.filter((c) => c.name === name);

/** All descendants (depth-first) named `name`. */
export const descendants = (el: XmlElement, name: XmlName): XmlElement[] => {
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
