import { type Budget, makeBudget } from "./limits";
import {
	ATTR_IDS,
	appendText,
	type Offset,
	type XmlElement,
	type XmlName,
	type XmlText,
} from "./xml-tree";

/**
 * Decoder for aapt2 protobuf XML (`XmlNode`), the format of manifests and
 * resources inside .aab bundles.
 */

interface ProtoField {
	readonly field: number;
	readonly wire: number;
	readonly value: number;
	readonly bytes?: Uint8Array;
}

type FieldKey = Pick<ProtoField, "field" | "wire">;

const readVarint = (buf: Uint8Array, pos: Offset): [number, Offset] => {
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

/** Reads a field's payload at `p`; returns the field and the offset after it. */
type WireReader = (
	buf: Uint8Array,
	p: Offset,
	key: FieldKey,
) => [ProtoField, Offset];

const readVarintField: WireReader = (buf, p, key) => {
	const [value, next] = readVarint(buf, p);
	return [{ ...key, value }, next];
};

const readLengthDelimited: WireReader = (buf, p, key) => {
	const [len, next] = readVarint(buf, p);
	if (next + len > buf.length) throw new Error("truncated field");
	return [
		{ ...key, value: len, bytes: buf.subarray(next, next + len) },
		next + len,
	];
};

const fixedField =
	(size: number): WireReader =>
	(buf, p, key) => [
		{ ...key, value: 0, bytes: buf.subarray(p, p + size) },
		p + size,
	];

const WIRE_READERS = new Map<number, WireReader>([
	[0, readVarintField],
	[2, readLengthDelimited],
	[5, fixedField(4)],
	[1, fixedField(8)],
]);

const protoFields = (buf: Uint8Array): ProtoField[] => {
	const out: ProtoField[] = [];
	let p = 0;
	while (p < buf.length) {
		const [key, afterKey] = readVarint(buf, p);
		const wire = key % 8;
		const read = WIRE_READERS.get(wire);
		if (!read) throw new Error(`unsupported wire type ${wire}`);
		const [field, next] = read(buf, afterKey, {
			field: Math.floor(key / 8),
			wire,
		});
		out.push(field);
		p = next;
	}
	return out;
};

const fieldOf = (fields: ReadonlyArray<ProtoField>, n: number) =>
	fields.find((f) => f.field === n);

const protoText = (f: ProtoField | undefined) =>
	f?.bytes ? new TextDecoder().decode(f.bytes) : undefined;

/** Primitive { int_decimal = 6, int_hex = 7, boolean = 8 } renderings. */
const PRIMITIVE_FORMATS = new Map<number, (value: number) => string>([
	[8, (value) => (value !== 0 ? "true" : "false")],
	[6, (value) => String(value | 0)],
	[7, (value) => `0x${value.toString(16)}`],
]);

const primitiveValue = (prim: Uint8Array): string | undefined => {
	for (const g of protoFields(prim)) {
		const format = PRIMITIVE_FORMATS.get(g.field);
		if (format) return format(g.value);
	}
	return undefined;
};

/** Item.str / raw_str → String { value = 1 } */
const isStringItem = (f: ProtoField) => f.field === 2 || f.field === 3;

/** Value of an aapt2 `Item` when the attribute has no string form. */
const protoItemValue = (item: Uint8Array): string | undefined => {
	for (const f of protoFields(item)) {
		if (!f.bytes) continue;
		if (isStringItem(f)) return protoText(fieldOf(protoFields(f.bytes), 1));
		// Item.prim → Primitive
		const prim = f.field === 7 ? primitiveValue(f.bytes) : undefined;
		if (prim !== undefined) return prim;
	}
	return undefined;
};

/** XmlAttribute { name = 2, value = 3, resource_id = 5, compiled_item = 6 } */
const protoAttrName = (af: ReadonlyArray<ProtoField>): XmlName | undefined => {
	const resId = fieldOf(af, 5)?.value;
	return (
		protoText(fieldOf(af, 2)) ||
		(resId !== undefined ? ATTR_IDS[resId] : undefined)
	);
};

const protoAttrValue = (af: ReadonlyArray<ProtoField>): string => {
	const item = fieldOf(af, 6)?.bytes;
	return (
		protoText(fieldOf(af, 3)) || (item ? protoItemValue(item) : undefined) || ""
	);
};

interface ProtoContext {
	readonly budget: Budget;
	readonly depth: number;
}

/** The parts of an element collected while its fields are read. */
interface ElementParts {
	name: XmlName;
	readonly attrs: Record<string, string>;
	readonly children: XmlElement[];
	text: XmlText;
}

const readProtoAttribute = (
	parts: ElementParts,
	attr: Uint8Array,
	budget: Budget,
) => {
	budget.node();
	const af = protoFields(attr);
	const name = protoAttrName(af);
	if (name) parts.attrs[name] = protoAttrValue(af);
};

const readProtoChild = (
	parts: ElementParts,
	node: Uint8Array,
	ctx: ProtoContext,
) => {
	const child = decodeProtoNode(node, {
		budget: ctx.budget,
		depth: ctx.depth + 1,
	});
	if (typeof child === "string") parts.text += child;
	else if (child) parts.children.push(child);
};

/** XmlElement { name = 3, attribute = 4, child = 5 } */
const readElementField = (
	parts: ElementParts,
	f: ProtoField,
	ctx: ProtoContext,
) => {
	if (f.field === 3) parts.name = protoText(f) ?? "";
	else if (f.field === 4 && f.bytes)
		readProtoAttribute(parts, f.bytes, ctx.budget);
	else if (f.field === 5 && f.bytes) readProtoChild(parts, f.bytes, ctx);
};

const decodeProtoElement = (buf: Uint8Array, ctx: ProtoContext): XmlElement => {
	ctx.budget.node();
	ctx.budget.depth(ctx.depth);
	const parts: ElementParts = { name: "", attrs: {}, children: [], text: "" };
	for (const f of protoFields(buf)) readElementField(parts, f, ctx);
	const el: XmlElement = {
		name: parts.name,
		attrs: parts.attrs,
		children: parts.children,
	};
	appendText(el, parts.text);
	return el;
};

/** XmlNode.source = SourcePosition { line_number = 1 } */
const sourceLine = (source: Uint8Array | undefined) =>
	source ? fieldOf(protoFields(source), 1)?.value : undefined;

/** An element, or the text of a text node. */
const decodeProtoNode = (
	buf: Uint8Array,
	ctx: ProtoContext,
): XmlElement | string | undefined => {
	const fields = protoFields(buf);
	const element = fieldOf(fields, 1)?.bytes;
	if (!element) return protoText(fieldOf(fields, 2));
	const el = decodeProtoElement(element, ctx);
	const line = sourceLine(fieldOf(fields, 3)?.bytes);
	return line ? { ...el, line } : el;
};

/** Decodes an aapt2 protobuf `XmlNode` (manifests inside .aab bundles). */
export const decodeProtoXml = (bytes: Uint8Array): XmlElement | undefined => {
	try {
		const root = decodeProtoNode(bytes, { budget: makeBudget(), depth: 0 });
		return typeof root === "object" && root.name ? root : undefined;
	} catch {
		return undefined;
	}
};
