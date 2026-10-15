import { Parser } from "htmlparser2";

import {
	isBinaryPlist,
	type PlistDict,
	type PlistValue,
	parseBinaryPlist,
} from "./bplist";
import { makeBudget } from "./limits";

export type { PlistDict, PlistValue } from "./bplist";

const decodeBase64 = (text: string): Uint8Array => {
	try {
		return Uint8Array.from(atob(text.replace(/\s+/g, "")), (c) =>
			c.charCodeAt(0),
		);
	} catch {
		return new Uint8Array();
	}
};

type Frame =
	| { readonly kind: "dict"; readonly value: PlistDict; key?: string }
	| { readonly kind: "array"; readonly value: PlistValue[] };

const newFrame = (name: string): Frame | undefined =>
	name === "dict"
		? { kind: "dict", value: Object.create(null) }
		: name === "array"
			? { kind: "array", value: [] }
			: undefined;

/** Elements whose text content is a single value. */
const LEAF_VALUES = new Map<string, (text: string) => PlistValue>([
	["string", (text) => text],
	["integer", (text) => Number.parseInt(text.trim(), 10)],
	["real", (text) => Number.parseFloat(text.trim())],
	["true", () => true],
	["false", () => false],
	["date", (text) => new Date(text.trim())],
	["data", decodeBase64],
]);

/** Builds a plist value from parser events, within the decode limits. */
class PlistBuilder {
	private readonly budget = makeBudget();
	private readonly stack: Frame[] = [];
	private text = "";
	private done = false;
	root: PlistValue | undefined;

	open(name: string) {
		this.text = "";
		if (this.done) return;
		const frame = newFrame(name);
		if (!frame) return;
		this.budget.depth(this.stack.length);
		this.stack.push(frame);
	}

	append(chunk: string) {
		this.budget.bytes(chunk.length);
		this.text += chunk;
	}

	close(name: string) {
		if (this.done) return;
		this.closeElement(name);
		this.text = "";
	}

	private closeElement(name: string) {
		if (name === "dict" || name === "array") {
			const frame = this.stack.pop();
			if (frame) this.add(frame.value);
			return;
		}
		if (name === "key") return this.setKey();
		const leaf = LEAF_VALUES.get(name);
		if (leaf) this.add(leaf(this.text));
	}

	private setKey() {
		const top = this.stack.at(-1);
		if (top?.kind === "dict") top.key = this.text;
	}

	private add(value: PlistValue) {
		this.budget.node();
		const top = this.stack.at(-1);
		if (!top) {
			if (this.root === undefined) this.root = value;
			this.done = true;
		} else if (top.kind === "array") top.value.push(value);
		else if (top.key !== undefined) {
			top.value[top.key] = value;
			top.key = undefined;
		}
	}
}

/**
 * Parses an XML property list. Returns `undefined` when there is no plist
 * root; throws when the document exceeds the decode limits.
 */
export const parseXmlPlist = (xml: string): PlistValue | undefined => {
	const builder = new PlistBuilder();
	const parser = new Parser(
		{
			onopentag: (name) => builder.open(name),
			ontext: (chunk) => builder.append(chunk),
			onclosetag: (name) => builder.close(name),
		},
		{ xmlMode: true, decodeEntities: true },
	);
	parser.write(xml);
	parser.end();
	return builder.root;
};

/** Parses a binary or XML plist; `undefined` when the bytes are neither. */
export const parsePlist = (bytes: Uint8Array): PlistValue | undefined => {
	try {
		if (isBinaryPlist(bytes)) return parseBinaryPlist(bytes);
		const text = new TextDecoder().decode(bytes);
		if (!/<plist[\s>]|<dict[\s>]/.test(text)) return undefined;
		return parseXmlPlist(text);
	} catch {
		return undefined;
	}
};

/**
 * Finds an XML plist embedded in other bytes, e.g. the CMS-signed
 * `embedded.mobileprovision`.
 */
export const extractEmbeddedPlist = (
	bytes: Uint8Array,
): PlistValue | undefined => {
	const latin1 = new TextDecoder("latin1").decode(bytes);
	const start = latin1.indexOf("<?xml");
	const end = latin1.indexOf("</plist>", start);
	if (start === -1 || end === -1) return undefined;
	const xml = new TextDecoder().decode(
		bytes.subarray(start, end + "</plist>".length),
	);
	try {
		return parseXmlPlist(xml);
	} catch {
		return undefined;
	}
};

const isDict = (v: PlistValue | undefined): v is PlistDict =>
	typeof v === "object" &&
	v !== null &&
	!Array.isArray(v) &&
	!(v instanceof Date) &&
	!(v instanceof Uint8Array);

/** Narrows a plist value to a dictionary. */
export const asDict = (v: PlistValue | undefined): PlistDict | undefined =>
	isDict(v) ? v : undefined;

/** True for plist/JSON truthy booleans (`<true/>`, `true`, `"YES"`). */
export const isTrue = (v: unknown): boolean =>
	v === true || v === 1 || v === "YES" || v === "true";
