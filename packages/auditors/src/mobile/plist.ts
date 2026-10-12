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

/**
 * Parses an XML property list. Returns `undefined` when there is no plist
 * root; throws when the document exceeds the decode limits.
 */
export const parseXmlPlist = (xml: string): PlistValue | undefined => {
	const budget = makeBudget();
	const stack: Frame[] = [];
	let root: PlistValue | undefined;
	let text = "";
	let done = false;

	const add = (value: PlistValue) => {
		budget.node();
		const top = stack.at(-1);
		if (!top) {
			if (root === undefined) root = value;
			done = true;
		} else if (top.kind === "array") top.value.push(value);
		else if (top.key !== undefined) {
			top.value[top.key] = value;
			top.key = undefined;
		}
	};

	const parser = new Parser(
		{
			onopentag(name) {
				text = "";
				if (done) return;
				if (name === "dict" || name === "array") budget.depth(stack.length);
				if (name === "dict")
					stack.push({ kind: "dict", value: Object.create(null) });
				else if (name === "array") stack.push({ kind: "array", value: [] });
			},
			ontext(chunk) {
				budget.bytes(chunk.length);
				text += chunk;
			},
			onclosetag(name) {
				if (done) return;
				switch (name) {
					case "dict":
					case "array": {
						const frame = stack.pop();
						if (frame) add(frame.value);
						break;
					}
					case "key": {
						const top = stack.at(-1);
						if (top?.kind === "dict") top.key = text;
						break;
					}
					case "string":
						add(text);
						break;
					case "integer":
						add(Number.parseInt(text.trim(), 10));
						break;
					case "real":
						add(Number.parseFloat(text.trim()));
						break;
					case "true":
						add(true);
						break;
					case "false":
						add(false);
						break;
					case "date":
						add(new Date(text.trim()));
						break;
					case "data":
						add(decodeBase64(text));
						break;
				}
				text = "";
			},
		},
		{ xmlMode: true, decodeEntities: true },
	);
	parser.write(xml);
	parser.end();
	return root;
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

/** Narrows a plist value to a dictionary. */
export const asDict = (v: PlistValue | undefined): PlistDict | undefined =>
	v !== null &&
	v !== undefined &&
	typeof v === "object" &&
	!Array.isArray(v) &&
	!(v instanceof Date) &&
	!(v instanceof Uint8Array)
		? v
		: undefined;

/** True for plist/JSON truthy booleans (`<true/>`, `true`, `"YES"`). */
export const isTrue = (v: unknown): boolean =>
	v === true || v === 1 || v === "YES" || v === "true";
