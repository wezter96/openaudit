import { Parser } from "htmlparser2";

import { makeBudget } from "./limits";

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

/** Element or attribute name, such as `activity` or `exported`. */
export type XmlName = string;
/** Character data or the source of a text XML document. */
export type XmlText = string;
/** Byte or character offset into a document. */
export type Offset = number;

/** Framework attribute ids, used when AXML attribute names are stripped. */
export const ATTR_IDS: Record<number, string> = {
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

export const appendText = (el: XmlElement, text: XmlText) => {
	const t = text.trim();
	if (!t || (el.text?.length ?? 0) >= MAX_TEXT) return;
	el.text = (el.text ? `${el.text}${t}` : t).slice(0, MAX_TEXT);
};

/** The open elements while a document is decoded; the first one is the root. */
export class ElementStack {
	private readonly stack: XmlElement[] = [];
	root: XmlElement | undefined;

	get depth(): number {
		return this.stack.length;
	}

	get current(): XmlElement | undefined {
		return this.stack[this.stack.length - 1];
	}

	open(el: XmlElement) {
		const parent = this.current;
		if (parent) parent.children.push(el);
		else this.root ??= el;
		this.stack.push(el);
	}

	close() {
		this.stack.pop();
	}
}

/* -------------------------------- text XML -------------------------------- */

const lineStartsOf = (text: XmlText): Offset[] => {
	const lineStarts = [0];
	for (let i = 0; i < text.length; i++)
		if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
	return lineStarts;
};

/** 1-based line of `index`, by binary search over the line starts. */
const lineAt = (lineStarts: ReadonlyArray<Offset>, index: Offset) => {
	let lo = 0;
	let hi = lineStarts.length - 1;
	while (lo < hi) {
		const mid = (lo + hi + 1) >> 1;
		if ((lineStarts[mid] ?? 0) <= index) lo = mid;
		else hi = mid - 1;
	}
	return lo + 1;
};

const withoutAndroidPrefix = (
	attribs: Record<string, string>,
): Record<string, string> => {
	const attrs: Record<string, string> = {};
	for (const [k, v] of Object.entries(attribs))
		attrs[k.startsWith("android:") ? k.slice(8) : k] = v;
	return attrs;
};

/**
 * Parses a text XML document, stripping the `android:` attribute prefix.
 * Returns undefined when it exceeds the decode limits.
 */
export const parseXmlText = (text: XmlText): XmlElement | undefined => {
	const budget = makeBudget();
	const lineStarts = lineStartsOf(text);
	const tree = new ElementStack();
	const parser: Parser = new Parser(
		{
			onopentag(name, attribs) {
				budget.node();
				budget.depth(tree.depth);
				tree.open({
					name,
					attrs: withoutAndroidPrefix(attribs),
					children: [],
					line: lineAt(lineStarts, parser.startIndex),
				});
			},
			ontext(data) {
				const current = tree.current;
				if (current) appendText(current, data);
			},
			onclosetag() {
				tree.close();
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
	return tree.root;
};
