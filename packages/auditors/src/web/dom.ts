import { Parser } from "htmlparser2";

/**
 * A deliberately tiny DOM built from htmlparser2 callbacks. Auditors only need
 * tag names, attributes, text and parent links, and owning the shape keeps us
 * independent of domhandler's typings.
 */
export interface El {
	readonly type: "el";
	readonly name: string;
	readonly attrs: Readonly<Record<string, string>>;
	readonly children: Node[];
	readonly parent: El | undefined;
	/** Offset of the opening tag in the source HTML. */
	readonly start: number;
}

export interface TextNode {
	readonly type: "text";
	readonly data: string;
	readonly parent: El;
}

export type Node = El | TextNode;

export const parseHtml = (html: string): El => {
	const root: El = {
		type: "el",
		name: "#document",
		attrs: {},
		children: [],
		parent: undefined,
		start: 0,
	};
	let current = root;
	const parser = new Parser(
		{
			onopentag(name, attrs) {
				const el: El = {
					type: "el",
					name,
					attrs,
					children: [],
					parent: current,
					start: parser.startIndex,
				};
				current.children.push(el);
				current = el;
			},
			ontext(data) {
				current.children.push({ type: "text", data, parent: current });
			},
			onclosetag() {
				if (current.parent) current = current.parent;
			},
		},
		{
			decodeEntities: true,
			lowerCaseTags: true,
			lowerCaseAttributeNames: true,
		},
	);
	parser.write(html);
	parser.end();
	return root;
};

/** All descendant elements matching a tag name (or `*`) and optional predicate. */
export const findAll = (
	root: El,
	names: string | ReadonlyArray<string>,
	pred?: (el: El) => boolean,
): El[] => {
	const wanted = typeof names === "string" ? [names] : names;
	const any = wanted.includes("*");
	const out: El[] = [];
	const visit = (el: El) => {
		for (const child of el.children) {
			if (child.type !== "el") continue;
			if ((any || wanted.includes(child.name)) && (!pred || pred(child)))
				out.push(child);
			visit(child);
		}
	};
	visit(root);
	return out;
};

export const findFirst = (
	root: El,
	names: string | ReadonlyArray<string>,
	pred?: (el: El) => boolean,
): El | undefined => findAll(root, names, pred)[0];

export const attr = (el: El, name: string): string | undefined =>
	el.attrs[name];

export const hasAttr = (el: El, name: string): boolean => name in el.attrs;

/** Visible text content; skips script/style/template. */
export const textOf = (el: El): string => {
	let out = "";
	const visit = (node: Node) => {
		if (node.type === "text") out += node.data;
		else if (!["script", "style", "template", "noscript"].includes(node.name))
			for (const child of node.children) visit(child);
	};
	visit(el);
	return out.replace(/\s+/g, " ").trim();
};

/** Raw text content (for script/style bodies). */
export const rawText = (el: El): string =>
	el.children.map((c) => (c.type === "text" ? c.data : rawText(c))).join("");

export const closest = (el: El, name: string): El | undefined => {
	let cur = el.parent;
	while (cur) {
		if (cur.name === name) return cur;
		cur = cur.parent;
	}
	return undefined;
};

const cssIdent = (s: string) => s.replace(/([^\w-])/g, "\\$1");

/** A short, reasonably unique CSS selector for reporting. */
export const selectorOf = (el: El): string => {
	const parts: string[] = [];
	let cur: El | undefined = el;
	while (cur && cur.name !== "#document" && parts.length < 5) {
		const id = cur.attrs.id;
		if (id && /^[A-Za-z][\w-]*$/.test(id)) {
			parts.unshift(`${cur.name}#${cssIdent(id)}`);
			break;
		}
		let part = cur.name;
		const parent: El | undefined = cur.parent;
		if (parent && cur.name !== "html" && cur.name !== "body") {
			const siblings = parent.children.filter(
				(c): c is El => c.type === "el" && c.name === cur?.name,
			);
			if (siblings.length > 1)
				part += `:nth-of-type(${siblings.indexOf(cur) + 1})`;
		}
		parts.unshift(part);
		if (cur.name === "body" || cur.name === "html") break;
		cur = parent;
	}
	return parts.join(" > ");
};

/** Opening tag as it would appear in source, truncated for evidence. */
export const snippetOf = (el: El, max = 160): string => {
	const attrs = Object.entries(el.attrs)
		.map(([k, v]) => (v === "" ? k : `${k}="${v}"`))
		.join(" ");
	const tag = `<${el.name}${attrs ? ` ${attrs}` : ""}>`;
	return tag.length > max ? `${tag.slice(0, max)}…` : tag;
};
