import {
	type Confidence,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	extOf,
	isFixturePath,
	isGeneratedPath,
	isTestPath,
	lineLocator,
	readTextFiles,
	type SourceFile,
	truncate,
	wcagUrl,
} from "./util";

/* -------------------------------------------------------------------------- */
/*                                 Tag parsing                                */
/* -------------------------------------------------------------------------- */

type AttrValue =
	| { readonly kind: "string"; readonly value: string }
	| { readonly kind: "expr"; readonly value: string }
	| { readonly kind: "bool" };

export interface Tag {
	readonly name: string;
	/** Normalised attribute names: `onClick`, `@click`, `on:click` → `onclick`. */
	readonly attrs: ReadonlyMap<string, AttrValue>;
	/** `{...props}` / `v-bind="obj"`: attributes we cannot see. */
	readonly hasSpread: boolean;
	readonly selfClosing: boolean;
	readonly start: number;
	/** Index just past the closing `>`. */
	readonly end: number;
}

/** Skips a balanced `{...}` starting at `i`; returns the index after `}`. */
const skipBraces = (text: string, i: number): number => {
	let depth = 0;
	for (let j = i; j < text.length && j - i < 4000; j++) {
		const ch = text[j];
		if (ch === '"' || ch === "'" || ch === "`") {
			const close = text.indexOf(ch, j + 1);
			if (close === -1) return -1;
			j = close;
		} else if (ch === "{") depth++;
		else if (ch === "}" && --depth === 0) return j + 1;
	}
	return -1;
};

const normaliseAttr = (raw: string): string => {
	let name = raw;
	if (name.startsWith("v-bind:")) name = name.slice(7);
	else if (name.startsWith(":")) name = name.slice(1);
	else if (name.startsWith("v-on:")) name = `on${name.slice(5)}`;
	else if (name.startsWith("@")) name = `on${name.slice(1)}`;
	else if (name.startsWith("on:")) name = `on${name.slice(3)}`;
	name = name.split(".")[0] ?? name; // @click.prevent
	name = name.toLowerCase();
	return name === "classname" ? "class" : name === "htmlfor" ? "for" : name;
};

/** Parses the tag opening at `start` (`text[start] === "<"`). */
export const parseTag = (text: string, start: number): Tag | undefined => {
	const nameMatch = /^<([a-zA-Z][\w.:-]*)/.exec(text.slice(start, start + 64));
	if (!nameMatch?.[1]) return undefined;
	const attrs = new Map<string, AttrValue>();
	let hasSpread = false;
	let j = start + nameMatch[0].length;
	const ws = () => {
		while (j < text.length && /\s/.test(text[j] ?? "")) j++;
	};
	while (j < text.length) {
		if (j - start > 6000) return undefined;
		ws();
		const ch = text[j];
		if (ch === ">") return done(false);
		if (ch === "/" && text[j + 1] === ">") {
			j++;
			return done(true);
		}
		if (ch === "{") {
			const end = skipBraces(text, j);
			if (end === -1) return undefined;
			const inner = text.slice(j + 1, end - 1).trim();
			if (inner.startsWith("...")) hasSpread = true;
			else if (/^\w+$/.test(inner))
				attrs.set(inner.toLowerCase(), { kind: "expr", value: inner }); // svelte {alt}
			j = end;
			continue;
		}
		const nm = /^[^\s=>/"'{}<]+/.exec(text.slice(j, j + 128));
		if (!nm) return undefined;
		const rawName = nm[0];
		j += rawName.length;
		ws();
		let value: AttrValue = { kind: "bool" };
		if (text[j] === "=") {
			j++;
			ws();
			const q = text[j];
			if (q === '"' || q === "'") {
				const close = text.indexOf(q, j + 1);
				if (close === -1) return undefined;
				const v = text.slice(j + 1, close);
				const bound = rawName.startsWith(":") || rawName.startsWith("v-bind:");
				value = { kind: bound ? "expr" : "string", value: v };
				j = close + 1;
			} else if (q === "{") {
				const end = skipBraces(text, j);
				if (end === -1) return undefined;
				value = { kind: "expr", value: text.slice(j + 1, end - 1).trim() };
				j = end;
			} else {
				const v = /^[^\s>]+/.exec(text.slice(j, j + 256))?.[0] ?? "";
				value = { kind: "string", value: v };
				j += v.length;
			}
		}
		if (rawName === "v-bind") hasSpread = true;
		else attrs.set(normaliseAttr(rawName), value);
	}
	return undefined;

	function done(selfClosing: boolean): Tag {
		return {
			name: nameMatch?.[1] ?? "",
			attrs,
			hasSpread,
			selfClosing,
			start,
			end: j + 1,
		};
	}
};

/** All lowercase (intrinsic HTML) opening tags in `text`. */
export const scanTags = (text: string): Tag[] => {
	const tags: Tag[] = [];
	for (const m of text.matchAll(/<[a-z][\w-]*(?=[\s/>])/g)) {
		const tag = parseTag(text, m.index ?? 0);
		if (tag) tags.push(tag);
	}
	return tags;
};

/* -------------------------------------------------------------------------- */
/*                                    Rules                                   */
/* -------------------------------------------------------------------------- */

interface A11yRule {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly wcag: ReadonlyArray<string>;
	readonly message: string;
	readonly remediation: string;
}

const RULES = {
	imgAlt: {
		id: "img-alt-missing",
		title: "Image without alt text",
		severity: "high",
		wcag: ["1.1.1"],
		message:
			"This <img> has no alt attribute, so screen readers announce the file name or nothing at all.",
		remediation:
			'Add a meaningful alt describing the image, or alt="" if it is purely decorative.',
	},
	clickNonInteractive: {
		id: "click-on-non-interactive",
		title: "Click handler on a non-interactive element",
		severity: "medium",
		wcag: ["2.1.1", "4.1.2"],
		message:
			"A click handler is attached to an element that keyboard and screen-reader users cannot reach or identify as interactive.",
		remediation:
			'Use a <button> (or <a href>) instead. If you must keep the element, add role="button", tabIndex={0} and an onKeyDown handler for Enter/Space.',
	},
	anchorButton: {
		id: "anchor-is-button",
		title: "Link used as a button",
		severity: "medium",
		wcag: ["2.1.1", "4.1.2"],
		message:
			'This <a> has no real destination (missing href, "#" or javascript:) and acts as a button, which confuses assistive tech and breaks keyboard expectations.',
		remediation:
			'Use <button type="button"> for actions and <a href> only for navigation.',
	},
	positiveTabindex: {
		id: "positive-tabindex",
		title: "Positive tabindex",
		severity: "low",
		wcag: ["2.4.3"],
		message:
			"A positive tabindex overrides the natural focus order, which makes keyboard navigation unpredictable.",
		remediation:
			"Use tabIndex={0} (or -1 for programmatic focus) and order the DOM to match the visual order.",
	},
	autofocus: {
		id: "no-autofocus",
		title: "autoFocus used",
		severity: "low",
		wcag: ["2.4.3", "3.2.1"],
		message:
			"Autofocus moves focus unexpectedly on load, disorienting screen-reader and keyboard users.",
		remediation:
			"Remove autoFocus, or only move focus in response to an explicit user action (e.g. opening a dialog).",
	},
	formLabel: {
		id: "form-label-missing",
		title: "Form control without a label",
		severity: "high",
		wcag: ["1.3.1", "3.3.2", "4.1.2"],
		message:
			"This form control has no associated <label>, aria-label or aria-labelledby, so its purpose is not announced. Placeholders do not count as labels.",
		remediation:
			'Wrap it in a <label>, add <label for="id"> (htmlFor in JSX), or provide aria-label / aria-labelledby.',
	},
	htmlLang: {
		id: "html-lang-missing",
		title: "<html> without lang",
		severity: "medium",
		wcag: ["3.1.1"],
		message:
			"The document language is not declared, so screen readers may pronounce content with the wrong voice.",
		remediation: 'Add a lang attribute, e.g. <html lang="en">.',
	},
	emptyControl: {
		id: "control-name-missing",
		title: "Button or link without an accessible name",
		severity: "high",
		wcag: ["4.1.2", "2.4.4"],
		message:
			'This button/link has no text content and no aria-label, so it is announced as just "button" or "link".',
		remediation:
			"Add visible text, visually-hidden text (e.g. a .sr-only span), or an aria-label describing the action.",
	},
	outline: {
		id: "focus-outline-removed",
		title: "Focus outline removed",
		severity: "medium",
		wcag: ["2.4.7"],
		message:
			"The focus outline is removed without a visible replacement, so keyboard users cannot see where focus is.",
		remediation:
			"Keep the outline, or replace it with a clearly visible :focus-visible style (outline, ring or box-shadow).",
	},
	viewportZoom: {
		id: "viewport-zoom-disabled",
		title: "Zoom disabled in viewport",
		severity: "high",
		wcag: ["1.4.4"],
		message:
			"The viewport prevents pinch-zoom (user-scalable=no or maximum-scale < 2), blocking low-vision users from enlarging content.",
		remediation:
			"Remove user-scalable=no and maximum-scale from the viewport meta (or Next.js viewport export).",
	},
} as const satisfies Record<string, A11yRule>;

const NON_INTERACTIVE = new Set([
	"div",
	"span",
	"li",
	"p",
	"section",
	"article",
	"td",
	"tr",
	"th",
	"img",
	"header",
	"footer",
	"main",
	"nav",
	"ul",
	"ol",
	"table",
	"h1",
	"h2",
	"h3",
	"h4",
	"h5",
	"h6",
	"aside",
	"figure",
	"i",
	"b",
	"strong",
	"em",
	"small",
	"svg",
]);

const UNLABELLED_INPUT_TYPES = new Set([
	"hidden",
	"submit",
	"button",
	"reset",
	"image",
]);

const ICON_COMPONENT =
	/<(?:\w+Icon|Icon\w*|Fa[A-Z]\w*|Md[A-Z]\w*|Io[A-Z]\w*|Hi[A-Z]\w*|Bi[A-Z]\w*|Ai[A-Z]\w*|Lu[A-Z]\w*)\b/;

const strValue = (v: AttrValue | undefined): string | undefined =>
	v?.kind === "string"
		? v.value
		: v?.kind === "expr"
			? /^["'`]([^"'`]*)["'`]$/.exec(v.value)?.[1]
			: undefined;

const hasName = (tag: Tag) =>
	tag.attrs.has("aria-label") ||
	tag.attrs.has("aria-labelledby") ||
	tag.attrs.has("title");

const isHidden = (tag: Tag) => {
	const hidden = tag.attrs.get("aria-hidden");
	return (
		hidden !== undefined &&
		(hidden.kind === "bool" || /^["'`]?true["'`]?$/.test(hidden.value.trim()))
	);
};

/** Text between an element's open tag and its first closing tag. */
const elementContent = (
	text: string,
	lower: string,
	tag: Tag,
): string | undefined => {
	if (tag.selfClosing) return "";
	const close = lower.indexOf(`</${tag.name}`, tag.end);
	return close === -1 || close - tag.end > 4000
		? undefined
		: text.slice(tag.end, close);
};

/** Whether element content (between open and close tags) yields a name. */
const contentHasName = (content: string): boolean => {
	if (/\{/.test(content)) return true; // expression or template interpolation
	if (/<img\b[^>]*\balt\s*=\s*["'][^"']+["']/i.test(content)) return true;
	if (/aria-label(?:ledby)?\s*=/i.test(content)) return true;
	if (/<[A-Z]/.test(content) && !ICON_COMPONENT.test(content)) return true;
	const text = content
		.replace(/<!--[\s\S]*?-->/g, "")
		.replace(/<[^>]*>/g, "")
		.replace(/&nbsp;|&#160;/g, "")
		.trim();
	return text.length > 0;
};

const isWrappedInLabel = (text: string, index: number) =>
	text.lastIndexOf("<label", index) > text.lastIndexOf("</label", index);

const hasExplicitLabel = (text: string, id: string) =>
	// id is escaped, so it only matches itself.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	new RegExp(
		`(?:\\bfor|htmlFor)\\s*=\\s*\\{?\\s*["'\`]${id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'\`]`,
	).test(text);

/** max-scale below 2 or user-scalable=no in a viewport `content` string. */
export const viewportBlocksZoom = (content: string): boolean => {
	if (/user-scalable\s*=\s*(?:no|0)\b/i.test(content)) return true;
	const max = /maximum-scale\s*=\s*([\d.]+)/i.exec(content)?.[1];
	return max !== undefined && Number(max) < 2;
};

const markupExt = new Set([
	"jsx",
	"tsx",
	"js",
	"mjs",
	"vue",
	"svelte",
	"astro",
	"html",
	"htm",
	"ejs",
	"hbs",
	"handlebars",
	"njk",
	"liquid",
	"erb",
	"twig",
	"jinja",
	"j2",
	"php",
]);
const styleExt = new Set(["css", "scss", "sass", "less", "styl"]);
const scriptExt = new Set(["ts", "mts", "js", "mjs", "jsx", "tsx"]);

/** Runs every rule over one file. Exported for unit tests. */
export const scanAccessibility = (file: SourceFile): FindingInput[] => {
	const { path, text } = file;
	const ext = extOf(path);
	const lineOf = lineLocator(text);
	const findings: FindingInput[] = [];
	const report = (
		rule: A11yRule,
		index: number,
		evidence: string,
		confidence: Confidence = "medium",
		detail?: string,
	) =>
		findings.push({
			ruleId: `code.accessibility/${rule.id}`,
			title: rule.title,
			severity: rule.severity,
			category: "accessibility",
			message: detail ? `${rule.message} ${detail}` : rule.message,
			location: { file: path, line: lineOf(index) },
			evidence: truncate(evidence.replace(/\s+/g, " ")),
			remediation: rule.remediation,
			references: rule.wcag.map(wcagUrl),
			confidence,
			tags: rule.wcag.map((sc) => `wcag-${sc}`),
		});

	if (markupExt.has(ext)) {
		const lower = text.toLowerCase();
		for (const tag of scanTags(text)) {
			const src = text.slice(tag.start, tag.end);
			const a = tag.attrs;
			if (tag.hasSpread || isHidden(tag)) continue;
			const role = strValue(a.get("role"));

			if (
				tag.name === "img" &&
				!a.has("alt") &&
				!hasName(tag) &&
				role !== "presentation" &&
				role !== "none"
			)
				report(RULES.imgAlt, tag.start, src, "high");

			if (
				NON_INTERACTIVE.has(tag.name) &&
				a.has("onclick") &&
				role !== "presentation" &&
				role !== "none"
			) {
				const missing = [
					a.has("role") ? undefined : "role",
					a.has("tabindex") ? undefined : "tabIndex",
					a.has("onkeydown") || a.has("onkeyup") || a.has("onkeypress")
						? undefined
						: "keyboard handler",
				].filter(Boolean);
				if (missing.length)
					report(
						RULES.clickNonInteractive,
						tag.start,
						src,
						"medium",
						`Missing: ${missing.join(", ")}.`,
					);
			}

			if (tag.name === "a") {
				const href = a.get("href");
				const hrefStr = strValue(href);
				const dead =
					href === undefined ||
					(hrefStr !== undefined &&
						/^(#|javascript:.*|)$/i.test(hrefStr.trim()));
				if (
					(a.has("onclick") && dead) ||
					(hrefStr !== undefined && /^javascript:/i.test(hrefStr.trim()))
				)
					report(RULES.anchorButton, tag.start, src, "high");
			}

			const tabindex = a.get("tabindex");
			const tabValue =
				tabindex?.kind === "bool" ? undefined : Number(tabindex?.value.trim());
			if (tabValue !== undefined && Number.isInteger(tabValue) && tabValue > 0)
				report(RULES.positiveTabindex, tag.start, src, "high");

			const autofocus = a.get("autofocus");
			if (
				autofocus &&
				!(autofocus.kind !== "bool" && /^false$/.test(autofocus.value.trim()))
			)
				report(RULES.autofocus, tag.start, src, "medium");

			if (
				tag.name === "input" ||
				tag.name === "select" ||
				tag.name === "textarea"
			) {
				const type = (strValue(a.get("type")) ?? "text").toLowerCase();
				const id = a.get("id");
				const labelled =
					hasName(tag) ||
					UNLABELLED_INPUT_TYPES.has(type) ||
					a.get("type")?.kind === "expr" ||
					id?.kind === "expr" ||
					(id?.kind === "string" && hasExplicitLabel(text, id.value)) ||
					isWrappedInLabel(text, tag.start);
				if (!labelled) report(RULES.formLabel, tag.start, src, "medium");
			}

			if (tag.name === "html" && !a.has("lang") && !a.has("xml:lang"))
				report(RULES.htmlLang, tag.start, src, "high");

			if (
				(tag.name === "button" || (tag.name === "a" && a.has("href"))) &&
				!hasName(tag)
			) {
				const content = elementContent(text, lower, tag);
				if (content !== undefined && !contentHasName(content))
					report(
						RULES.emptyControl,
						tag.start,
						src,
						ICON_COMPONENT.test(content) ? "low" : "medium",
					);
			}

			if (
				tag.name === "meta" &&
				strValue(a.get("name"))?.toLowerCase() === "viewport"
			) {
				const content = strValue(a.get("content"));
				if (content && viewportBlocksZoom(content))
					report(RULES.viewportZoom, tag.start, src, "high");
			}

			const cls = a.get("class");
			if (
				cls &&
				cls.kind !== "bool" &&
				/(?:^|[\s"'`])outline-(?:none|0)(?=[\s"'`]|$)/.test(cls.value)
			) {
				if (
					!/focus(?:-visible|-within)?:(?:ring|outline|border|shadow|underline|bg)/.test(
						cls.value,
					)
				)
					report(
						RULES.outline,
						tag.start,
						src,
						"low",
						"Tailwind `outline-none` is used without a focus: / focus-visible: replacement.",
					);
			}
		}
	}

	if (scriptExt.has(ext)) {
		for (const m of text.matchAll(
			/\b(?:userScalable\s*:\s*false|maximumScale\s*:\s*(?:1(?:\.\d+)?|0?\.\d+))\b/g,
		))
			report(RULES.viewportZoom, m.index ?? 0, m[0], "medium");
	}

	const hasStyles =
		styleExt.has(ext) ||
		/<style[\s>]/.test(text) ||
		(scriptExt.has(ext) && /\boutline\s*:\s*["']?(?:none|0)\b/.test(text));
	if (hasStyles && !/focus-visible/.test(text)) {
		for (const m of text.matchAll(/\boutline\s*:\s*["']?(?:none|0)\b/g)) {
			const index = m.index ?? 0;
			const open = text.lastIndexOf("{", index);
			const close = text.indexOf("}", index);
			const block = text.slice(open + 1, close === -1 ? undefined : close);
			if (
				/box-shadow|boxShadow|border(?:-color|Color)?\s*:|outline-(?:color|style|width)\s*:/.test(
					block,
				)
			)
				continue;
			report(RULES.outline, index, m[0], styleExt.has(ext) ? "medium" : "low");
		}
	}

	return findings;
};

const shouldScan = (path: string) => {
	const ext = extOf(path);
	return (
		(markupExt.has(ext) || styleExt.has(ext) || scriptExt.has(ext)) &&
		!isTestPath(path) &&
		!isFixturePath(path) &&
		!isGeneratedPath(path)
	);
};

export const accessibility = defineAuditor({
	id: "code.accessibility",
	title: "Accessibility (static)",
	description:
		"Static WCAG checks over JSX/TSX, Vue, Svelte, HTML templates and CSS: alt text, labels, keyboard access, focus visibility, document language and zoom.",
	categories: ["accessibility"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, shouldScan);
			return files.flatMap(scanAccessibility);
		}),
});
