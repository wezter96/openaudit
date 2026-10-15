import {
	type Confidence,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	type AttrValue,
	type Markup,
	type Offset,
	scanTags,
	type Tag,
} from "./accessibility-tags";
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

export { parseTag, scanTags, type Tag } from "./accessibility-tags";

/** Repository-relative file path. */
type FilePath = string;
/** File extension without the dot, lowercase. */
type Extension = string;
/** Value of an element's `role` attribute. */
type AriaRole = string;
/** Value of an element's `id` attribute. */
type ElementId = string;
/** Static value of an attribute. */
type AttrText = string;

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

const strValue = (v: AttrValue | undefined): AttrText | undefined =>
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
	text: Markup,
	lower: Markup,
	tag: Tag,
): string | undefined => {
	if (tag.selfClosing) return "";
	const close = lower.indexOf(`</${tag.name}`, tag.end);
	return close === -1 || close - tag.end > 4000
		? undefined
		: text.slice(tag.end, close);
};

/** Whether element content (between open and close tags) yields a name. */
const contentHasName = (content: Markup): boolean => {
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

const isWrappedInLabel = (text: Markup, index: Offset) =>
	text.lastIndexOf("<label", index) > text.lastIndexOf("</label", index);

const hasExplicitLabel = (text: Markup, id: ElementId) =>
	// id is escaped, so it only matches itself.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	new RegExp(
		`(?:\\bfor|htmlFor)\\s*=\\s*\\{?\\s*["'\`]${id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'\`]`,
	).test(text);

/** max-scale below 2 or user-scalable=no in a viewport `content` string. */
export const viewportBlocksZoom = (content: AttrText): boolean => {
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

/** A rule hit on one tag, before it is placed in the file. */
interface TagHit {
	readonly rule: A11yRule;
	readonly confidence: Confidence;
	readonly detail?: string;
}

/** A rule hit at a position in the file. */
interface Match extends TagHit {
	readonly index: Offset;
	readonly evidence: string;
}

interface TagContext {
	readonly text: Markup;
	readonly lower: Markup;
	readonly tag: Tag;
	readonly role: AriaRole | undefined;
}

type TagCheck = (ctx: TagContext) => TagHit | undefined;

interface TagRule {
	/** Element names the check applies to; every element when absent. */
	readonly on?: ReadonlySet<string>;
	readonly check: TagCheck;
}

const isPresentational = (role: AriaRole | undefined) =>
	role === "presentation" || role === "none";

const checkImgAlt: TagCheck = ({ tag, role }) => {
	if (isPresentational(role)) return undefined;
	return tag.attrs.has("alt") || hasName(tag)
		? undefined
		: { rule: RULES.imgAlt, confidence: "high" };
};

const KEY_HANDLERS = ["onkeydown", "onkeyup", "onkeypress"];

/** What a clickable non-interactive element lacks for keyboard users. */
const missingKeyboardSupport = (attrs: Tag["attrs"]) =>
	[
		attrs.has("role") ? undefined : "role",
		attrs.has("tabindex") ? undefined : "tabIndex",
		KEY_HANDLERS.some((handler) => attrs.has(handler))
			? undefined
			: "keyboard handler",
	].filter(Boolean);

const checkClickHandler: TagCheck = ({ tag, role }) => {
	if (!tag.attrs.has("onclick") || isPresentational(role)) return undefined;
	const missing = missingKeyboardSupport(tag.attrs);
	return missing.length
		? {
				rule: RULES.clickNonInteractive,
				confidence: "medium",
				detail: `Missing: ${missing.join(", ")}.`,
			}
		: undefined;
};

/** Missing href, `#`, empty or `javascript:`: the link goes nowhere. */
const isDeadHref = (href: AttrValue | undefined): boolean => {
	if (href === undefined) return true;
	const value = strValue(href);
	return value !== undefined && /^(#|javascript:.*|)$/i.test(value.trim());
};

const isJavascriptUrl = (href: AttrText | undefined): boolean =>
	href !== undefined && /^javascript:/i.test(href.trim());

const checkAnchorButton: TagCheck = ({ tag }) => {
	const href = tag.attrs.get("href");
	const actsAsButton = tag.attrs.has("onclick") && isDeadHref(href);
	return actsAsButton || isJavascriptUrl(strValue(href))
		? { rule: RULES.anchorButton, confidence: "high" }
		: undefined;
};

const checkPositiveTabindex: TagCheck = ({ tag }) => {
	const tabindex = tag.attrs.get("tabindex");
	if (tabindex === undefined || tabindex.kind === "bool") return undefined;
	const value = Number(tabindex.value.trim());
	return Number.isInteger(value) && value > 0
		? { rule: RULES.positiveTabindex, confidence: "high" }
		: undefined;
};

const checkAutofocus: TagCheck = ({ tag }) => {
	const autofocus = tag.attrs.get("autofocus");
	if (autofocus === undefined) return undefined;
	const disabled =
		autofocus.kind !== "bool" && /^false$/.test(autofocus.value.trim());
	return disabled ? undefined : { rule: RULES.autofocus, confidence: "medium" };
};

const FORM_CONTROLS = new Set(["input", "select", "textarea"]);

const inputType = (attrs: Tag["attrs"]): string =>
	(strValue(attrs.get("type")) ?? "text").toLowerCase();

/** A bound `type` or `id` may get its label at runtime. */
const hasBoundTypeOrId = (attrs: Tag["attrs"]): boolean =>
	attrs.get("type")?.kind === "expr" || attrs.get("id")?.kind === "expr";

const hasLabelFor = (text: Markup, attrs: Tag["attrs"]): boolean => {
	const id = attrs.get("id");
	return id?.kind === "string" && hasExplicitLabel(text, id.value);
};

const isLabelled = (text: Markup, tag: Tag): boolean => {
	if (hasName(tag) || UNLABELLED_INPUT_TYPES.has(inputType(tag.attrs)))
		return true;
	if (hasBoundTypeOrId(tag.attrs) || hasLabelFor(text, tag.attrs)) return true;
	return isWrappedInLabel(text, tag.start);
};

const checkFormLabel: TagCheck = ({ text, tag }) =>
	isLabelled(text, tag)
		? undefined
		: { rule: RULES.formLabel, confidence: "medium" };

const checkHtmlLang: TagCheck = ({ tag }) =>
	tag.attrs.has("lang") || tag.attrs.has("xml:lang")
		? undefined
		: { rule: RULES.htmlLang, confidence: "high" };

const isControl = (tag: Tag): boolean =>
	tag.name === "button" || (tag.name === "a" && tag.attrs.has("href"));

const checkEmptyControl: TagCheck = ({ text, lower, tag }) => {
	if (!isControl(tag) || hasName(tag)) return undefined;
	const content = elementContent(text, lower, tag);
	if (content === undefined || contentHasName(content)) return undefined;
	return {
		rule: RULES.emptyControl,
		confidence: ICON_COMPONENT.test(content) ? "low" : "medium",
	};
};

const checkViewportMeta: TagCheck = ({ tag }) => {
	if (strValue(tag.attrs.get("name"))?.toLowerCase() !== "viewport")
		return undefined;
	const content = strValue(tag.attrs.get("content"));
	return content && viewportBlocksZoom(content)
		? { rule: RULES.viewportZoom, confidence: "high" }
		: undefined;
};

const OUTLINE_NONE_CLASS = /(?:^|[\s"'`])outline-(?:none|0)(?=[\s"'`]|$)/;
const FOCUS_STYLE_CLASS =
	/focus(?:-visible|-within)?:(?:ring|outline|border|shadow|underline|bg)/;

const checkOutlineClass: TagCheck = ({ tag }) => {
	const cls = tag.attrs.get("class");
	if (cls === undefined || cls.kind === "bool") return undefined;
	if (!OUTLINE_NONE_CLASS.test(cls.value) || FOCUS_STYLE_CLASS.test(cls.value))
		return undefined;
	return {
		rule: RULES.outline,
		confidence: "low",
		detail:
			"Tailwind `outline-none` is used without a focus: / focus-visible: replacement.",
	};
};

/** Per-tag checks, in the order their findings are reported. */
const TAG_RULES: ReadonlyArray<TagRule> = [
	{ on: new Set(["img"]), check: checkImgAlt },
	{ on: NON_INTERACTIVE, check: checkClickHandler },
	{ on: new Set(["a"]), check: checkAnchorButton },
	{ check: checkPositiveTabindex },
	{ check: checkAutofocus },
	{ on: FORM_CONTROLS, check: checkFormLabel },
	{ on: new Set(["html"]), check: checkHtmlLang },
	{ check: checkEmptyControl },
	{ on: new Set(["meta"]), check: checkViewportMeta },
	{ check: checkOutlineClass },
];

const appliesTo = (rule: TagRule, tag: Tag): boolean =>
	rule.on?.has(tag.name) ?? true;

const tagMatches = (ctx: TagContext): Match[] => {
	const { start, end } = ctx.tag;
	const evidence = ctx.text.slice(start, end);
	return TAG_RULES.flatMap((rule) => {
		const hit = appliesTo(rule, ctx.tag) ? rule.check(ctx) : undefined;
		return hit ? [{ ...hit, index: start, evidence }] : [];
	});
};

const scanMarkup = (text: Markup): Match[] => {
	const lower = text.toLowerCase();
	return scanTags(text).flatMap((tag) =>
		tag.hasSpread || isHidden(tag)
			? []
			: tagMatches({ text, lower, tag, role: strValue(tag.attrs.get("role")) }),
	);
};

/** Next.js `viewport` exports that disable zoom. */
const scanViewportOptions = (text: Markup): Match[] =>
	Array.from(
		text.matchAll(
			/\b(?:userScalable\s*:\s*false|maximumScale\s*:\s*(?:1(?:\.\d+)?|0?\.\d+))\b/g,
		),
		(m) => ({
			rule: RULES.viewportZoom,
			index: m.index ?? 0,
			evidence: m[0],
			confidence: "medium",
		}),
	);

const hasStyles = (text: Markup, ext: Extension): boolean =>
	styleExt.has(ext) ||
	/<style[\s>]/.test(text) ||
	(scriptExt.has(ext) && /\boutline\s*:\s*["']?(?:none|0)\b/.test(text));

/** Whether the CSS block around `index` draws its own focus indicator. */
const hasOutlineReplacement = (text: Markup, index: Offset): boolean => {
	const open = text.lastIndexOf("{", index);
	const close = text.indexOf("}", index);
	const block = text.slice(open + 1, close === -1 ? undefined : close);
	return /box-shadow|boxShadow|border(?:-color|Color)?\s*:|outline-(?:color|style|width)\s*:/.test(
		block,
	);
};

const scanOutlineStyles = (text: Markup, ext: Extension): Match[] => {
	if (!hasStyles(text, ext) || /focus-visible/.test(text)) return [];
	const confidence: Confidence = styleExt.has(ext) ? "medium" : "low";
	return Array.from(text.matchAll(/\boutline\s*:\s*["']?(?:none|0)\b/g))
		.filter((m) => !hasOutlineReplacement(text, m.index ?? 0))
		.map((m) => ({
			rule: RULES.outline,
			index: m.index ?? 0,
			evidence: m[0],
			confidence,
		}));
};

interface FindingSite {
	readonly path: FilePath;
	readonly lineOf: (index: Offset) => number;
}

const toFinding = (site: FindingSite, match: Match): FindingInput => {
	const { rule, detail } = match;
	return {
		ruleId: `code.accessibility/${rule.id}`,
		title: rule.title,
		severity: rule.severity,
		category: "accessibility",
		message: detail ? `${rule.message} ${detail}` : rule.message,
		location: { file: site.path, line: site.lineOf(match.index) },
		evidence: truncate(match.evidence.replace(/\s+/g, " ")),
		remediation: rule.remediation,
		references: rule.wcag.map(wcagUrl),
		confidence: match.confidence,
		tags: rule.wcag.map((sc) => `wcag-${sc}`),
	};
};

/** Runs every rule over one file. Exported for unit tests. */
export const scanAccessibility = (file: SourceFile): FindingInput[] => {
	const { path, text } = file;
	const ext = extOf(path);
	const matches = [
		...(markupExt.has(ext) ? scanMarkup(text) : []),
		...(scriptExt.has(ext) ? scanViewportOptions(text) : []),
		...scanOutlineStyles(text, ext),
	];
	const site: FindingSite = { path, lineOf: lineLocator(text) };
	return matches.map((match) => toFinding(site, match));
};

const shouldScan = (path: FilePath) => {
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
