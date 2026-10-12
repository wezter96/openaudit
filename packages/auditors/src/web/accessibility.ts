import {
	defineAuditor,
	type FindingInput,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	closest,
	type El,
	findAll,
	findFirst,
	selectorOf,
	snippetOf,
	textOf,
} from "./dom";
import { htmlPages, type Page } from "./page";

const WCAG = "https://www.w3.org/WAI/WCAG22/Understanding";
const DEQUE = "https://dequeuniversity.com/rules/axe/4.10";
/** Per rule and page, so one templated widget does not flood the report. */
const MAX_PER_RULE = 25;

interface Rule {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly wcag: ReadonlyArray<string>;
	readonly understanding?: string;
	readonly axe?: string;
	readonly remediation: string;
}

const hidden = (el: El): boolean => {
	let cur: El | undefined = el;
	while (cur) {
		if (
			"hidden" in cur.attrs ||
			cur.attrs["aria-hidden"] === "true" ||
			/display\s*:\s*none|visibility\s*:\s*hidden/i.test(cur.attrs.style ?? "")
		)
			return true;
		cur = cur.parent;
	}
	return false;
};

const ariaName = (page: Page, el: El): string => {
	const label = el.attrs["aria-label"]?.trim();
	if (label) return label;
	const ids = el.attrs["aria-labelledby"]?.trim().split(/\s+/) ?? [];
	return ids
		.map((id) => {
			const ref = findFirst(page.doc, "*", (e) => e.attrs.id === id);
			return ref ? textOf(ref) : "";
		})
		.join(" ")
		.trim();
};

/** Accessible name from content: text plus alt text of images inside. */
const contentName = (el: El): string => {
	const alts = findAll(el, ["img", "area"], (i) => !!i.attrs.alt?.trim())
		.map((i) => i.attrs.alt)
		.join(" ");
	const svgTitles = findAll(el, "title").map(textOf).join(" ");
	return `${textOf(el)} ${alts} ${svgTitles}`.trim();
};

const isPresentational = (el: El) =>
	/^(presentation|none)$/.test(el.attrs.role ?? "");

/** Static (non-rendered) WCAG checks over the crawled HTML. */
const checkPage = (page: Page): FindingInput[] => {
	const findings: FindingInput[] = [];
	const counts = new Map<string, number>();
	const report = (rule: Rule, el: El | undefined, message: string) => {
		const n = (counts.get(rule.id) ?? 0) + 1;
		counts.set(rule.id, n);
		if (n > MAX_PER_RULE) return;
		const references = [
			...(rule.understanding ? [`${WCAG}/${rule.understanding}`] : []),
			...(rule.axe ? [`${DEQUE}/${rule.axe}`] : []),
		];
		findings.push({
			ruleId: `web.accessibility/${rule.id}`,
			title: rule.title,
			severity: rule.severity,
			category: "accessibility",
			message,
			location: { url: page.url, selector: el ? selectorOf(el) : undefined },
			evidence: el ? snippetOf(el) : undefined,
			remediation: rule.remediation,
			references,
			tags: rule.wcag.map((sc) => `wcag-${sc}`),
		});
	};
	const doc = page.doc;

	/* ------------------------------ document ------------------------------ */
	const html = findFirst(doc, "html");
	if (!html?.attrs.lang?.trim())
		report(
			{
				id: "html-lang-missing",
				title: "<html> has no lang attribute",
				severity: "medium",
				wcag: ["3.1.1"],
				understanding: "language-of-page",
				axe: "html-has-lang",
				remediation: 'Set the page language, e.g. <html lang="en">.',
			},
			html,
			"Screen readers use the lang attribute to choose pronunciation; without it, content may be read with the wrong voice.",
		);
	const title = findFirst(doc, "title", (t) => !closest(t, "svg"));
	if (!title || !textOf(title))
		report(
			{
				id: "document-title-missing",
				title: "Document has no title",
				severity: "medium",
				wcag: ["2.4.2"],
				understanding: "page-titled",
				axe: "document-title",
				remediation: "Add a descriptive <title> to the <head>.",
			},
			undefined,
			"The page has no <title>, which is the first thing screen readers announce and what identifies the tab.",
		);

	const viewport = findFirst(
		doc,
		"meta",
		(m) => (m.attrs.name ?? "").toLowerCase() === "viewport",
	);
	const vp = (viewport?.attrs.content ?? "").toLowerCase();
	const maxScale = Number(
		vp.match(/maximum-scale\s*=\s*([\d.]+)/)?.[1] ?? "10",
	);
	if (viewport && (/user-scalable\s*=\s*(no|0)\b/.test(vp) || maxScale < 2))
		report(
			{
				id: "viewport-zoom-disabled",
				title: "Zooming is disabled",
				severity: "medium",
				wcag: ["1.4.4"],
				understanding: "resize-text",
				axe: "meta-viewport",
				remediation:
					"Remove user-scalable=no and maximum-scale below 2 from the viewport meta tag.",
			},
			viewport,
			"The viewport meta tag prevents pinch-zoom, so low-vision users cannot enlarge text.",
		);

	/* ------------------------------- images -------------------------------- */
	for (const img of findAll(doc, "img")) {
		if (
			"alt" in img.attrs ||
			isPresentational(img) ||
			hidden(img) ||
			ariaName(page, img)
		)
			continue;
		report(
			{
				id: "image-alt",
				title: "Image has no alt text",
				severity: "high",
				wcag: ["1.1.1"],
				understanding: "non-text-content",
				axe: "image-alt",
				remediation:
					'Add alt text describing the image, or alt="" if it is purely decorative.',
			},
			img,
			`Image ${img.attrs.src ? `"${img.attrs.src.slice(0, 80)}" ` : ""}has no alt attribute, so screen readers announce the file name or nothing at all.`,
		);
	}
	for (const input of findAll(
		doc,
		"input",
		(i) => (i.attrs.type ?? "").toLowerCase() === "image",
	)) {
		if (
			input.attrs.alt?.trim() ||
			ariaName(page, input) ||
			input.attrs.title?.trim()
		)
			continue;
		report(
			{
				id: "input-image-alt",
				title: "Image button has no alt text",
				severity: "high",
				wcag: ["1.1.1", "4.1.2"],
				understanding: "non-text-content",
				axe: "input-image-alt",
				remediation: "Add alt text describing the button's action.",
			},
			input,
			"An <input type=image> has no alternative text, so its purpose is not announced.",
		);
	}
	for (const area of findAll(doc, "area", (a) => "href" in a.attrs)) {
		if (area.attrs.alt?.trim() || ariaName(page, area)) continue;
		report(
			{
				id: "area-alt",
				title: "Image map area has no alt text",
				severity: "high",
				wcag: ["1.1.1", "2.4.4"],
				understanding: "non-text-content",
				axe: "area-alt",
				remediation:
					"Give each <area> an alt attribute describing its link target.",
			},
			area,
			"An image map <area> link has no alt text.",
		);
	}

	/* -------------------------------- forms -------------------------------- */
	const labelFor = new Set(
		findAll(doc, "label")
			.map((l) => l.attrs.for)
			.filter(Boolean),
	);
	for (const field of findAll(doc, ["input", "select", "textarea"])) {
		const type = (field.attrs.type ?? "text").toLowerCase();
		if (
			field.name === "input" &&
			["hidden", "submit", "button", "reset", "image"].includes(type)
		)
			continue;
		if (hidden(field)) continue;
		const labelled =
			(field.attrs.id && labelFor.has(field.attrs.id)) ||
			closest(field, "label") ||
			ariaName(page, field) ||
			field.attrs.title?.trim();
		if (labelled) continue;
		report(
			{
				id: "form-label",
				title: "Form field has no label",
				severity: "high",
				wcag: ["1.3.1", "4.1.2"],
				understanding: "info-and-relationships",
				axe: "label",
				remediation:
					'Associate a visible <label for="id"> with the field (placeholder text is not a label).',
			},
			field,
			`A ${field.name}${field.name === "input" ? ` type=${type}` : ""} has no programmatic label${field.attrs.placeholder ? " (placeholder is not a substitute)" : ""}, so screen-reader users do not know what to enter.`,
		);
	}

	/* -------------------------- links and buttons -------------------------- */
	for (const a of findAll(doc, "a", (el) => "href" in el.attrs)) {
		if (
			hidden(a) ||
			contentName(a) ||
			ariaName(page, a) ||
			a.attrs.title?.trim()
		)
			continue;
		report(
			{
				id: "link-name",
				title: "Link has no accessible name",
				severity: "medium",
				wcag: ["2.4.4", "4.1.2"],
				understanding: "link-purpose-in-context",
				axe: "link-name",
				remediation:
					"Give the link text content, or an aria-label for icon-only links.",
			},
			a,
			`Link to "${(a.attrs.href ?? "").slice(0, 80)}" has no text, so screen readers announce only "link".`,
		);
	}
	const buttons = [
		...findAll(doc, "button"),
		...findAll(
			doc,
			"*",
			(el) => el.attrs.role === "button" && el.name !== "button",
		),
	];
	for (const b of buttons) {
		if (
			hidden(b) ||
			contentName(b) ||
			ariaName(page, b) ||
			b.attrs.title?.trim()
		)
			continue;
		report(
			{
				id: "button-name",
				title: "Button has no accessible name",
				severity: "high",
				wcag: ["4.1.2"],
				understanding: "name-role-value",
				axe: "button-name",
				remediation: "Give the button visible text or an aria-label.",
			},
			b,
			"A button has no text or label, so its action is not announced.",
		);
	}
	for (const b of findAll(
		doc,
		"input",
		(i) => (i.attrs.type ?? "").toLowerCase() === "button",
	)) {
		if (
			hidden(b) ||
			b.attrs.value?.trim() ||
			ariaName(page, b) ||
			b.attrs.title?.trim()
		)
			continue;
		report(
			{
				id: "button-name",
				title: "Button has no accessible name",
				severity: "high",
				wcag: ["4.1.2"],
				understanding: "name-role-value",
				axe: "input-button-name",
				remediation: "Set a value attribute describing the action.",
			},
			b,
			"An <input type=button> has no value, so its action is not announced.",
		);
	}

	/* ------------------------------- headings ------------------------------ */
	let previous = 0;
	for (const h of findAll(doc, ["h1", "h2", "h3", "h4", "h5", "h6"])) {
		const level = Number(h.name[1]);
		if (previous > 0 && level > previous + 1)
			report(
				{
					id: "heading-order",
					title: "Heading level skipped",
					severity: "low",
					wcag: ["1.3.1"],
					understanding: "info-and-relationships",
					axe: "heading-order",
					remediation:
						"Use heading levels in order (h2 after h1, h3 after h2, …); style with CSS instead of picking levels for size.",
				},
				h,
				`Heading jumps from h${previous} to h${level}, breaking the outline screen-reader users navigate by.`,
			);
		previous = level;
		if (!textOf(h) && !contentName(h) && !ariaName(page, h) && !hidden(h))
			report(
				{
					id: "empty-heading",
					title: "Heading is empty",
					severity: "low",
					wcag: ["1.3.1", "2.4.6"],
					understanding: "headings-and-labels",
					axe: "empty-heading",
					remediation: "Remove the empty heading or give it text.",
				},
				h,
				"An empty heading is announced with no content.",
			);
	}

	/* ------------------------------ duplicate ids --------------------------- */
	const ids = new Map<string, El[]>();
	for (const el of findAll(doc, "*", (e) => !!e.attrs.id)) {
		const id = el.attrs.id as string;
		ids.set(id, [...(ids.get(id) ?? []), el]);
	}
	const referenced = new Set<string>([
		...labelFor.values(),
		...findAll(
			doc,
			"*",
			(e) =>
				!!(
					e.attrs["aria-labelledby"] ||
					e.attrs["aria-describedby"] ||
					e.attrs["aria-controls"]
				),
		).flatMap((e) =>
			`${e.attrs["aria-labelledby"] ?? ""} ${e.attrs["aria-describedby"] ?? ""} ${e.attrs["aria-controls"] ?? ""}`
				.trim()
				.split(/\s+/),
		),
	] as string[]);
	for (const [id, els] of ids) {
		if (els.length < 2) continue;
		const aria = referenced.has(id);
		report(
			{
				id: aria ? "duplicate-id-referenced" : "duplicate-id",
				title: `Duplicate id "${id}"`,
				severity: aria ? "medium" : "low",
				wcag: ["4.1.2"],
				understanding: "name-role-value",
				axe: aria ? "duplicate-id-aria" : "duplicate-id",
				remediation: "Make every id unique within the page.",
			},
			els[1],
			`${els.length} elements share id="${id}"${aria ? ", and a label or ARIA attribute references it, so assistive technology may associate the wrong element" : ""}.`,
		);
	}

	/* ----------------------------- skip link -------------------------------- */
	const body = findFirst(doc, "body") ?? doc;
	const hasMain =
		!!findFirst(doc, "main") ||
		!!findFirst(doc, "*", (e) => e.attrs.role === "main");
	const firstLinks = findAll(body, "a", (a) => "href" in a.attrs).slice(0, 5);
	const hasSkip = firstLinks.some((a) => /^#./.test(a.attrs.href ?? ""));
	const navigation =
		findAll(body, "a", (a) => "href" in a.attrs).length >= 10 ||
		!!findFirst(doc, "nav");
	if (navigation && !hasSkip && !hasMain)
		report(
			{
				id: "bypass-blocks",
				title: "No skip link or main landmark",
				severity: "low",
				wcag: ["2.4.1"],
				understanding: "bypass-blocks",
				axe: "bypass",
				remediation:
					'Add a "Skip to content" link as the first focusable element and wrap the main content in <main>.',
			},
			undefined,
			"Keyboard users must tab through all navigation on every page: there is neither a skip link nor a <main> landmark.",
		);

	/* -------------------------------- tables -------------------------------- */
	for (const table of findAll(doc, "table")) {
		if (isPresentational(table)) continue;
		const rows = findAll(table, "tr");
		if (rows.length < 2) continue;
		if (
			findFirst(table, "th") ||
			findFirst(
				table,
				"*",
				(e) => e.attrs.role === "columnheader" || e.attrs.role === "rowheader",
			)
		)
			continue;
		report(
			{
				id: "table-headers",
				title: "Data table has no header cells",
				severity: "medium",
				wcag: ["1.3.1"],
				understanding: "info-and-relationships",
				axe: "td-has-header",
				remediation:
					'Mark header cells with <th scope="col"> / <th scope="row">, or role="presentation" for layout tables.',
			},
			table,
			`A ${rows.length}-row table has no <th> cells, so screen readers cannot announce which column or row a cell belongs to.`,
		);
	}

	/* -------------------------------- frames -------------------------------- */
	for (const frame of findAll(doc, ["iframe", "frame"])) {
		if (hidden(frame) || frame.attrs.title?.trim() || ariaName(page, frame))
			continue;
		report(
			{
				id: "frame-title",
				title: "Frame has no title",
				severity: "medium",
				wcag: ["4.1.2"],
				understanding: "name-role-value",
				axe: "frame-title",
				remediation: "Add a title attribute describing the frame's content.",
			},
			frame,
			"An iframe has no title, so screen-reader users cannot tell what it contains before entering it.",
		);
	}

	/* ------------------------------- tabindex ------------------------------- */
	for (const el of findAll(doc, "*", (e) => Number(e.attrs.tabindex) > 0)) {
		report(
			{
				id: "positive-tabindex",
				title: "Positive tabindex",
				severity: "low",
				wcag: ["2.4.3"],
				understanding: "focus-order",
				axe: "tabindex",
				remediation:
					'Use tabindex="0" (or -1) and order focus via DOM order instead.',
			},
			el,
			`tabindex="${el.attrs.tabindex}" overrides the natural focus order, which confuses keyboard users.`,
		);
	}

	for (const [rule, n] of counts)
		if (n > MAX_PER_RULE)
			findings.push({
				ruleId: `web.accessibility/${rule}`,
				title: "More occurrences omitted",
				severity: "info",
				category: "accessibility",
				message: `${n - MAX_PER_RULE} further ${rule} issues on this page were not listed individually.`,
				location: { url: page.url, selector: "(truncated)" },
			});

	return findings;
};

/** Static WCAG checks over crawled HTML (no browser). */
export const accessibility = defineAuditor({
	id: "web.accessibility",
	title: "Accessibility (static)",
	description:
		"WCAG checks on the served HTML: alt text, form labels, link/button names, headings, language, title, zoom, duplicate ids, skip links, tables, frames and tabindex. Use --browser for a full axe-core run.",
	categories: ["accessibility"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx) => Effect.map(htmlPages(ctx), (pages) => pages.flatMap(checkPage)),
});
