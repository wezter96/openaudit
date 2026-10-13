import {
	defineAuditor,
	type FindingInput,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	type Dimension,
	parseAndroidXml,
	parseDimension,
	parseXmlText,
	renderTag,
	type XmlElement,
} from "./axml";
import { asDict, isTrue, type PlistDict, parsePlist } from "./plist";
import { loadMobileTarget } from "./shared";

/**
 * Accessibility checks for mobile apps.
 *
 * Android: compiled (AXML/proto) or source layouts under `res/layout*`.
 * iOS: Info.plist hints only. Storyboards and nibs are compiled, so view-level
 * checks (missing accessibilityLabel, Dynamic Type) are not attempted.
 */

const WCAG = "https://www.w3.org/WAI/WCAG22/Understanding";
const ANDROID_A11Y =
	"https://developer.android.com/guide/topics/ui/accessibility";
/** Per rule and layout file, so one templated layout does not flood the report. */
const MAX_ELEMENTS_LISTED = 5;
/** Layouts decoded per artifact; larger layouts are not accessibility-relevant. */
const MAX_LAYOUTS = 1000;
const MAX_LAYOUT_BYTES = 256 * 1024;
/** Material's recommended minimum touch target. */
const MIN_TARGET_DP = 48;

/** Layout file names that belong to AndroidX/Material/Play Services, not the app. */
const LIBRARY_LAYOUT =
	/^(abc_|mtrl_|m3_|design_|material_|notification_|browser_actions_|custom_dialog|select_dialog_|support_simple_spinner_|ime_base_split_test_activity|expand_button|preference|exo_|androidx_|mr_|text_view_with_line_height_from_|image_frame|test_)/;

const LAYOUT_PATH_RE = /^(?:[^/]+\/)?res\/layout[^/]*\/([^/]+)\.xml$/;
const SOURCE_LAYOUT_RE = /(^|\/)res\/layout[^/]*\/[^/]+\.xml$/;
const NON_RELEASE_SOURCE_SET = /(^|\/)src\/(test|androidTest)[^/]*\//;

interface LayoutDoc {
	/** Location used in findings (`app.apk!/res/layout/main.xml` for artifacts). */
	readonly file: string;
	readonly root: XmlElement;
}

interface Hit {
	readonly element: XmlElement;
}

interface RuleSpec {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly confidence: "high" | "medium" | "low";
	readonly wcag: ReadonlyArray<string>;
	readonly understanding: string;
	readonly message: (count: number, first: XmlElement) => string;
	readonly remediation: string;
}

const RULES = {
	imageNoLabel: {
		id: "image-missing-content-description",
		title: "Image without a content description",
		severity: "medium",
		confidence: "medium",
		wcag: ["1.1.1"],
		understanding: `${WCAG}/non-text-content.html`,
		message: (n, el) =>
			`${n} image view${n === 1 ? "" : "s"} (first: ${el.name}) ${n === 1 ? "has" : "have"} no android:contentDescription and ${n === 1 ? "is" : "are"} not marked importantForAccessibility="no". Screen readers announce them as "unlabelled" or skip them, so their meaning is lost.`,
		remediation:
			'Add android:contentDescription with a short description of the image or its action. For purely decorative images set android:importantForAccessibility="no" (or contentDescription="@null").',
	},
	smallTarget: {
		id: "touch-target-too-small",
		title: "Touch target smaller than 48dp",
		severity: "low",
		confidence: "low",
		wcag: ["2.5.8"],
		understanding: `${WCAG}/target-size-minimum.html`,
		message: (n, el) =>
			`${n} clickable view${n === 1 ? "" : "s"} (first: ${el.name}) declare${n === 1 ? "s" : ""} a layout_width or layout_height below ${MIN_TARGET_DP}dp. Small targets are hard to hit for users with motor impairments. This is a heuristic: padding, minWidth/minHeight or a TouchDelegate set in code can enlarge the real touch area.`,
		remediation: `Make the touch target at least ${MIN_TARGET_DP}dp x ${MIN_TARGET_DP}dp, using android:minWidth/minHeight, padding, or a TouchDelegate when the visual must stay small.`,
	},
	textSizeUnit: {
		id: "text-size-not-sp",
		title: "Text size not in sp",
		severity: "low",
		confidence: "high",
		wcag: ["1.4.4"],
		understanding: `${WCAG}/resize-text.html`,
		message: (n, el) =>
			`${n} view${n === 1 ? "" : "s"} (first: ${el.name}) set${n === 1 ? "s" : ""} android:textSize in ${n === 1 ? "a unit" : "units"} other than sp (${el.attrs.textSize}). Only sp follows the user's font-size setting, so these texts cannot be enlarged.`,
		remediation:
			"Express text sizes in sp (or use a TextAppearance/style that does) so they scale with the system font size.",
	},
	editNoLabel: {
		id: "edittext-missing-label",
		title: "Input field without a label",
		severity: "low",
		confidence: "medium",
		wcag: ["1.3.1", "3.3.2"],
		understanding: `${WCAG}/labels-or-instructions.html`,
		message: (n, el) =>
			`${n} input field${n === 1 ? "" : "s"} (first: ${el.name}) ha${n === 1 ? "s" : "ve"} no android:hint, android:labelFor target, contentDescription or TextInputLayout hint. Screen readers cannot tell users what to enter.`,
		remediation:
			"Add android:hint, point a visible TextView at the field with android:labelFor, or wrap it in a TextInputLayout with a hint.",
	},
} satisfies Record<string, RuleSpec>;

type RuleKey = keyof typeof RULES;

/* ------------------------------ layout checks ------------------------------ */

const simpleName = (el: XmlElement) => el.name.split(".").pop() ?? el.name;

const IMAGE_VIEW = /(ImageView|ImageButton|FloatingActionButton)$/;
const EDIT_TEXT =
	/(EditText|AutoCompleteTextView|MaterialAutoCompleteTextView)$/;

const walk = (
	el: XmlElement,
	visit: (e: XmlElement, parents: XmlElement[]) => void,
) => {
	const stack: XmlElement[] = [];
	const go = (e: XmlElement) => {
		visit(e, stack);
		stack.push(e);
		for (const c of e.children) go(c);
		stack.pop();
	};
	go(el);
};

/** `tools:ignore="ContentDescription,LabelFor"` suppression (source layouts). */
const ignores = (el: XmlElement, lintId: string) =>
	(el.attrs["tools:ignore"] ?? "")
		.split(",")
		.some((s) => s.trim() === lintId || s.trim() === "all");

/** True when `importantForAccessibility` resolves to no / noHideDescendants. */
const hiddenFromA11y = (value: string | undefined) =>
	value !== undefined &&
	/^(no|noHideDescendants|0x2|0x4|2|4)$/.test(value.trim());

const normaliseId = (ref: string | undefined) =>
	ref?.trim().replace(/^@\+/, "@");

const toDp = (d: Dimension): number | undefined => {
	switch (d.unit) {
		case "dp":
			return d.value;
		case "px":
			// Density is unknown; at density >= 1 a px size is at most that many dp.
			return d.value;
		case "pt":
			return (d.value * 160) / 72;
		case "in":
			return d.value * 160;
		case "mm":
			return (d.value * 160) / 25.4;
		default:
			return undefined;
	}
};

const belowMinimum = (size: string | undefined, min: string | undefined) => {
	const dim = parseDimension(size);
	if (!dim) return false;
	const dp = toDp(dim);
	if (dp === undefined || dp >= MIN_TARGET_DP) return false;
	const minDp = (() => {
		const m = parseDimension(min);
		return m ? toDp(m) : undefined;
	})();
	return minDp === undefined || minDp < MIN_TARGET_DP;
};

const isClickable = (el: XmlElement) =>
	el.attrs.clickable === "true" ||
	el.attrs.onClick !== undefined ||
	/ImageButton$/.test(el.name);

export const checkLayout = (root: XmlElement): Map<RuleKey, Hit[]> => {
	const hits = new Map<RuleKey, Hit[]>();
	const add = (key: RuleKey, element: XmlElement) => {
		const list = hits.get(key) ?? [];
		list.push({ element });
		hits.set(key, list);
	};
	// Ids that some view declares as the label of another (android:labelFor).
	const labelled = new Set<string>();
	walk(root, (el) => {
		const target = normaliseId(el.attrs.labelFor);
		if (target) labelled.add(target);
	});
	walk(root, (el, parents) => {
		if (
			IMAGE_VIEW.test(el.name) &&
			el.attrs.contentDescription === undefined &&
			!hiddenFromA11y(el.attrs.importantForAccessibility) &&
			!ignores(el, "ContentDescription") &&
			!parents.some((p) => hiddenFromA11y(p.attrs.importantForAccessibility))
		)
			add("imageNoLabel", el);

		if (
			isClickable(el) &&
			(belowMinimum(el.attrs.layout_width, el.attrs.minWidth) ||
				belowMinimum(el.attrs.layout_height, el.attrs.minHeight)) &&
			!ignores(el, "TouchTargetSizeCheck")
		)
			add("smallTarget", el);

		const size = parseDimension(el.attrs.textSize);
		if (size && size.unit !== "sp" && !ignores(el, "SpUsage"))
			add("textSizeUnit", el);

		if (EDIT_TEXT.test(simpleName(el))) {
			const id = normaliseId(el.attrs.id);
			const wrapped = parents.some(
				(p) =>
					simpleName(p) === "TextInputLayout" && p.attrs.hint !== undefined,
			);
			if (
				el.attrs.hint === undefined &&
				el.attrs.contentDescription === undefined &&
				!(id && labelled.has(id)) &&
				!wrapped &&
				!ignores(el, "LabelFor") &&
				!hiddenFromA11y(el.attrs.importantForAccessibility)
			)
				add("editNoLabel", el);
		}
	});
	return hits;
};

const layoutFindings = (doc: LayoutDoc): FindingInput[] => {
	const out: FindingInput[] = [];
	for (const [key, hits] of checkLayout(doc.root)) {
		const rule = RULES[key];
		const first = hits[0]?.element;
		if (!first) continue;
		const listed = hits
			.slice(0, MAX_ELEMENTS_LISTED)
			.map((h) => renderTag(h.element, 120))
			.join("\n");
		out.push({
			ruleId: `mobile.accessibility/${rule.id}`,
			title: rule.title,
			severity: rule.severity,
			category: "accessibility",
			message: rule.message(hits.length, first),
			location: { file: doc.file, ...(first.line ? { line: first.line } : {}) },
			evidence:
				hits.length > MAX_ELEMENTS_LISTED
					? `${listed}\n… and ${hits.length - MAX_ELEMENTS_LISTED} more`
					: listed,
			remediation: rule.remediation,
			references: [rule.understanding, ANDROID_A11Y],
			confidence: rule.confidence,
			tags: ["android", ...rule.wcag.map((sc) => `wcag-${sc}`)],
		});
	}
	return out;
};

/* ------------------------------- iOS Info.plist ------------------------------ */

const PORTRAIT = /Portrait/;
const LANDSCAPE = /Landscape/;

const checkInfoPlist = (file: string, info: PlistDict): FindingInput[] => {
	const out: FindingInput[] = [];
	if (isTrue(info.UIRequiresFullScreen))
		out.push({
			ruleId: "mobile.accessibility/ios-requires-fullscreen",
			title: "App opts out of iPad multitasking",
			severity: "low",
			category: "accessibility",
			message:
				"UIRequiresFullScreen is true, so the app cannot run in Split View, Slide Over or resizable windows. Users who rely on window management, zoom or an external assistive layout lose that flexibility, and Apple has deprecated the key.",
			location: { file },
			evidence: "UIRequiresFullScreen = true",
			remediation:
				"Remove UIRequiresFullScreen and support adaptive layouts (size classes, Auto Layout) so the UI reflows in any window size.",
			references: [`${WCAG}/orientation.html`],
			confidence: "low",
			tags: ["ios", "wcag-1.3.4"],
		});
	const orientations = Array.isArray(info.UISupportedInterfaceOrientations)
		? info.UISupportedInterfaceOrientations.filter(
				(v): v is string => typeof v === "string",
			)
		: [];
	if (
		orientations.length > 0 &&
		(orientations.every((o) => PORTRAIT.test(o)) ||
			orientations.every((o) => LANDSCAPE.test(o)))
	)
		out.push({
			ruleId: "mobile.accessibility/ios-orientation-locked",
			title: "App is locked to a single orientation",
			severity: "low",
			category: "accessibility",
			message: `UISupportedInterfaceOrientations only lists ${orientations.join(", ")}. Users who mount their device in a fixed orientation (for example on a wheelchair) cannot use the app unless the restriction is essential.`,
			location: { file },
			evidence: `UISupportedInterfaceOrientations = ${orientations.join(", ")}`,
			remediation:
				"Support both portrait and landscape unless a single orientation is essential to the app's function.",
			references: [`${WCAG}/orientation.html`],
			confidence: "low",
			tags: ["ios", "wcag-1.3.4"],
		});
	return out;
};

/* --------------------------------- loading --------------------------------- */

const readPlist = (bytes: Uint8Array) => {
	try {
		return asDict(parsePlist(bytes));
	} catch {
		return undefined;
	}
};

const sourceLayouts = (
	ws: Workspace,
	files: ReadonlyArray<string>,
): Effect.Effect<LayoutDoc[]> =>
	Effect.gen(function* () {
		const docs: LayoutDoc[] = [];
		const wanted = files
			.filter(
				(f) => SOURCE_LAYOUT_RE.test(f) && !NON_RELEASE_SOURCE_SET.test(f),
			)
			.filter((f) => !/(^|\/)(build|Pods|node_modules)\//.test(f))
			.slice(0, MAX_LAYOUTS);
		for (const file of wanted) {
			const size = yield* ws.size(file).pipe(Effect.orElseSucceed(() => 0));
			if (size > MAX_LAYOUT_BYTES) continue;
			const text = yield* ws
				.readText(file)
				.pipe(Effect.orElseSucceed(() => ""));
			const root = parseXmlText(text);
			if (root) docs.push({ file, root });
		}
		return docs;
	});

export const mobileAccessibility = defineAuditor({
	id: "mobile.accessibility",
	title: "Mobile accessibility",
	description:
		"Checks Android layouts (compiled or source) for images without content descriptions, touch targets under 48dp, text sizes not in sp and unlabelled input fields, and iOS Info.plist for orientation and multitasking restrictions. iOS storyboards and nibs are compiled and not analysed. Findings are tagged with WCAG success criteria.",
	categories: ["accessibility"],
	targets: ["mobile"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const target = yield* loadMobileTarget(ctx);
			const findings: FindingInput[] = [];
			let inspected = 0;

			if (target.kind === "artifact") {
				if (target.type === "ipa") {
					const entries = target.extract(
						(name, info) =>
							/^Payload\/[^/]+\.app\/Info\.plist$/.test(name) &&
							info.originalSize < MAX_LAYOUT_BYTES,
					);
					for (const [name, bytes] of Object.entries(entries)) {
						const info = readPlist(bytes);
						if (!info) continue;
						inspected++;
						findings.push(...checkInfoPlist(`${target.file}!/${name}`, info));
					}
				} else {
					const entries = target.extract((name, info) => {
						const m = LAYOUT_PATH_RE.exec(name);
						return (
							m !== null &&
							!LIBRARY_LAYOUT.test(m[1] ?? "") &&
							info.originalSize < MAX_LAYOUT_BYTES
						);
					});
					for (const [name, bytes] of Object.entries(entries).slice(
						0,
						MAX_LAYOUTS,
					)) {
						const root = parseAndroidXml(bytes, { dimensions: true });
						if (!root) continue;
						inspected++;
						findings.push(
							...layoutFindings({ file: `${target.file}!/${name}`, root }),
						);
					}
				}
			} else {
				const docs = yield* sourceLayouts(target.ws, target.files);
				inspected += docs.length;
				for (const doc of docs) findings.push(...layoutFindings(doc));
				for (const file of target.files.filter(
					(f) =>
						/(^|\/)Info\.plist$/.test(f) &&
						!/(^|\/)(Pods|build|node_modules)\//.test(f),
				)) {
					const bytes = yield* target.ws
						.readBytes(file)
						.pipe(Effect.orElseSucceed(() => undefined));
					const info = bytes && readPlist(bytes);
					if (!info) continue;
					inspected++;
					findings.push(...checkInfoPlist(file, info));
				}
			}

			if (inspected === 0)
				return yield* skip(
					"No Android layouts (res/layout*/*.xml) or iOS Info.plist found",
				);
			return findings;
		}),
});
