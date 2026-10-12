import { describe, expect, test } from "bun:test";

import {
	accessibility,
	parseTag,
	scanAccessibility,
	viewportBlocksZoom,
} from "../src/codebase/accessibility";
import { fixture, runAuditor } from "./helpers";

const byFile = (
	findings: ReadonlyArray<{
		ruleId: string;
		location?: { file?: string; line?: number };
	}>,
) => {
	const out: Record<string, string[]> = {};
	for (const f of findings) {
		const file = f.location?.file ?? "";
		out[file] ??= [];
		out[file].push(
			`${f.location?.line}:${f.ruleId.replace("code.accessibility/", "")}`,
		);
	}
	for (const list of Object.values(out))
		list.sort(
			(a, b) =>
				Number.parseInt(a, 10) - Number.parseInt(b, 10) || a.localeCompare(b),
		);
	return out;
};

describe("code.accessibility", () => {
	test("flags JSX, Vue, HTML and CSS issues and leaves accessible code alone", async () => {
		const report = await runAuditor(accessibility, fixture("codebase", "a11y"));
		const findings = report.results.flatMap((r) => r.findings);
		expect(byFile(findings)).toEqual({
			"src/Bad.tsx": [
				"5:img-alt-missing",
				"6:click-on-non-interactive",
				"7:anchor-is-button",
				"8:anchor-is-button",
				"11:positive-tabindex",
				"12:form-label-missing",
				"12:no-autofocus",
				"13:control-name-missing",
				"16:focus-outline-removed",
			],
			"src/Widget.vue": [
				"3:img-alt-missing",
				"5:click-on-non-interactive",
				"6:form-label-missing",
			],
			"public/index.html": [
				"2:html-lang-missing",
				"5:viewport-zoom-disabled",
				"10:form-label-missing",
				"11:control-name-missing",
			],
			"public/styles.css": ["2:focus-outline-removed"],
		});
		const img = findings.find((f) => f.ruleId.endsWith("img-alt-missing"));
		expect(img?.tags).toEqual(["wcag-1.1.1"]);
		expect(img?.references).toEqual([
			"https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html",
		]);
	});

	test("parses JSX attributes with nested braces, spreads and Vue bindings", () => {
		const text = `<img alt={t("a", { b: 1 })} {...rest} :src="x" @click.prevent="go" />`;
		const tag = parseTag(text, 0);
		expect(tag?.name).toBe("img");
		expect(tag?.hasSpread).toBe(true);
		expect(tag?.selfClosing).toBe(true);
		expect([...(tag?.attrs.keys() ?? [])]).toEqual(["alt", "src", "onclick"]);
	});

	test("viewport zoom detection", () => {
		expect(viewportBlocksZoom("width=device-width, maximum-scale=1")).toBe(
			true,
		);
		expect(viewportBlocksZoom("width=device-width, user-scalable=0")).toBe(
			true,
		);
		expect(viewportBlocksZoom("width=device-width, maximum-scale=5")).toBe(
			false,
		);
		const next = scanAccessibility({
			path: "app/layout.ts",
			text: "export const viewport = { maximumScale: 1 };",
		});
		expect(next.map((f) => f.ruleId)).toEqual([
			"code.accessibility/viewport-zoom-disabled",
		]);
	});

	test("does not treat TypeScript generics or comparisons as tags", () => {
		const text = "const a: Array<string> = []; if (x <b && y > 2) {}";
		expect(scanAccessibility({ path: "a.tsx", text })).toEqual([]);
	});
});
