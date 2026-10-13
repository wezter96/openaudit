import { describe, expect, test } from "bun:test";
import { mobileAccessibility } from "../src/mobile/accessibility";
import {
	decodeAxml,
	decodeDimension,
	parseDimension,
} from "../src/mobile/axml";
import { ruleIds, runAuditor } from "./helpers";
import {
	complexDimension,
	encodeLayout,
	type LayoutEl,
} from "./mobile-layout-encoder";
import { encodeBplist, writeArchive, writeTree } from "./mobile-plist-encoder";

const dp = (dim: number) => ({ dim, unit: "dp" as const });
const sp = (dim: number) => ({ dim, unit: "sp" as const });

const layout: LayoutEl = {
	name: "LinearLayout",
	attrs: { layout_width: -1, layout_height: -1 },
	children: [
		// Missing contentDescription.
		{
			name: "ImageView",
			attrs: { src: { ref: 0x7f080001 }, layout_width: dp(64) },
		},
		// Labelled, decorative, hidden: all fine.
		{ name: "ImageView", attrs: { contentDescription: "Logo" } },
		{ name: "ImageView", attrs: { contentDescription: { ref: 0 } } },
		{ name: "ImageView", attrs: { importantForAccessibility: { hex: 2 } } },
		{
			name: "com.google.android.material.floatingactionbutton.FloatingActionButton",
			attrs: { id: { ref: 0x7f0b0001 } },
		},
		// Clickable and small.
		{
			name: "ImageButton",
			attrs: {
				contentDescription: "Close",
				layout_width: dp(32),
				layout_height: dp(32),
			},
		},
		{
			name: "View",
			attrs: { clickable: true, layout_width: dp(48), layout_height: dp(24) },
		},
		// Small but enlarged through minHeight / not clickable: fine.
		{
			name: "View",
			attrs: {
				clickable: true,
				layout_height: dp(24),
				minHeight: dp(48),
				layout_width: dp(48),
			},
		},
		{ name: "View", attrs: { layout_width: dp(10), layout_height: dp(10) } },
		// Text sizes.
		{ name: "TextView", attrs: { textSize: sp(14) } },
		{ name: "TextView", attrs: { textSize: dp(14) } },
		{ name: "TextView", attrs: { textSize: { dim: 12, unit: "px" } } },
		// Inputs.
		{ name: "EditText", attrs: { id: { ref: 0x7f0b0010 } } },
		{ name: "EditText", attrs: { hint: "Email" } },
		{ name: "EditText", attrs: { id: { ref: 0x7f0b0011 } } },
		{
			name: "TextView",
			attrs: { text: "Name", labelFor: { ref: 0x7f0b0011 } },
		},
		{
			name: "com.google.android.material.textfield.TextInputLayout",
			attrs: { hint: "Phone" },
			children: [
				{ name: "com.google.android.material.textfield.TextInputEditText" },
			],
		},
	],
};

const clean: LayoutEl = {
	name: "FrameLayout",
	children: [
		{ name: "ImageView", attrs: { contentDescription: "Photo" } },
		{ name: "TextView", attrs: { textSize: sp(16) } },
		{ name: "EditText", attrs: { hint: "Search" } },
	],
};

const findings = (report: Awaited<ReturnType<typeof runAuditor>>) =>
	report.results.flatMap((r) => r.findings);

describe("axml dimensions", () => {
	test("decodes complex units", () => {
		expect(decodeDimension(complexDimension(48, "dp"))).toBe("48dp");
		expect(decodeDimension(complexDimension(14, "sp"))).toBe("14sp");
		expect(decodeDimension(complexDimension(-3, "px"))).toBe("-3px");
		// 0.5dp in 16p7 radix: mantissa 64 << 8 | radix 1 << 4 | dp.
		expect(decodeDimension(((64 << 8) | (1 << 4) | 1) >>> 0)).toBe("0.5dp");
		expect(decodeDimension(0xf)).toBeUndefined();
	});

	test("parses dimension strings", () => {
		expect(parseDimension("48dp")).toEqual({ value: 48, unit: "dp" });
		expect(parseDimension("14.5sp")).toEqual({ value: 14.5, unit: "sp" });
		expect(parseDimension("12dip")).toEqual({ value: 12, unit: "dp" });
		expect(parseDimension("match_parent")).toBeUndefined();
		expect(parseDimension("@dimen/x")).toBeUndefined();
	});

	test("only typed when asked, so default decoding is unchanged", () => {
		const bytes = encodeLayout({
			name: "View",
			attrs: { layout_width: dp(48) },
		});
		expect(decodeAxml(bytes)?.attrs.layout_width).not.toBe("48dp");
		expect(decodeAxml(bytes, { dimensions: true })?.attrs.layout_width).toBe(
			"48dp",
		);
	});
});

describe("mobile.accessibility", () => {
	test("flags Android layout problems in an APK", async () => {
		const apk = await writeArchive("app.apk", {
			"res/layout/activity_main.xml": encodeLayout(layout),
			"res/layout/activity_ok.xml": encodeLayout(clean),
			// Library layouts are not the app's responsibility.
			"res/layout/abc_screen_toolbar.xml": encodeLayout(layout),
		});
		const report = await runAuditor(mobileAccessibility, apk);
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"mobile.accessibility/edittext-missing-label",
			"mobile.accessibility/image-missing-content-description",
			"mobile.accessibility/text-size-not-sp",
			"mobile.accessibility/touch-target-too-small",
		]);
		const all = findings(report);
		const image = all.find((f) =>
			f.ruleId.endsWith("/image-missing-content-description"),
		);
		expect(image?.severity).toBe("medium");
		expect(image?.tags).toContain("wcag-1.1.1");
		expect(image?.message).toContain("2 image views");
		expect(image?.location?.file).toBe(
			`${apk}!/res/layout/activity_main.xml`.replace(apk, "app.apk"),
		);
		const target = all.find((f) =>
			f.ruleId.endsWith("/touch-target-too-small"),
		);
		expect(target?.severity).toBe("low");
		expect(target?.confidence).toBe("low");
		expect(target?.tags).toContain("wcag-2.5.8");
		expect(target?.message).toContain("2 clickable views");
		const text = all.find((f) => f.ruleId.endsWith("/text-size-not-sp"));
		expect(text?.message).toContain("2 views");
		expect(text?.tags).toContain("wcag-1.4.4");
		const edit = all.find((f) => f.ruleId.endsWith("/edittext-missing-label"));
		expect(edit?.message).toContain("1 input field");
		expect(edit?.tags).toEqual(["android", "wcag-1.3.1", "wcag-3.3.2"]);
		for (const f of all) {
			expect(f.remediation).toBeTruthy();
			expect(f.evidence).toBeTruthy();
			expect(f.category).toBe("accessibility");
		}
		expect(all.every((f) => !f.location?.file?.includes("abc_screen"))).toBe(
			true,
		);
	});

	test("passes a clean layout", async () => {
		const apk = await writeArchive("clean.apk", {
			"res/layout/main.xml": encodeLayout(clean),
		});
		const report = await runAuditor(mobileAccessibility, apk);
		expect(report.results[0]?.status).toBe("passed");
	});

	test("reads source layouts (text XML with dimensions and lint ignores)", async () => {
		const dir = await writeTree({
			"app/src/main/AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b"/>`,
			"app/src/main/res/layout/main.xml": `<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">
    <ImageView android:src="@drawable/a" />
    <ImageView android:src="@drawable/b" tools:ignore="ContentDescription" />
    <ImageButton android:layout_width="40dp" android:layout_height="48dp" android:contentDescription="@string/x" />
    <TextView android:textSize="14dp" />
    <EditText android:id="@+id/name" />
    <TextView android:labelFor="@id/name" />
</LinearLayout>
`,
			"app/src/test/res/layout/skipped.xml": `<ImageView xmlns:android="http://schemas.android.com/apk/res/android"/>`,
		});
		const report = await runAuditor(mobileAccessibility, dir);
		expect(ruleIds(report)).toEqual([
			"mobile.accessibility/image-missing-content-description",
			"mobile.accessibility/text-size-not-sp",
			"mobile.accessibility/touch-target-too-small",
		]);
		const image = findings(report).find((f) =>
			f.ruleId.endsWith("/image-missing-content-description"),
		);
		expect(image?.location).toEqual({
			file: "app/src/main/res/layout/main.xml",
			line: 4,
		});
	});

	test("reads orientation and multitasking hints from an IPA", async () => {
		const ipa = await writeArchive("app.ipa", {
			"Payload/Demo.app/Info.plist": encodeBplist({
				CFBundleIdentifier: "com.example.demo",
				UIRequiresFullScreen: true,
				UISupportedInterfaceOrientations: ["UIInterfaceOrientationPortrait"],
			}),
		});
		const report = await runAuditor(mobileAccessibility, ipa);
		expect(ruleIds(report)).toEqual([
			"mobile.accessibility/ios-orientation-locked",
			"mobile.accessibility/ios-requires-fullscreen",
		]);
		expect(findings(report).every((f) => f.confidence === "low")).toBe(true);
		expect(findings(report)[0]?.tags).toContain("wcag-1.3.4");
	});

	test("skips artifacts without layouts", async () => {
		const apk = await writeArchive("empty.apk", {
			"classes.dex": new Uint8Array(8),
		});
		const report = await runAuditor(mobileAccessibility, apk);
		expect(report.results[0]?.status).toBe("skipped");
	});
});
