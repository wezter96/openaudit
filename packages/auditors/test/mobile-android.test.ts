import { describe, expect, test } from "bun:test";
import type { Report } from "@openaudit/core";

import { android } from "../src/mobile/android";
import { fixture, ruleIds, runAuditor } from "./helpers";
import {
	type El,
	encodeAxml,
	encodeProtoXml,
	writeZip,
} from "./mobile-encoders";

const findings = (report: Report) => report.results.flatMap((r) => r.findings);

const badManifest: El = {
	name: "manifest",
	attrs: { package: "com.example.bad" },
	children: [
		{ name: "uses-sdk", attrs: { minSdkVersion: 19, targetSdkVersion: 28 } },
		{
			name: "uses-permission",
			attrs: { name: "android.permission.SYSTEM_ALERT_WINDOW" },
		},
		{
			name: "application",
			attrs: { debuggable: true, taskAffinity: "com.evil" },
			children: [
				{
					name: "activity",
					attrs: { name: ".Main", exported: true },
					children: [
						{
							name: "intent-filter",
							children: [
								{
									name: "action",
									attrs: { name: "android.intent.action.MAIN" },
								},
								{
									name: "category",
									attrs: { name: "android.intent.category.LAUNCHER" },
								},
							],
						},
					],
				},
				{ name: "service", attrs: { name: ".Open", exported: true } },
			],
		},
	],
};

const cleanManifest: El = {
	name: "manifest",
	attrs: { package: "com.example.good" },
	children: [
		{ name: "uses-sdk", attrs: { minSdkVersion: 26, targetSdkVersion: 35 } },
		{ name: "uses-permission", attrs: { name: "android.permission.INTERNET" } },
		{
			name: "application",
			attrs: { allowBackup: false, taskAffinity: "" },
			children: [
				{
					name: "activity",
					attrs: { name: ".Main", exported: true },
					children: [
						{
							name: "intent-filter",
							children: [
								{
									name: "action",
									attrs: { name: "android.intent.action.MAIN" },
								},
								{
									name: "category",
									attrs: { name: "android.intent.category.LAUNCHER" },
								},
							],
						},
						{
							name: "intent-filter",
							attrs: { autoVerify: true },
							children: [
								{
									name: "action",
									attrs: { name: "android.intent.action.VIEW" },
								},
								{
									name: "category",
									attrs: { name: "android.intent.category.BROWSABLE" },
								},
								{
									name: "data",
									attrs: { scheme: "https", host: "example.com" },
								},
							],
						},
					],
				},
				{ name: "service", attrs: { name: ".Internal", exported: false } },
			],
		},
	],
};

const userCaConfig: El = {
	name: "network-security-config",
	children: [
		{
			name: "domain-config",
			attrs: { cleartextTrafficPermitted: "true" },
			children: [{ name: "domain", text: "legacy.example.com" }],
		},
	],
};

describe("mobile.android", () => {
	test("audits a source tree (manifests, network config, gradle SDK levels)", async () => {
		const report = await runAuditor(android, fixture("mobile", "android-src"));
		expect(report.target.kinds).toContain("mobile");
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"mobile.android/allow-backup",
			"mobile.android/app-link-unverified",
			"mobile.android/cleartext-traffic",
			"mobile.android/custom-scheme-deep-link",
			"mobile.android/dangerous-permission",
			"mobile.android/dangerous-permission",
			"mobile.android/debuggable",
			"mobile.android/exported-component",
			"mobile.android/exported-component",
			"mobile.android/exported-component",
			"mobile.android/exported-component",
			"mobile.android/exported-undeclared",
			"mobile.android/min-sdk-low",
			"mobile.android/nsc-cleartext-permitted",
			"mobile.android/nsc-user-certificates",
			"mobile.android/target-sdk-low",
			"mobile.android/task-hijacking",
		]);
		const all = findings(report);
		const debuggable = all.find(
			(f) => f.ruleId === "mobile.android/debuggable",
		);
		expect(debuggable?.location).toEqual({
			file: "app/src/main/AndroidManifest.xml",
			line: 6,
		});
		// Debug source sets are ignored; library manifests get component checks only.
		expect(all.some((f) => f.location?.file?.includes("src/debug"))).toBe(
			false,
		);
		expect(
			all
				.filter((f) => f.ruleId === "mobile.android/exported-component")
				.map((f) => [f.message.split(" ")[1], f.severity])
				.sort(),
		).toEqual([
			[".DataProvider", "high"],
			[".LinkActivity", "low"],
			[".PushReceiver", "medium"],
			["com.example.lib.LibService", "medium"],
		]);
		const target = all.find(
			(f) => f.ruleId === "mobile.android/target-sdk-low",
		);
		expect(target?.location).toEqual({ file: "app/build.gradle", line: 12 });
		const userCa = all.find(
			(f) => f.ruleId === "mobile.android/nsc-user-certificates",
		);
		expect(userCa?.location?.line).toBe(6);
	});

	test("decodes the binary manifest and network config of an APK", async () => {
		const apk = writeZip("app.apk", {
			"AndroidManifest.xml": encodeAxml(badManifest),
			// Obfuscated resource name: identified by its root element.
			"res/a1.xml": encodeAxml(userCaConfig, { utf8: true }),
			"res/layout/main.xml": encodeAxml({ name: "LinearLayout" }),
			"classes.dex": new Uint8Array([0x64, 0x65, 0x78]),
		});
		const report = await runAuditor(android, apk);
		expect(report.target.kinds).toEqual(["mobile"]);
		expect(ruleIds(report)).toEqual([
			"mobile.android/allow-backup",
			"mobile.android/dangerous-permission",
			"mobile.android/debuggable",
			"mobile.android/exported-component",
			"mobile.android/min-sdk-low",
			"mobile.android/nsc-cleartext-permitted",
			"mobile.android/target-sdk-low",
			"mobile.android/task-hijacking",
		]);
		const all = findings(report);
		const debuggable = all.find(
			(f) => f.ruleId === "mobile.android/debuggable",
		);
		expect(debuggable?.location?.file).toBe("app.apk!/AndroidManifest.xml");
		expect(debuggable?.evidence).toContain('debuggable="true"');
		expect(
			all.find((f) => f.ruleId === "mobile.android/nsc-cleartext-permitted")
				?.message,
		).toContain("legacy.example.com");
		// Cleartext default only applies when no network config exists.
		expect(ruleIds(report)).not.toContain("mobile.android/cleartext-traffic");
	});

	test("a hardened APK passes", async () => {
		const apk = writeZip("good.apk", {
			"AndroidManifest.xml": encodeAxml(cleanManifest),
		});
		const report = await runAuditor(android, apk);
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual([]);
	});

	test("decodes protobuf manifests inside an AAB", async () => {
		const aab = writeZip("app.aab", {
			"base/manifest/AndroidManifest.xml": encodeProtoXml(badManifest),
		});
		const report = await runAuditor(android, aab);
		expect(ruleIds(report)).toContain("mobile.android/debuggable");
		expect(ruleIds(report)).toContain("mobile.android/target-sdk-low");
	});

	test("reports an undecodable manifest as info", async () => {
		const aab = writeZip("broken.aab", {
			"base/manifest/AndroidManifest.xml": new Uint8Array([0x0a, 0xff, 0x01]),
		});
		const report = await runAuditor(android, aab);
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual(["mobile.android/manifest-undecodable"]);
	});

	test("honours a custom minimum target SDK setting", async () => {
		const apk = writeZip("good.apk", {
			"AndroidManifest.xml": encodeAxml(cleanManifest),
		});
		const report = await runAuditor(android, apk, {
			settings: { "mobile.android": { minTargetSdk: 36 } },
		});
		expect(ruleIds(report)).toEqual(["mobile.android/target-sdk-low"]);
	});

	test("skips iOS artifacts", async () => {
		const ipa = writeZip("app.ipa", {
			"Payload/App.app/Info.plist": new TextEncoder().encode("<plist/>"),
		});
		const report = await runAuditor(android, ipa);
		expect(report.results[0]?.status).toBe("skipped");
	});
});
