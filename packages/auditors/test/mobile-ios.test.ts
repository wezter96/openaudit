import { describe, expect, test } from "bun:test";

import { ios } from "../src/mobile/ios";
import { fixture, ruleIds, runAuditor } from "./helpers";
import {
	encodeBplist,
	writeArchive,
	writeTree,
	xmlPlist,
} from "./mobile-plist-encoder";

const findings = (report: Awaited<ReturnType<typeof runAuditor>>) =>
	report.results.flatMap((r) => r.findings);

describe("mobile.ios", () => {
	test("flags insecure Info.plist and entitlements in a source tree", async () => {
		const report = await runAuditor(ios, fixture("mobile", "ios-src"));
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"mobile.ios/ats-arbitrary-loads",
			"mobile.ios/ats-insecure-exception-domain",
			"mobile.ios/ats-weak-tls",
			"mobile.ios/custom-url-scheme",
			"mobile.ios/file-sharing-enabled",
			"mobile.ios/get-task-allow",
			"mobile.ios/usage-description-empty",
			"mobile.ios/usage-description-missing",
		]);
		const all = findings(report);
		const ats = all.find((f) => f.ruleId === "mobile.ios/ats-arbitrary-loads");
		expect(ats?.location).toEqual({ file: "ios/Demo/Info.plist", line: 18 });
		const missing = all.find(
			(f) => f.ruleId === "mobile.ios/usage-description-missing",
		);
		expect(missing?.title).toContain("Location");
		expect(missing?.location).toEqual({
			file: "ios/Demo/LocationService.swift",
			line: 4,
		});
		expect(missing?.confidence).toBe("low");
	});

	test("passes a clean project that declares its purpose strings", async () => {
		const report = await runAuditor(ios, fixture("mobile", "ios-clean"));
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual([]);
	});

	test("reads binary Info.plist and the provisioning profile from an IPA", async () => {
		const info = encodeBplist({
			CFBundleIdentifier: "com.example.demo",
			NSAppTransportSecurity: { NSAllowsArbitraryLoads: true },
			NSMicrophoneUsageDescription: " ",
			CFBundleURLTypes: [{ CFBundleURLSchemes: ["demo"] }],
		});
		const profileXml = xmlPlist({
			Name: "Demo Development",
			Entitlements: {
				"get-task-allow": true,
				"application-identifier": "T.demo",
			},
		});
		const profile = new Uint8Array([
			0x30,
			0x80,
			0x06,
			...new TextEncoder().encode(profileXml),
			0x00,
			0x00,
		]);
		const ipa = await writeArchive("Demo.ipa", {
			"Payload/Demo.app/Info.plist": info,
			"Payload/Demo.app/embedded.mobileprovision": profile,
			"Payload/Demo.app/Demo": new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]),
		});
		const report = await runAuditor(ios, ipa);
		expect(ruleIds(report)).toEqual([
			"mobile.ios/ats-arbitrary-loads",
			"mobile.ios/custom-url-scheme",
			"mobile.ios/get-task-allow",
			"mobile.ios/usage-description-empty",
		]);
		const task = findings(report).find(
			(f) => f.ruleId === "mobile.ios/get-task-allow",
		);
		expect(task?.severity).toBe("high");
		expect(task?.location?.file).toBe(
			"Demo.ipa!Payload/Demo.app/embedded.mobileprovision",
		);
	});

	test("checks Expo ios.infoPlist", async () => {
		const dir = await writeTree({
			"app.json": JSON.stringify(
				{
					expo: {
						name: "demo",
						scheme: "demo",
						ios: {
							bundleIdentifier: "com.example.demo",
							infoPlist: {
								NSAppTransportSecurity: { NSAllowsArbitraryLoads: true },
							},
						},
					},
				},
				null,
				2,
			),
			"ios/Info.plist": xmlPlist({ CFBundleIdentifier: "com.example.demo" }),
		});
		const report = await runAuditor(ios, dir);
		expect(ruleIds(report)).toEqual([
			"mobile.ios/ats-arbitrary-loads",
			"mobile.ios/custom-url-scheme",
		]);
		const ats = findings(report).find(
			(f) => f.ruleId === "mobile.ios/ats-arbitrary-loads",
		);
		expect(ats?.location?.file).toBe("app.json");
		expect(ats?.location?.line).toBeGreaterThan(1);
	});

	test("skips Android artifacts", async () => {
		const apk = await writeArchive("app.apk", { "AndroidManifest.xml": "x" });
		const report = await runAuditor(ios, apk);
		expect(report.results[0]?.status).toBe("skipped");
	});

	test("skips files that are not zip archives", async () => {
		const dir = await writeTree({ "broken.ipa": "not a zip" });
		const report = await runAuditor(ios, `${dir}/broken.ipa`);
		expect(report.results[0]?.status).toBe("skipped");
	});
});
