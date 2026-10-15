import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
	Exec,
	Http,
	type HttpRequest,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import {
	androidComponents,
	iosComponents,
	mobileDependencies,
	parseClientProperties,
	parsePomProperties,
	parseVersionFile,
} from "../src/mobile/dependencies";
import { fixture, runAuditor } from "./helpers";
import { encodeBplist, writeArchive, writeTree } from "./mobile-plist-encoder";
import { findingsOf, findingWith, firstResult, must } from "./must";

// OSV responses recorded from api.osv.dev (querybatch and /vulns/<id>) for
// gson 2.8.0, okhttp 3.8.0 and androidx.core 1.12.0. The APK around them is
// synthetic: only the marker files are modelled on the Gradle conventions.
const recorded = (name: string): unknown =>
	JSON.parse(
		readFileSync(fixture("mobile-dependencies", `${name}.json`), "utf8"),
	);
const batch = recorded("osv-querybatch") as {
	results: Array<Record<string, unknown>>;
};
const BATCH_ORDER = [
	"com.google.code.gson:gson",
	"com.squareup.okhttp3:okhttp",
	"androidx.core:core",
];
const VULNS: Record<string, unknown> = {
	"GHSA-4jrv-ppp4-jm57": recorded("osv-GHSA-4jrv-ppp4-jm57"),
	"GHSA-3cqm-mf7h-prrj": recorded("osv-GHSA-3cqm-mf7h-prrj"),
};

const response = (url: string, status: number, body: unknown) => ({
	url,
	status,
	headers: new Headers(),
	cookies: [],
	body: JSON.stringify(body),
	bytes: 0,
	redirected: false,
	ttfbMs: 0,
	totalMs: 0,
});

const runWithOsv = (
	target: string,
	calls: Array<{ url: string; init?: HttpRequest }> = [],
	options: { offline?: boolean } = {},
): Promise<Report> => {
	const http = Layer.succeed(Http, {
		request: (url: string, init?: HttpRequest) =>
			Effect.sync(() => {
				calls.push({ url, init });
				if (url.endsWith("/querybatch")) {
					const { queries } = JSON.parse(init?.body ?? "{}") as {
						queries: Array<{ package: { name: string; ecosystem: string } }>;
					};
					return response(url, 200, {
						results: queries.map((q) => {
							expect(q.package.ecosystem).toBe("Maven");
							const i = BATCH_ORDER.indexOf(q.package.name);
							return i === -1 ? {} : (batch.results[i] ?? {});
						}),
					});
				}
				const id = decodeURIComponent(url.split("/").pop() ?? "");
				const vuln = VULNS[id];
				return vuln ? response(url, 200, vuln) : response(url, 404, {});
			}),
	});
	return Effect.runPromise(
		runAudit({
			target,
			auditors: [mobileDependencies],
			options,
			selection: { only: [mobileDependencies.id] },
		}).pipe(Effect.provide(Layer.mergeAll(Workspaces.layer, http, Exec.layer))),
	);
};

describe("marker parsers", () => {
	test("META-INF version files map file names to Maven coordinates", () => {
		expect(
			parseVersionFile("META-INF/androidx.core_core.version", "1.12.0\n"),
		).toMatchObject({
			group: "androidx.core",
			name: "core",
			version: "1.12.0",
		});
		expect(
			parseVersionFile(
				"META-INF/com.google.android.material_material.version",
				"1.11.0",
			),
		).toMatchObject({ group: "com.google.android.material", name: "material" });
		expect(
			parseVersionFile(
				"base/root/META-INF/androidx.appcompat_appcompat-resources.version",
				"1.6.1",
			),
		).toMatchObject({
			group: "androidx.appcompat",
			name: "appcompat-resources",
		});
		expect(parseVersionFile("META-INF/foo.version", "1.0")).toBeUndefined();
		expect(
			parseVersionFile("META-INF/a.b_c.version", "latest"),
		).toBeUndefined();
		expect(parseVersionFile("META-INF/a.b_c.version", "")).toBeUndefined();
	});

	test("pom.properties", () => {
		const text =
			"#Generated\nversion=2.8.0\ngroupId=com.google.code.gson\nartifactId=gson\n";
		expect(
			parsePomProperties(
				"META-INF/maven/com.google.code.gson/gson/pom.properties",
				text,
			),
		).toMatchObject({
			group: "com.google.code.gson",
			name: "gson",
			version: "2.8.0",
		});
		// Falls back to the path when ids are missing.
		expect(
			parsePomProperties(
				"META-INF/maven/org.x/y/pom.properties",
				"version=1.0.0",
			),
		).toMatchObject({ group: "org.x", name: "y" });
		expect(
			parsePomProperties("META-INF/maven/org.x/y/pom.properties", ""),
		).toBeUndefined();
	});

	test("Firebase and Play Services client properties", () => {
		expect(
			parseClientProperties(
				"firebase-common.properties",
				"version=20.3.2\nclient=firebase-common\nfirebase-common_client=20.3.2\n",
			),
		).toMatchObject({
			group: "com.google.firebase",
			name: "firebase-common",
			version: "20.3.2",
		});
		expect(
			parseClientProperties(
				"play-services-base.properties",
				"client=play-services-base\nplay-services-base_client=18.2.0\n",
			),
		).toMatchObject({
			group: "com.google.android.gms",
			name: "play-services-base",
			version: "18.2.0",
		});
		expect(
			parseClientProperties("other.properties", "version=1.0"),
		).toBeUndefined();
	});

	test("components are deduplicated by coordinate and version", () => {
		const enc = (s: string) => new TextEncoder().encode(s);
		const components = androidComponents({
			"META-INF/androidx.core_core.version": enc("1.12.0"),
			"META-INF/maven/androidx.core/core/pom.properties": enc("version=1.12.0"),
		});
		expect(components).toHaveLength(1);
	});

	test("iOS frameworks", () => {
		const components = iosComponents({
			"Payload/A.app/Frameworks/Alamofire.framework/Info.plist": encodeBplist({
				CFBundleIdentifier: "org.alamofire.Alamofire",
				CFBundleName: "Alamofire",
				CFBundleShortVersionString: "5.8.1",
			}),
			"Payload/A.app/Frameworks/NoVersion.framework/Info.plist": encodeBplist({
				CFBundleIdentifier: "x",
			}),
		});
		expect(components).toHaveLength(1);
		expect(components[0]).toMatchObject({
			name: "Alamofire",
			version: "5.8.1",
			bundleId: "org.alamofire.Alamofire",
		});
	});
});

describe("mobile.dependencies", () => {
	const enc = (s: string) => new TextEncoder().encode(s);
	const apkEntries = {
		"META-INF/androidx.core_core.version": enc("1.12.0\n"),
		"META-INF/maven/com.google.code.gson/gson/pom.properties": enc(
			"version=2.8.0\ngroupId=com.google.code.gson\nartifactId=gson\n",
		),
		"META-INF/com.squareup.okhttp3_okhttp.version": enc("3.8.0"),
		"firebase-common.properties": enc(
			"version=20.3.2\nclient=firebase-common\nfirebase-common_client=20.3.2\n",
		),
		"classes.dex": enc("dex\n035\0"),
	};

	test("reports OSV advisories for bundled Maven libraries and an inventory", async () => {
		const apk = await writeArchive("app.apk", apkEntries);
		const calls: Array<{ url: string; init?: HttpRequest }> = [];
		const report = await runWithOsv(apk, calls);
		expect(firstResult(report).status).toBe("failed");
		expect(mobileDependencies.network).toBe(true);
		expect(
			calls.filter((c) => c.url === "https://api.osv.dev/v1/querybatch"),
		).toHaveLength(1);

		const findings = findingsOf(report);
		const vulns = findings.filter(
			(f) => f.ruleId === "mobile.dependencies/vulnerable-dependency",
		);
		expect(vulns.map((f) => f.evidence).sort()).toEqual([
			"com.google.code.gson:gson@2.8.0 GHSA-4jrv-ppp4-jm57",
			"com.squareup.okhttp3:okhttp@3.8.0 GHSA-3cqm-mf7h-prrj",
		]);
		const vulnFor = (library: string) =>
			must(
				vulns.find((f) => f.evidence?.includes(library)),
				`a ${library} advisory`,
			);
		const gson = vulnFor("gson");
		expect(gson.severity).toBe("high");
		expect(gson.category).toBe("supply-chain");
		expect(gson.tags).toContain("cve-2022-25647");
		expect(gson.tags).toContain("ghsa-4jrv-ppp4-jm57");
		expect(gson.tags).toContain("cwe-502");
		expect(gson.remediation).toContain("2.8.9");
		expect(must(gson.location, "its location").file).toContain(
			"!/META-INF/maven/com.google.code.gson/gson/pom.properties",
		);
		expect(vulnFor("okhttp").severity).toBe("high"); // CVSS 7.5

		const inventory = findingWith(
			findings,
			"mobile.dependencies/sdk-inventory",
		);
		expect(inventory.severity).toBe("info");
		expect(inventory.tags).toContain("sbom");
		expect(inventory.evidence).toContain("androidx.core:core@1.12.0");
		expect(inventory.evidence).toContain(
			"com.google.firebase:firebase-common@20.3.2",
		);
		expect(inventory.title).toBe("4 bundled libraries identified");
	});

	test("is skipped offline by the engine", async () => {
		const apk = await writeArchive("app.apk", apkEntries);
		const calls: Array<{ url: string }> = [];
		const report = await runWithOsv(apk, calls, { offline: true });
		expect(report.results[0]?.status).toBe("skipped");
		expect(calls).toHaveLength(0);
	});

	test("an APK without markers is skipped", async () => {
		const apk = await writeArchive("plain.apk", { "classes.dex": enc("x") });
		const report = await runAuditor(mobileDependencies, apk);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("version markers");
	});

	test("an IPA is inventoried without any network call", async () => {
		const ipa = await writeArchive("app.ipa", {
			"Payload/A.app/Frameworks/Alamofire.framework/Info.plist": encodeBplist({
				CFBundleIdentifier: "org.alamofire.Alamofire",
				CFBundleShortVersionString: "5.8.1",
			}),
		});
		const calls: Array<{ url: string }> = [];
		const report = await runWithOsv(ipa, calls);
		expect(calls).toHaveLength(0);
		expect(report.results[0]?.findings.map((f) => f.ruleId)).toEqual([
			"mobile.dependencies/ios-framework-inventory",
		]);
		expect(report.results[0]?.findings[0]?.evidence).toBe(
			"Alamofire@5.8.1 (org.alamofire.Alamofire)",
		);
	});

	test("source trees are skipped", async () => {
		const dir = await writeTree({
			"AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b"/>`,
		});
		const report = await runAuditor(mobileDependencies, dir);
		expect(report.results[0]?.status).toBe("skipped");
	});

	test("oversized marker files are ignored", async () => {
		const apk = await writeArchive("big.apk", {
			"META-INF/androidx.core_core.version": new Uint8Array(128 * 1024).fill(
				0x31,
			),
		});
		const report = await runAuditor(mobileDependencies, apk);
		expect(report.results[0]?.status).toBe("skipped");
	});
});
