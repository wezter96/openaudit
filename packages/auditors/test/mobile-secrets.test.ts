import { describe, expect, test } from "bun:test";

import { entropy, mobileSecrets, scanForSecrets } from "../src/mobile/secrets";
import { ruleIds, runAuditor } from "./helpers";
import { writeArchive, writeTree, xmlPlist } from "./mobile-plist-encoder";

// Assembled at runtime so no secret-shaped literal lives in the repo.
const AWS_KEY = ["AK", "IA", "Q3TESTFAKE7KEY12"].join("");
const STRIPE_KEY = ["sk", "live", "FAKE0123456789abcdefFAKE"].join("_");
const GOOGLE_KEY = ["AI", "za", "SyFAKE".padEnd(35, "x0")].join("");
const GENERIC = "Zq8Lr3Vt9Wm2Kx7Pn4Bs";
const PEM = [
	"-----BEGIN ",
	"PRIVATE KEY",
	"-----\nMIIfake\n-----END PRIVATE KEY-----",
].join("");

const findings = (report: Awaited<ReturnType<typeof runAuditor>>) =>
	report.results.flatMap((r) => r.findings);

const bytes = (...parts: Array<string | number[]>) =>
	Uint8Array.from(
		parts.flatMap((p) =>
			typeof p === "string" ? [...new TextEncoder().encode(p)] : p,
		),
	);

describe("mobile.secrets", () => {
	test("scans dex, assets and JS bundles in an APK and redacts evidence", async () => {
		const apk = await writeArchive("app.apk", {
			"AndroidManifest.xml": bytes([0x03, 0x00, 0x08, 0x00]),
			"classes.dex": bytes("dex\n035\0", [0, 1, 2, 20], AWS_KEY, [0, 7]),
			"assets/config.json": `{\n  "payments": "${STRIPE_KEY}",\n  "api": "http://api.demo-backend.io/v1"\n}\n`,
			"assets/index.android.bundle": `var a=1;\nvar cfg={apiKey:"${GENERIC}",databaseURL:"https://demo-app-1234.firebaseio.com"};`,
			"assets/certs/key.pem": PEM,
			// Media is never scanned, even if it happens to contain a token.
			"res/drawable/icon.png": bytes([0x89, 0x50], AWS_KEY.replace("Q3", "Z9")),
		});
		const report = await runAuditor(mobileSecrets, apk);
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"mobile.secrets/aws-access-key",
			"mobile.secrets/cleartext-endpoint",
			"mobile.secrets/firebase-database-url",
			"mobile.secrets/generic-secret",
			"mobile.secrets/private-key",
			"mobile.secrets/stripe-live-secret",
		]);
		const all = findings(report);
		for (const f of all) {
			expect(f.evidence ?? "").not.toContain(AWS_KEY);
			expect(f.evidence ?? "").not.toContain(STRIPE_KEY);
			expect(f.evidence ?? "").not.toContain(GENERIC);
		}
		const aws = all.find((f) => f.ruleId === "mobile.secrets/aws-access-key");
		expect(aws?.location).toEqual({ file: "app.apk!classes.dex" });
		const stripe = all.find(
			(f) => f.ruleId === "mobile.secrets/stripe-live-secret",
		);
		expect(stripe?.severity).toBe("critical");
		expect(stripe?.location).toEqual({
			file: "app.apk!assets/config.json",
			line: 2,
		});
	});

	test("treats Google keys in Firebase config as informational", async () => {
		const ipa = await writeArchive("Demo.ipa", {
			"Payload/Demo.app/GoogleService-Info.plist": xmlPlist({
				API_KEY: GOOGLE_KEY,
				DATABASE_URL:
					"https://demo-app-1234-default-rtdb.europe-west1.firebasedatabase.app",
			}),
			"Payload/Demo.app/main.jsbundle": `const maps="${GOOGLE_KEY}";`,
			"Payload/Demo.app/Assets.car": AWS_KEY,
		});
		const report = await runAuditor(mobileSecrets, ipa);
		const google = findings(report).filter(
			(f) => f.ruleId === "mobile.secrets/google-api-key",
		);
		expect(google.map((f) => f.severity).sort()).toEqual(["info", "low"]);
		expect(ruleIds(report)).not.toContain("mobile.secrets/aws-access-key");
		expect(ruleIds(report)).toContain("mobile.secrets/firebase-database-url");
	});

	test("scans only mobile config files in a source tree", async () => {
		const dir = await writeTree({
			"android/app/src/main/AndroidManifest.xml":
				'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo"/>',
			"android/app/src/main/res/values/strings.xml": `<resources>\n  <string name="app_name">Demo</string>\n  <string name="backend_secret">${GENERIC}</string>\n</resources>\n`,
			"android/gradle.properties": `org.gradle.jvmargs=-Xmx2048m\nSTRIPE_SECRET_KEY=${STRIPE_KEY}\nMAPS_API_KEY=your-api-key-here-please\n`,
			"src/client.ts": `export const key = "${AWS_KEY}";`,
		});
		const report = await runAuditor(mobileSecrets, dir);
		expect(ruleIds(report)).toEqual([
			"mobile.secrets/generic-secret",
			"mobile.secrets/stripe-live-secret",
		]);
		const generic = findings(report).find(
			(f) => f.ruleId === "mobile.secrets/generic-secret",
		);
		expect(generic?.location).toEqual({
			file: "android/app/src/main/res/values/strings.xml",
			line: 3,
		});
		expect(generic?.evidence).toBe("backend_secret = Zq8L************");
	});

	test("ignores placeholders, low-entropy values and well-known schema URLs", () => {
		const text = [
			'apiKey: "aaaaaaaaaaaaaaaaaaaa"',
			'api_key = "YOUR_API_KEY_GOES_HERE"',
			'xmlns:android="http://schemas.android.com/apk/res/android"',
			'"http://localhost:8081/index.bundle"',
			'"http://www.w3.org/2000/svg"',
		].join("\n");
		expect(scanForSecrets(text, "x.json")).toEqual([]);
		expect(entropy("aaaa")).toBe(0);
	});

	test("does not report http endpoints or generic assignments in binaries", () => {
		const text = `http://api.demo-backend.io apiKey="${GENERIC}"`;
		expect(scanForSecrets(text, "classes.dex", { binary: true })).toEqual([]);
	});
});
