import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { maskPersonalData, privacy } from "../src/codebase/privacy";
import { runAuditor } from "./helpers";

const FILES: Record<string, string> = {
	"package.json": JSON.stringify({
		name: "app",
		dependencies: {
			"posthog-js": "^1.0.0",
			"@sentry/react": "^8.0.0",
			logrocket: "^9.0.0",
			"@fingerprintjs/fingerprintjs": "^4.0.0",
			react: "^18.0.0",
		},
		devDependencies: { "mixpanel-browser": "^2.0.0" },
	}),
	"backend/requirements.txt": "Django==5.0\nmixpanel>=4.10  # analytics\n",
	"backend/requirements-dev.txt": "amplitude-analytics==1.0\n",
	"android/app/build.gradle.kts":
		'dependencies {\n  implementation("com.appsflyer:af-android-sdk:6.12.0")\n}\n',
	"go.mod":
		"module x\n\nrequire (\n\tgithub.com/segmentio/analytics-go/v3 v3.3.0\n)\n",
	"package-lock.json": JSON.stringify({
		packages: {
			"": {},
			"node_modules/react": {},
			"node_modules/@amplitude/analytics-browser": {},
		},
	}),
	"public/index.html": `<!doctype html><html><head>
<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDE12345"></script>
<script>gtag('config', 'G-ABCDE12345'); fbq('init', '1234567890123456');</script>
<!-- <script src="https://static.hotjar.com/c/hotjar-1.js"></script> -->
</head></html>`,
	"src/styles.css": '@import url("https://fonts.gstatic.com/s/inter.css");\n',
	"src/replay.ts": `import LogRocket from "logrocket";
LogRocket.init("a/b", { dom: { inputSanitizer: false } });
posthog.init("key", { session_recording: { maskAllInputs: false } });
`,
	"src/safe-replay.ts": `posthog.init("key", { session_recording: { maskAllInputs: true } });\n`,
	"src/logs.ts": `export const f = (user: any) => {
  console.log("Invalid email format");
  console.log("user signed in", user.email);
  logger.info(\`reset for \${user.phone}\`);
  console.error("password reset failed", err);
  logger.debug("hash", maskEmail(user.email));
  console.log("emailSent", emailSent);
};
`,
	"src/app.py": `import logging
log = logging.getLogger(__name__)
def f(user):
    print("enter your email")
    log.info(f"login by {user.email}")
    logging.warning("bad request from %s", request.remote_addr)
`,
	"src/main.go": `package main
func f() {
	log.Printf("created %s", customer.PhoneNumber)
	log.Println("started server")
}
`,
	"src/Service.java": `class S { void f() { log.info("User: {}", user.getEmail()); log.info("done"); } }\n`,
	"src/app.rb": `logger.info "signup #{user.email}"\nlogger.info "signup done"\n`,
	"tests/log.test.ts": `console.log("x", user.email);\n`,
	"fixtures/package.json": JSON.stringify({
		dependencies: { "@hotjar/browser": "1" },
	}),
};

let dir: string;
beforeAll(() => {
	dir = mkdtempSync(join(tmpdir(), "openaudit-privacy-"));
	for (const [path, text] of Object.entries(FILES)) {
		mkdirSync(dirname(join(dir, path)), { recursive: true });
		writeFileSync(join(dir, path), text);
	}
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const rule = (id: string) => `code.privacy/${id}`;

describe("code.privacy", () => {
	test("inventories SDKs, flags replay and fingerprinting, skips dev and fixtures", async () => {
		const report = await runAuditor(privacy, dir);
		const findings = report.results.flatMap((r) => r.findings);

		const inventory = findings.find(
			(f) => f.ruleId === rule("tracking-sdk-inventory"),
		);
		expect(inventory?.severity).toBe("info");
		const sdks = inventory?.evidence ?? "";
		for (const name of [
			"PostHog",
			"Sentry",
			"LogRocket",
			"FingerprintJS",
			"Mixpanel",
			"AppsFlyer",
			"Segment",
			"Google Analytics",
			"Meta Pixel / Facebook SDK",
			"Amplitude", // lockfile-only
		])
			expect(sdks).toContain(name);
		// Dev requirements, test fixtures and commented-out markup are ignored.
		expect(sdks).not.toContain("Hotjar");
		expect(inventory?.message).toContain("lockfile only");
		expect(inventory?.message).not.toContain("requirements-dev");

		const replay = findings.filter(
			(f) => f.ruleId === rule("session-replay-sdk"),
		);
		expect(replay.map((f) => f.title)).toEqual([
			expect.stringContaining("LogRocket"),
		]);
		expect(replay[0]?.severity).toBe("low");
		const fp = findings.filter((f) => f.ruleId === rule("fingerprinting-sdk"));
		expect(fp).toHaveLength(1);
		expect(fp[0]?.severity).toBe("low");
	});

	test("flags PII in log calls only when the value is logged", async () => {
		const report = await runAuditor(privacy, dir);
		const logs = report.results
			.flatMap((r) => r.findings)
			.filter((f) => f.ruleId === rule("pii-in-logs"));
		const at = (file: string) =>
			logs
				.filter((f) => f.location?.file === file)
				.map((f) => f.location?.line)
				.sort();
		expect(at("src/logs.ts")).toEqual([3, 4]);
		expect(at("src/app.py")).toEqual([5, 6]);
		expect(at("src/main.go")).toEqual([3]);
		expect(at("src/Service.java")).toEqual([1]);
		expect(at("src/app.rb")).toEqual([1]);
		expect(at("tests/log.test.ts")).toEqual([]);
		for (const f of logs) {
			expect(f.severity).toBe("medium");
			expect(f.confidence).toBe("low");
			expect(f.tags).toContain("cwe-532");
		}
	});

	test("flags unmasked session replay, Google Fonts and tracking IDs", async () => {
		const report = await runAuditor(privacy, dir);
		const findings = report.results.flatMap((r) => r.findings);
		const unmasked = findings.filter(
			(f) => f.ruleId === rule("session-replay-unmasked"),
		);
		expect(unmasked.map((f) => [f.location?.file, f.location?.line])).toEqual(
			expect.arrayContaining([
				["src/replay.ts", 2],
				["src/replay.ts", 3],
			]),
		);
		expect(
			unmasked.some((f) => f.location?.file === "src/safe-replay.ts"),
		).toBe(false);

		const fonts = findings
			.filter((f) => f.ruleId === rule("google-fonts"))
			.map((f) => f.location?.file)
			.sort();
		expect(fonts).toEqual(["public/index.html", "src/styles.css"]);

		const ids = findings
			.filter((f) => f.ruleId === rule("tracking-id"))
			.map((f) => f.title)
			.sort();
		expect(ids).toEqual([
			"Google Analytics 4 measurement ID hard-coded",
			"Meta Pixel ID hard-coded",
		]);
		expect(
			findings
				.filter((f) => f.ruleId === rule("tracking-id"))
				.every((f) => f.severity === "info"),
		).toBe(true);
	});

	test("quotes no personal data from the source in findings", async () => {
		const pii = [
			"jane.doe@example.org",
			"415-555-0132",
			"+44 20 7946 0958",
			"203.0.113.42",
			"2001:db8::8a2e:370:7334",
			"4111 1111 1111 1111",
			"078-05-1120",
		];
		const files: Record<string, string> = {
			"src/pii.ts": `export const f = (user: any) => {
  console.log("signup jane.doe@example.org +1 415-555-0132 from 203.0.113.42", user.email);
  logger.info(\`card 4111 1111 1111 1111 ssn 078-05-1120 for \${user.ssn}\`);
  posthog.init("k", { session_recording: { maskAllInputs: false } }); // owner jane.doe@example.org
};
`,
			"src/app.py": `log.info(f"login 2001:db8::8a2e:370:7334 {user.email}")\n`,
			"public/index.html": `<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet"> <!-- +44 20 7946 0958 -->
<script>gtag('config', 'G-ABCDE12345'); /* jane.doe@example.org */</script>
`,
		};
		const root = mkdtempSync(join(tmpdir(), "openaudit-privacy-pii-"));
		try {
			for (const [path, text] of Object.entries(files)) {
				mkdirSync(dirname(join(root, path)), { recursive: true });
				writeFileSync(join(root, path), text);
			}
			const findings = (await runAuditor(privacy, root)).results.flatMap(
				(r) => r.findings,
			);
			expect(findings.map((f) => f.ruleId).sort()).toEqual(
				[
					"google-fonts",
					"pii-in-logs",
					"pii-in-logs",
					"pii-in-logs",
					"session-replay-unmasked",
					"tracking-id",
					"tracking-sdk-inventory",
				].map(rule),
			);
			const out = JSON.stringify(findings);
			for (const value of pii) expect(out).not.toContain(value);
			const signup = findings.find(
				(f) => f.ruleId === rule("pii-in-logs") && f.location?.line === 2,
			);
			expect(signup?.message).toContain("`email`");
			expect(signup?.evidence).toContain("[email]");
			expect(signup?.evidence).toContain("user.email");
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	test("maskPersonalData names the kind of value and leaves code alone", () => {
		expect(
			maskPersonalData(
				'log("a.b+c@mail.example.com 10.0.0.12 fe80::1ff:fe23:4567:890a +1 (415) 555-0132 4242-4242-4242-4242 078-05-1120")',
			),
		).toBe('log("[email] [ip] [ip] [phone] [card] [ssn]")');
		for (const code of [
			'log("v1.2.3", 2024-01-01, 12:30:45, Face::Detector, port 8080)',
			"const ts = 1700000000001; const n = 123456789;",
		])
			expect(maskPersonalData(code)).toBe(code);
	});

	test("reports nothing for a codebase without trackers", async () => {
		const clean = mkdtempSync(join(tmpdir(), "openaudit-privacy-clean-"));
		try {
			writeFileSync(
				join(clean, "package.json"),
				JSON.stringify({ dependencies: { react: "1" } }),
			);
			writeFileSync(join(clean, "a.ts"), 'console.log("hello");\n');
			const report = await runAuditor(privacy, clean);
			expect(report.results[0]?.status).toBe("passed");
			expect(report.results[0]?.findings).toEqual([]);
		} finally {
			rmSync(clean, { recursive: true, force: true });
		}
	});
});
