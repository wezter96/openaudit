import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { isPlaceholder, scanSecrets, secrets } from "../src/codebase/secrets";
import { scrubLine } from "../src/codebase/util";
import { ruleIds, runAuditor } from "./helpers";
import { must } from "./must";

// Fake credentials are assembled at runtime so no token-shaped literal is
// committed (keeps push protection and other scanners quiet).
const FAKE = {
	aws: `AKIA${"Q7ZK3M9P2W5X8R4T"}`,
	awsSecret: `q8Vt2LmN4pRx7ZcW1bYk9HsJ3dF6gTaE0u${"QiOyPn"}`,
	github: `ghp_${"R8mK2vX9pL4qT7wZ1nB5cY3hJ6dF0gS8aE2u"}`,
	stripe: `sk_${"live_"}${"4eC39HqLyjWDarjtT1zdp7dc"}`,
	slack: `https://hooks.slack.com/${"services"}/T024BE7LD/B01QWE2RTY/Zq8Xk2Lm9Pv4Rt7Wn3Yc5Bd1`,
	pem: `-----BEGIN RSA ${"PRIVATE KEY"}-----\nMIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi0rC5r1D2G4bWm6pQ8sY7wZ+K\n-----END RSA PRIVATE KEY-----`,
	dbPassword: "Hk29xLq7Zp",
	generic: "f9K2mQ8xV4pL7wZ3rT6y",
	jwt: `eyJhbGciOiJIUzI1NiJ9.${"eyJzdWIiOiIxMjM0NTY3ODkwIn0"}.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
	envPassword: "Zx81kLmQ2pW7vR",
};

const FILES: Record<string, string> = {
	"src/config.ts": [
		`export const aws = "${FAKE.aws}";`,
		`export const aws_secret_access_key = "${FAKE.awsSecret}";`,
		`export const gh = "${FAKE.github}";`,
		`export const stripe = "${FAKE.stripe}";`,
		`export const hook = "${FAKE.slack}";`,
		`export const db = "postgres://app:${FAKE.dbPassword}@db.internal:5432/app";`,
		`export const apiKey = "${FAKE.generic}";`,
		`export const session = "${FAKE.jwt}";`,
		`export const password = "changeme";`,
		`export const ignored = "${FAKE.github}"; // openaudit-ignore`,
		`export const local = "postgres://app:\${DB_PASSWORD}@localhost/app";`,
	].join("\n"),
	"keys/id_rsa": FAKE.pem,
	".env.production": `NODE_ENV=production\nDATABASE_PASSWORD=${FAKE.envPassword}\n`,
	".env.example": "API_KEY=your-api-key\nDATABASE_PASSWORD=changeme\n",
	"package-lock.json": `{"packages":{"node_modules/x":{"integrity":"sha512-${FAKE.awsSecret}"}}}`,
	"fixtures/fake.ts": `export const k = "${FAKE.aws}";`,
};

/** No fake credential except the PEM block appears in full in `serialised`. */
const expectNoFullSecret = (serialised: string) => {
	for (const value of Object.values(FAKE)) {
		if (value === FAKE.pem) continue;
		expect(serialised).not.toContain(value);
	}
};

let root = "";

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "openaudit-secrets-"));
	for (const [path, content] of Object.entries(FILES)) {
		await mkdir(dirname(join(root, path)), { recursive: true });
		await writeFile(join(root, path), content);
	}
});

afterAll(() => rm(root, { recursive: true, force: true }));

describe("code.secrets", () => {
	test("detects provider tokens, keys, connection strings and env files", async () => {
		const report = await runAuditor(secrets, root);
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"code.secrets/aws-access-key-id",
			"code.secrets/aws-secret-access-key",
			"code.secrets/database-url-password",
			"code.secrets/env-file-committed",
			"code.secrets/generic-secret",
			"code.secrets/generic-secret",
			"code.secrets/github-token",
			"code.secrets/jwt",
			"code.secrets/private-key",
			"code.secrets/slack-webhook",
			"code.secrets/stripe-live-key",
		]);
	});

	test("never leaks a full secret in evidence and reports locations", async () => {
		const report = await runAuditor(secrets, root);
		const findings = report.results.flatMap((r) => r.findings);
		expectNoFullSecret(JSON.stringify(findings));
		const gh = must(
			findings.find((f) => f.ruleId === "code.secrets/github-token"),
			"the GitHub token finding",
		);
		expect(gh.location).toEqual({ file: "src/config.ts", line: 3 });
		expect(gh.evidence).toContain("ghp_");
		expect(gh.tags).toContain("cwe-798");
		const env = must(
			findings.find(
				(f) =>
					f.ruleId === "code.secrets/generic-secret" &&
					f.location?.file === ".env.production",
			),
			"the .env.production finding",
		);
		expect(must(env.location, "its location").line).toBe(2);
	});

	test("treats documentation placeholders as non-secrets", () => {
		expect(isPlaceholder("changeme")).toBe(true);
		expect(isPlaceholder("AKIAIOSFODNN7EXAMPLE")).toBe(true);
		expect(isPlaceholder(["$", "{API_KEY}"].join(""))).toBe(true);
		expect(isPlaceholder("<your-token>")).toBe(true);
		expect(isPlaceholder(FAKE.generic)).toBe(false);
	});

	test("lowers confidence for test files", () => {
		const findings = scanSecrets({
			path: "src/api.test.ts",
			text: `const t = "${FAKE.github}";`,
		});
		expect(findings).toHaveLength(1);
		expect(findings[0]?.confidence).toBe("low");
	});

	test("ignores low-entropy assignments", () => {
		expect(
			scanSecrets({
				path: "a.py",
				text: 'password = "aaaaaaaaaaaa"\nsecret_key = "my_app_name"',
			}),
		).toEqual([]);
	});

	test("two secrets on one line: neither appears raw in any evidence", () => {
		const lines = [
			`AWS_ACCESS_KEY_ID=${FAKE.aws} AWS_SECRET_ACCESS_KEY=${FAKE.awsSecret}`,
			`const cfg = { db: "postgres://app:${FAKE.dbPassword}@db.internal/app", token: "${FAKE.github}" };`,
			`const pair = { apiKey: "${FAKE.generic}", stripe: "${FAKE.stripe}" };`,
		];
		for (const [path, text] of [
			[".env.production", lines[0] ?? ""],
			["src/config.ts", lines.join("\n")],
		] as const) {
			const findings = scanSecrets({ path, text });
			expect(findings.length).toBeGreaterThan(0);
			const evidence = findings.map((f) => f.evidence ?? "").join("\n");
			for (const raw of [
				FAKE.aws,
				FAKE.awsSecret,
				FAKE.dbPassword,
				FAKE.github,
				FAKE.generic,
				FAKE.stripe,
			])
				expect(evidence).not.toContain(raw);
		}
	});

	test("private keys show only the PEM header", () => {
		const text = `const key = "${FAKE.pem.replaceAll("\n", "\\n")}";\n${FAKE.pem}`;
		const findings = scanSecrets({ path: "src/keys.ts", text });
		expect(findings.map((f) => f.evidence)).toEqual([
			"-----BEGIN RSA PRIVATE KEY-----****",
			"-----BEGIN RSA PRIVATE KEY-----****",
		]);
	});

	test("scrubLine masks every credential shape on a line", () => {
		const line = `x = "${FAKE.github}" url="mysql://root:${FAKE.dbPassword}@h/db" password=${FAKE.envPassword} jwt=${FAKE.jwt} ${FAKE.pem.split("\n").join(" ")}`;
		const scrubbed = scrubLine(line);
		for (const raw of [
			FAKE.github,
			FAKE.dbPassword,
			FAKE.envPassword,
			FAKE.jwt,
			"MIIEpAIBAAKCAQEA",
		])
			expect(scrubbed).not.toContain(raw);
		expect(scrubbed).toContain("-----BEGIN RSA PRIVATE KEY-----****");
		expect(scrubLine("const total = items.length + 1;")).toBe(
			"const total = items.length + 1;",
		);
	});
});
