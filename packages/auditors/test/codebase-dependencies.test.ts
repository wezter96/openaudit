import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { cp, mkdtemp, readdir, readFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
	checkPackageJson,
	cvss3BaseScore,
	type Dependency,
	dependencies,
	fixedVersions,
	type OsvVuln,
	osvSeverity,
	parseDependencies,
} from "../src/codebase/dependencies";
import { fixture } from "./helpers";

// Lockfiles are stored as `*.fixture` so repository dependency scanners do not
// raise alerts for their intentionally vulnerable versions.
const FIXTURE_DIR = fixture("codebase", "deps");
let root = "";

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "openaudit-deps-"));
	await cp(FIXTURE_DIR, root, { recursive: true });
	for (const name of await readdir(root))
		if (name.endsWith(".fixture"))
			await rename(
				join(root, name),
				join(root, name.slice(0, -".fixture".length)),
			);
});

afterAll(() => rm(root, { recursive: true, force: true }));

const parse = async (name: string) =>
	parseDependencies({
		path: name,
		text: await readFile(join(FIXTURE_DIR, `${name}.fixture`), "utf8"),
	}).map((d) => `${d.ecosystem}:${d.name}@${d.version}`);

describe("code.dependencies parsers", () => {
	test("npm lockfiles", async () => {
		expect(await parse("package-lock.json")).toEqual([
			"npm:lodash@4.17.20",
			"npm:minimist@1.2.5",
			"npm:minimist@0.0.8",
		]);
		expect(await parse("bun.lock")).toEqual([
			"npm:lodash@4.17.20",
			"npm:@scope/pkg@2.0.1",
		]);
		expect(await parse("pnpm-lock.yaml")).toEqual([
			"npm:axios@0.21.0",
			"npm:@babel/core@7.20.0",
			"npm:react-dom@18.2.0",
		]);
		expect(await parse("yarn.lock")).toEqual([
			"npm:@types/node@18.11.9",
			"npm:minimist@1.2.5",
		]);
	});

	test("other ecosystems", async () => {
		expect(await parse("requirements.txt")).toEqual([
			"PyPI:django@3.2.0",
			"PyPI:requests@2.25.0",
		]);
		expect(await parse("poetry.lock")).toEqual([
			"PyPI:pyyaml@5.3",
			"PyPI:jinja2@2.10",
		]);
		expect(await parse("go.mod")).toEqual([
			"Go:github.com/gin-gonic/gin@1.6.0",
			"Go:golang.org/x/crypto@0.0.0-20200622213623-75b288015ac9",
			"Go:github.com/old/thing@2.0.0",
		]);
		expect(await parse("Cargo.lock")).toEqual(["crates.io:smallvec@1.6.0"]);
		expect(await parse("Gemfile.lock")).toEqual([
			"RubyGems:nokogiri@1.10.0",
			"RubyGems:rack@2.0.1",
		]);
		expect(await parse("composer.lock")).toEqual([
			"Packagist:guzzlehttp/guzzle@7.4.0",
			"Packagist:phpunit/phpunit@9.5.0",
		]);
	});

	test("pnpm v6 and v5 keys", () => {
		const text =
			"lockfileVersion: 5.4\npackages:\n  /lodash/4.17.20:\n    resolution: {}\n  /@scope/pkg@1.0.0_react@18.0.0:\n    resolution: {}\n";
		expect(
			parseDependencies({ path: "pnpm-lock.yaml", text }).map(
				(d) => `${d.name}@${d.version}`,
			),
		).toEqual(["lodash@4.17.20", "@scope/pkg@1.0.0"]);
	});

	test("package.json wildcard and URL dependencies", async () => {
		const text = await readFile(
			join(FIXTURE_DIR, "package.json.fixture"),
			"utf8",
		);
		const findings = checkPackageJson({ path: "package.json", text });
		expect(
			findings.map(
				(f) => `${f.ruleId}:${f.evidence}:${f.severity}:${f.location?.line}`,
			),
		).toEqual([
			'code.dependencies/unpinned-version:"left-pad": "*":medium:6',
			'code.dependencies/url-dependency:"my-lib": "github:someone/my-lib":medium:7',
			'code.dependencies/url-dependency:"pinned-lib": "git+https://github.com/someone/pinned-lib.git#0123456789abcdef0123456789abcdef01234567":low:8',
			'code.dependencies/unpinned-version:"typescript": "latest":medium:13',
		]);
	});
});

describe("code.dependencies severity", () => {
	test("CVSS v3 base scores", () => {
		expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(
			9.8,
		);
		expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(
			6.1,
		);
		expect(cvss3BaseScore("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")).toBe(
			5.5,
		);
		expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(
			0,
		);
		expect(cvss3BaseScore("garbage")).toBeUndefined();
	});

	test("prefers CVSS, falls back to database labels", () => {
		expect(
			osvSeverity({
				id: "X",
				severity: [
					{
						type: "CVSS_V3",
						score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
				],
			}),
		).toBe("critical");
		expect(
			osvSeverity({
				id: "X",
				severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N" }],
				database_specific: { severity: "MODERATE" },
			}),
		).toBe("medium");
		expect(
			osvSeverity({
				id: "X",
				affected: [{ ecosystem_specific: { severity: "HIGH" } }],
			}),
		).toBe("high");
		expect(osvSeverity({ id: "X" })).toBe("medium");
	});

	test("fixed versions for the matching package", () => {
		const vuln: OsvVuln = {
			id: "X",
			affected: [
				{
					package: { name: "lodash", ecosystem: "npm" },
					ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
				},
				{
					package: { name: "lodash-es", ecosystem: "npm" },
					ranges: [{ events: [{ fixed: "4.17.22" }] }],
				},
			],
		};
		const d: Dependency = {
			name: "lodash",
			version: "4.17.20",
			ecosystem: "npm",
			file: "x",
		};
		expect(fixedVersions(vuln, d)).toEqual(["4.17.21"]);
	});
});

const LODASH_VULN = {
	id: "GHSA-35jh-r3h4-6jhm",
	summary: "Command Injection in lodash",
	aliases: ["CVE-2021-23337"],
	severity: [
		{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" },
	],
	affected: [
		{
			package: { name: "lodash", ecosystem: "npm" },
			ranges: [
				{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] },
			],
		},
	],
	references: [
		{
			type: "ADVISORY",
			url: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
		},
	],
	database_specific: { cwe_ids: ["CWE-77", "CWE-94"], severity: "HIGH" },
};
const DJANGO_PYSEC = {
	id: "PYSEC-2021-9",
	summary: "Django path traversal",
	aliases: ["CVE-2021-28658", "GHSA-xgxc-v2qg-chmh"],
};
const DJANGO_GHSA = {
	id: "GHSA-xgxc-v2qg-chmh",
	summary: "Django path traversal",
	aliases: ["CVE-2021-28658"],
	database_specific: { severity: "MODERATE" },
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

const runWithMockOsv = (
	target: string,
	calls: Array<{ url: string; init?: HttpRequest }>,
): Promise<Report> => {
	const http = Layer.succeed(Http, {
		request: (url: string, init?: HttpRequest) =>
			Effect.sync(() => {
				calls.push({ url, init });
				if (url.endsWith("/querybatch")) {
					const { queries } = JSON.parse(init?.body ?? "{}") as {
						queries: Array<{ package: { name: string }; version: string }>;
					};
					return response(url, 200, {
						results: queries.map((q) =>
							q.package.name === "lodash"
								? { vulns: [{ id: LODASH_VULN.id }] }
								: q.package.name === "django"
									? { vulns: [{ id: DJANGO_PYSEC.id }, { id: DJANGO_GHSA.id }] }
									: {},
						),
					});
				}
				const id = decodeURIComponent(url.split("/").pop() ?? "");
				const vuln = [LODASH_VULN, DJANGO_PYSEC, DJANGO_GHSA].find(
					(v) => v.id === id,
				);
				return vuln ? response(url, 200, vuln) : response(url, 404, {});
			}),
	});
	return Effect.runPromise(
		runAudit({
			target,
			auditors: [dependencies],
			selection: { only: [dependencies.id] },
		}).pipe(Effect.provide(Layer.mergeAll(Workspaces.layer, http, Exec.layer))),
	);
};

describe("code.dependencies auditor", () => {
	test("queries OSV in a batch and reports vulnerabilities with fixes", async () => {
		const calls: Array<{ url: string; init?: HttpRequest }> = [];
		const report = await runWithMockOsv(root, calls);
		const findings = report.results.flatMap((r) => r.findings);
		expect(report.results[0]?.status).toBe("failed");

		const batches = calls.filter(
			(c) => c.url === "https://api.osv.dev/v1/querybatch",
		);
		expect(batches).toHaveLength(1);
		expect(batches[0]?.init?.method).toBe("POST");

		const vulns = findings.filter(
			(f) => f.ruleId === "code.dependencies/vulnerable-dependency",
		);
		// lodash appears in bun.lock and package-lock.json but is reported once;
		// Django's PYSEC and GHSA records are the same advisory.
		expect(vulns.map((f) => f.evidence).sort()).toEqual([
			"django@3.2.0 PYSEC-2021-9",
			"lodash@4.17.20 GHSA-35jh-r3h4-6jhm",
		]);
		const lodash = vulns.find((f) => f.evidence?.startsWith("lodash"));
		expect(lodash?.severity).toBe("high");
		expect(lodash?.remediation).toContain("4.17.21");
		expect(lodash?.location).toEqual({ file: "bun.lock", line: 7 });
		expect(lodash?.tags).toEqual([
			"owasp-a06",
			"cwe-77",
			"cwe-94",
			"ghsa-35jh-r3h4-6jhm",
			"cve-2021-23337",
		]);
		expect(lodash?.references?.[0]).toBe(
			"https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
		);

		const local = findings
			.filter((f) => f.ruleId !== "code.dependencies/vulnerable-dependency")
			.map((f) => f.ruleId);
		expect(local.sort()).toEqual([
			"code.dependencies/unpinned-version",
			"code.dependencies/unpinned-version",
			"code.dependencies/url-dependency",
			"code.dependencies/url-dependency",
		]);
	});

	test("errors when OSV is unavailable instead of silently passing", async () => {
		const http = Layer.succeed(Http, {
			request: (url: string) => Effect.succeed(response(url, 503, {})),
		});
		const report = await Effect.runPromise(
			runAudit({
				target: root,
				auditors: [dependencies],
				selection: { only: [dependencies.id] },
			}).pipe(
				Effect.provide(Layer.mergeAll(Workspaces.layer, http, Exec.layer)),
			),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("HTTP 503");
	});

	test("skips when offline", async () => {
		const report = await runWithMockOsv(root, []).then(() =>
			Effect.runPromise(
				runAudit({
					target: root,
					auditors: [dependencies],
					options: { offline: true },
					selection: { only: [dependencies.id] },
				}).pipe(
					Effect.provide(
						Layer.mergeAll(Workspaces.layer, Http.layer, Exec.layer),
					),
				),
			),
		);
		expect(report.results[0]?.status).toBe("skipped");
	});

	test.skipIf(process.env.OPENAUDIT_NETWORK_TESTS !== "1")(
		"live OSV lookup",
		async () => {
			const report = await Effect.runPromise(
				runAudit({
					target: root,
					auditors: [dependencies],
					selection: { only: [dependencies.id] },
				}).pipe(
					Effect.provide(
						Layer.mergeAll(Workspaces.layer, Http.layer, Exec.layer),
					),
				),
			);
			const vulns = report.results
				.flatMap((r) => r.findings)
				.filter((f) => f.ruleId === "code.dependencies/vulnerable-dependency");
			expect(vulns.some((f) => f.evidence?.startsWith("lodash@4.17.20"))).toBe(
				true,
			);
		},
		60_000,
	);
});
