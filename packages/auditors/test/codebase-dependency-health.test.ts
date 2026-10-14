import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { cp, mkdtemp, readdir, readFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditorResult,
	correlate,
	Exec,
	type Finding,
	Http,
	type HttpRequest,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import type { Dependency } from "../src/codebase/dependencies";
import {
	assessDependency,
	DEPENDENCY_HEALTH_ID,
	declaredDependencies,
	dependencyHealth,
	parsePackage,
	parseProjectBatch,
	parseVersionBatch,
	readHealthSettings,
} from "../src/codebase/dependency-health";
import { fixture } from "./helpers";

// Lockfiles are stored as `*.fixture` so repository dependency scanners do not
// raise alerts for their intentionally unhealthy versions. Everything under
// api/ is a recorded deps.dev, npm or PyPI response.
const FIXTURE_DIR = fixture("codebase", "dependency-health");
const API_DIR = join(FIXTURE_DIR, "api");
let root = "";

const api = async (name: string): Promise<unknown> =>
	JSON.parse(await readFile(join(API_DIR, name), "utf8"));

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "openaudit-dep-health-"));
	await cp(FIXTURE_DIR, root, { recursive: true });
	await rm(join(root, "api"), { recursive: true });
	for (const name of await readdir(root))
		if (name.endsWith(".fixture"))
			await rename(
				join(root, name),
				join(root, name.slice(0, -".fixture".length)),
			);
});

afterAll(() => rm(root, { recursive: true, force: true }));

const NOW = Date.parse("2026-10-14T00:00:00Z");

describe("deps.dev parsers", () => {
	test("versionbatch: deprecation, yanking, default and source repository", async () => {
		const { versions, answered } = parseVersionBatch(
			await api("versionbatch.json"),
		);
		expect(versions.get("NPM|request|2.88.2")).toEqual({
			publishedAt: "2020-02-11T16:35:36Z",
			isDefault: true,
			isDeprecated: true,
			deprecatedReason:
				"request has been deprecated, see https://github.com/request/request/issues/3142",
			sourceRepo: "github.com/request/request",
		});
		expect(versions.get("NPM|rimraf|3.0.2")).toMatchObject({
			isDefault: false,
			isDeprecated: true,
		});
		// deps.dev reports a yanked PyPI or Cargo release as deprecated.
		expect(versions.get("PYPI|requests|2.32.0")).toMatchObject({
			isDeprecated: true,
			deprecatedReason:
				"Yanked due to conflicts with CVE-2024-35195 mitigation",
		});
		expect(versions.get("CARGO|tokio|1.39.0")).toMatchObject({
			isDeprecated: true,
			deprecatedReason: "yanked",
		});
		expect(versions.get("GO|github.com/golang/protobuf|v1.5.4")).toMatchObject({
			isDeprecated: true,
			isDefault: true,
		});
		expect(versions.get("NPM|is-number|7.0.0")).toMatchObject({
			isDeprecated: false,
			deprecatedReason: undefined,
		});
		// Unknown packages are answered without a version.
		expect(answered.has("NPM|openaudit-no-such-package-zz|1.0.0")).toBe(true);
		expect(versions.has("NPM|openaudit-no-such-package-zz|1.0.0")).toBe(false);
		expect(answered.size).toBe(11);
		expect(versions.size).toBe(10);
	});

	test("deps.dev deprecation matches the npm registry and PyPI", async () => {
		const { versions } = parseVersionBatch(await api("versionbatch.json"));
		const npm = (await api("npm-request-2.88.2.json")) as {
			deprecated: string;
		};
		const pypi = (await api("pypi-requests-2.32.0.json")) as {
			info: { yanked: boolean; yanked_reason: string };
		};
		expect(versions.get("NPM|request|2.88.2")?.deprecatedReason).toBe(
			npm.deprecated,
		);
		expect(pypi.info.yanked).toBe(true);
		expect(versions.get("PYPI|requests|2.32.0")?.deprecatedReason).toBe(
			pypi.info.yanked_reason,
		);
	});

	test("projectbatch: archived repositories from the Scorecard Maintained check", async () => {
		const { projects, answered } = parseProjectBatch(
			await api("projectbatch.json"),
		);
		expect(projects.get("github.com/mitchellh/go-homedir")).toEqual({
			archived: true,
			scorecardDate: "2026-08-24T00:00:00Z",
		});
		expect(projects.get("github.com/isaacs/rimraf")?.archived).toBe(false);
		expect(projects.get("github.com/psf/requests")?.archived).toBe(false);
		expect(answered.has("github.com/openaudit-no-such/repo-zz")).toBe(true);
		expect(projects.has("github.com/openaudit-no-such/repo-zz")).toBe(false);
	});

	test("package: default version and newest release", async () => {
		expect(parsePackage(await api("package-npm-rimraf.json"))).toEqual({
			defaultVersion: { version: "6.1.3", isDeprecated: false },
			latest: { version: "6.1.3", publishedAt: "2026-02-16T00:59:39Z" },
		});
		expect(parsePackage(await api("package-npm-is-number.json"))).toEqual({
			defaultVersion: { version: "7.0.0", isDeprecated: false },
			latest: { version: "7.0.0", publishedAt: "2018-07-04T15:08:58Z" },
		});
		expect(parsePackage({ error: "not found" })).toBeUndefined();
	});
});

describe("declared (direct) dependencies", () => {
	test("reads package.json, go.mod, Cargo.toml and requirements", async () => {
		const read = async (name: string) => ({
			path: name,
			text: await readFile(join(FIXTURE_DIR, `${name}.fixture`), "utf8"),
		});
		const direct = declaredDependencies([
			await read("package.json"),
			await read("go.mod"),
			await read("Cargo.toml"),
			await read("requirements.txt"),
		]);
		expect([...direct].sort()).toEqual([
			"Go|github.com/golang/protobuf",
			"Go|github.com/mitchellh/go-homedir",
			"PyPI|requests",
			"crates.io|tokio",
			"npm|is-number",
			"npm|left-pad",
			"npm|openaudit-no-such-package-zz",
			"npm|request",
			"npm|rimraf",
		]);
	});

	test("reads pyproject.toml, Gemfile and Cargo tables", () => {
		const direct = declaredDependencies([
			{
				path: "pyproject.toml",
				text: [
					"[project]",
					'name = "app"',
					"dependencies = [",
					'  "Django>=4.2",',
					"  \"typing_extensions; python_version < '3.11'\",",
					"]",
					"[project.optional-dependencies]",
					'dev = ["pytest==8.0.0"]',
					"[tool.poetry.dependencies]",
					'python = "^3.11"',
					'httpx = "^0.27"',
					"[tool.poetry.group.test.dependencies]",
					'Faker = "*"',
					"[tool.ruff]",
					'line-length = "100"',
				].join("\n"),
			},
			{
				path: "Gemfile",
				text: "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n  gem \"pg\"\n",
			},
			{
				path: "crates/a/Cargo.toml",
				text: [
					"[package]",
					'name = "a"',
					"[dev-dependencies]",
					'Serde_Json = "1"',
					"[target.'cfg(unix)'.dependencies]",
					'libc = "0.2"',
					"[dependencies.rand]",
					'version = "0.8"',
				].join("\n"),
			},
		]);
		expect([...direct].sort()).toEqual([
			"PyPI|django",
			"PyPI|faker",
			"PyPI|httpx",
			"PyPI|pytest",
			"PyPI|typing-extensions",
			"RubyGems|pg",
			"RubyGems|rails",
			"crates.io|libc",
			"crates.io|rand",
			"crates.io|serde-json",
		]);
	});
});

describe("settings", () => {
	test("defaults and validation", () => {
		expect(readHealthSettings(undefined)).toEqual({
			staleYears: 3,
			maxRequests: 200,
		});
		expect(readHealthSettings({ staleYears: 0, maxRequests: 50 })).toEqual({
			staleYears: 0,
			maxRequests: 50,
		});
		expect(() => readHealthSettings({ staleYears: -1 })).toThrow("staleYears");
		expect(() => readHealthSettings({ maxRequests: 0 })).toThrow("maxRequests");
		expect(() => readHealthSettings({ maxRequests: 1.5 })).toThrow(
			"maxRequests",
		);
	});
});

describe("assessDependency", () => {
	const isNumber: Dependency = {
		name: "is-number",
		version: "7.0.0",
		ecosystem: "npm",
		file: "package-lock.json",
	};

	test("stale when the newest release is older than the threshold", async () => {
		const { versions } = parseVersionBatch(await api("versionbatch.json"));
		const pkg = parsePackage(await api("package-npm-is-number.json"));
		const assess = (staleYears: number) =>
			assessDependency(isNumber, {
				version: versions.get("NPM|is-number|7.0.0"),
				pkg,
				direct: true,
				now: NOW,
				staleYears,
				line: 12,
			});
		const [stale, ...rest] = assess(3);
		expect(rest).toEqual([]);
		expect(stale).toMatchObject({
			ruleId: "code.dependency-health/stale-package",
			severity: "low",
			confidence: "low",
			location: { file: "package-lock.json", line: 12 },
			tags: ["cwe-1104", "owasp-a06"],
		});
		expect(stale?.message).toContain("2018-07-04");
		expect(assess(10)).toEqual([]);
		expect(assess(0)).toEqual([]);
	});

	test("an archived repository behind newer releases is likely a move", async () => {
		const { versions } = parseVersionBatch(await api("versionbatch.json"));
		const { projects } = parseProjectBatch(await api("projectbatch.json"));
		const homedir: Dependency = {
			name: "github.com/mitchellh/go-homedir",
			version: "1.1.0",
			ecosystem: "Go",
			file: "go.mod",
		};
		const version = versions.get("GO|github.com/mitchellh/go-homedir|v1.1.0");
		const assess = (isDefault: boolean) =>
			assessDependency(homedir, {
				version: version && { ...version, isDefault },
				project: projects.get("github.com/mitchellh/go-homedir"),
				direct: true,
				now: NOW,
				staleYears: 3,
			});
		expect(assess(true)[0]).toMatchObject({
			severity: "medium",
			confidence: "medium",
		});
		const [moved] = assess(false);
		expect(moved).toMatchObject({ severity: "low", confidence: "low" });
		expect(moved?.remediation).toContain("latest release");
		expect(moved?.references?.[0]).toBe(
			"https://deps.dev/project/github/mitchellh%2Fgo-homedir",
		);
	});

	test("transitive dependencies are never reported as stale", async () => {
		const { versions } = parseVersionBatch(await api("versionbatch.json"));
		expect(
			assessDependency(isNumber, {
				version: versions.get("NPM|is-number|7.0.0"),
				pkg: parsePackage(await api("package-npm-is-number.json")),
				direct: false,
				now: NOW,
				staleYears: 3,
			}),
		).toEqual([]);
	});
});

/* -------------------------------------------------------------------------- */
/*                         Auditor against a fake deps.dev                    */
/* -------------------------------------------------------------------------- */

type Call = { url: string; init?: HttpRequest };

interface FakeOptions {
	/** Responses per batch page (deps.dev pages at 100). */
	readonly pageSize?: number;
	readonly fail?: (url: string) => number | "invalid-json" | undefined;
}

const response = (url: string, status: number, body: string) => ({
	url,
	status,
	headers: new Headers(),
	cookies: [],
	body,
	bytes: body.length,
	redirected: false,
	ttfbMs: 0,
	totalMs: 0,
});

type Entry = { request: Record<string, Record<string, string>> };

/** Replays recorded deps.dev responses for whatever the auditor asks. */
const fakeDepsDev = async (calls: Call[], options: FakeOptions = {}) => {
	const versionEntries = (
		(await api("versionbatch.json")) as { responses: Entry[] }
	).responses;
	const projectEntries = (
		(await api("projectbatch.json")) as { responses: Entry[] }
	).responses;
	const packages = new Map<string, string>();
	for (const name of await readdir(API_DIR))
		if (name.startsWith("package-"))
			packages.set(name, await readFile(join(API_DIR, name), "utf8"));

	const batch = (
		url: string,
		init: HttpRequest | undefined,
		entries: Entry[],
		keyOf: (r: Record<string, Record<string, string>>) => string,
	) => {
		const body = JSON.parse(init?.body ?? "{}") as {
			requests: Array<Record<string, Record<string, string>>>;
			pageToken?: string;
		};
		const all = body.requests.map((r) => {
			const entry = entries.find((e) => keyOf(e.request) === keyOf(r));
			if (!entry) throw new Error(`no recorded response for ${keyOf(r)}`);
			return entry;
		});
		const size = options.pageSize ?? 100;
		const page = body.pageToken ? Number(body.pageToken.slice(5)) : 0;
		const responses = all.slice(page * size, (page + 1) * size);
		const more = (page + 1) * size < all.length;
		return response(
			url,
			200,
			JSON.stringify({
				responses,
				nextPageToken: more ? `page-${page + 1}` : "",
			}),
		);
	};

	return Layer.succeed(Http, {
		request: (url: string, init?: HttpRequest) =>
			Effect.sync(() => {
				calls.push({ url, init });
				const failure = options.fail?.(url);
				if (failure === "invalid-json") return response(url, 200, "{oops");
				if (failure !== undefined) return response(url, failure, "{}");
				if (url === "https://api.deps.dev/v3alpha/versionbatch")
					return batch(url, init, versionEntries, (r) =>
						Object.values(r.versionKey ?? {}).join("|"),
					);
				if (url === "https://api.deps.dev/v3alpha/projectbatch")
					return batch(
						url,
						init,
						projectEntries,
						(r) => r.projectKey?.id ?? "",
					);
				const m =
					/^https:\/\/api\.deps\.dev\/v3\/systems\/(\w+)\/packages\/([^/]+)$/.exec(
						url,
					);
				const body = m
					? packages.get(
							`package-${m[1]}-${decodeURIComponent(m[2] ?? "")}.json`,
						)
					: undefined;
				return body
					? response(url, 200, body)
					: response(url, 404, '{"code":5,"message":"package not found"}');
			}),
	});
};

const runHealth = async (
	calls: Call[],
	options: FakeOptions & {
		readonly settings?: Record<string, unknown>;
		readonly offline?: boolean;
	} = {},
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target: root,
			auditors: [dependencyHealth],
			options: {
				offline: options.offline,
				settings: options.settings
					? { [DEPENDENCY_HEALTH_ID]: options.settings }
					: undefined,
			},
			selection: { only: [DEPENDENCY_HEALTH_ID] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					await fakeDepsDev(calls, options),
					Exec.layer,
				),
			),
		),
	);

const summary = (report: Report) =>
	report.results
		.flatMap((r) => r.findings)
		.map(
			(f) =>
				`${f.ruleId.replace(`${DEPENDENCY_HEALTH_ID}/`, "")} ${f.evidence?.split(" ")[0]} ${f.severity}`,
		)
		.sort();

const urls = (calls: Call[]) =>
	calls.map((c) => c.url.replace("https://api.deps.dev", ""));

describe("code.dependency-health auditor", () => {
	test("is opt-in and needs the network", () => {
		expect(dependencyHealth.defaultEnabled).toBe(false);
		expect(dependencyHealth.network).toBe(true);
	});

	test("reports deprecated, yanked, archived and stale dependencies in a few batched requests", async () => {
		const calls: Call[] = [];
		const report = await runHealth(calls);
		expect(report.results[0]?.status).toBe("failed");
		expect(summary(report)).toEqual([
			"archived-repository github.com/mitchellh/go-homedir@1.1.0 medium",
			"deprecated-package github.com/golang/protobuf@1.5.4 medium",
			"deprecated-package inflight@1.0.6 medium",
			"deprecated-package left-pad@1.3.0 medium",
			"deprecated-package request@2.88.2 medium",
			"deprecated-package rimraf@3.0.2 low",
			"stale-package is-number@7.0.0 low",
			"yanked-release requests@2.32.0 medium",
			"yanked-release tokio@1.39.0 medium",
		]);
		// One page of versions, one page of projects (none for packages that are
		// deprecated outright), and package histories only where they matter.
		expect(urls(calls).sort()).toEqual([
			"/v3/systems/cargo/packages/tokio",
			"/v3/systems/npm/packages/is-number",
			"/v3/systems/npm/packages/rimraf",
			"/v3/systems/pypi/packages/requests",
			"/v3alpha/projectbatch",
			"/v3alpha/versionbatch",
		]);
		const projectsAsked = (
			JSON.parse(
				calls.find((c) => c.url.endsWith("/projectbatch"))?.init?.body ?? "{}",
			) as { requests: Array<{ projectKey: { id: string } }> }
		).requests.map((r) => r.projectKey.id);
		expect(projectsAsked.sort()).toEqual([
			"github.com/isaacs/rimraf",
			"github.com/jonschlinkert/is-number",
			"github.com/mitchellh/go-homedir",
			"github.com/pkg/errors",
			"github.com/psf/requests",
			"github.com/tokio-rs/tokio",
		]);
		// Go versions are sent with their `v` prefix.
		expect(
			calls.find((c) => c.url.endsWith("/versionbatch"))?.init?.body,
		).toContain('"version":"v1.5.4"');

		const findings = report.results.flatMap((r) => r.findings);
		const byEvidence = (prefix: string) =>
			findings.find((f) => f.evidence?.startsWith(prefix)) as Finding;

		const rimraf = byEvidence("rimraf@");
		expect(rimraf.remediation).toContain("6.1.3");
		expect(rimraf.location).toEqual({ file: "package-lock.json", line: 15 });
		expect(rimraf.tags).toEqual(["cwe-1104", "owasp-a06"]);

		const request = byEvidence("request@");
		expect(request.message).toContain(
			"request has been deprecated, see https://github.com/request/request/issues/3142",
		);
		expect(request.remediation).toContain("Replace");

		const requests = byEvidence("requests@");
		expect(requests.remediation).toContain("2.34.2");
		expect(requests.references).toContain("https://peps.python.org/pep-0592/");
		expect(requests.location).toEqual({ file: "requirements.txt", line: 1 });

		const homedir = byEvidence("github.com/mitchellh/go-homedir@");
		expect(homedir.confidence).toBe("medium");
		expect(homedir.location).toEqual({ file: "go.mod", line: 7 });
		expect(homedir.message).toContain("github.com/mitchellh/go-homedir");
	});

	test("follows deps.dev pagination", async () => {
		const calls: Call[] = [];
		const report = await runHealth(calls, { pageSize: 4 });
		expect(summary(report)).toHaveLength(9);
		const pages = calls.filter((c) => c.url.endsWith("/versionbatch"));
		expect(pages).toHaveLength(3);
		expect(JSON.parse(pages[2]?.init?.body ?? "{}").pageToken).toBe("page-2");
		expect(calls.filter((c) => c.url.endsWith("/projectbatch"))).toHaveLength(
			2,
		);
	});

	test("stops at the request budget and says what was not checked", async () => {
		const calls: Call[] = [];
		const report = await runHealth(calls, { settings: { maxRequests: 2 } });
		expect(calls).toHaveLength(2);
		expect(summary(report)).toEqual([
			"archived-repository github.com/mitchellh/go-homedir@1.1.0 medium",
			"deprecated-package github.com/golang/protobuf@1.5.4 medium",
			"deprecated-package inflight@1.0.6 medium",
			"deprecated-package left-pad@1.3.0 medium",
			"deprecated-package request@2.88.2 medium",
			"deprecated-package rimraf@3.0.2 low",
			"truncated 4 info",
			"yanked-release requests@2.32.0 medium",
			"yanked-release tokio@1.39.0 medium",
		]);
		const truncated = report.results[0]?.findings.find((f) =>
			f.ruleId.endsWith("/truncated"),
		);
		expect(truncated?.message).toContain("4 package histories");
		expect(truncated?.remediation).toContain("maxRequests");
		const rimraf = report.results[0]?.findings.find((f) =>
			f.evidence?.startsWith("rimraf@"),
		);
		expect(rimraf?.remediation).not.toContain("6.1.3");
	});

	test("keeps going when some lookups fail", async () => {
		const calls: Call[] = [];
		const report = await runHealth(calls, {
			fail: (url) =>
				url.endsWith("/projectbatch")
					? "invalid-json"
					: url.endsWith("/packages/rimraf")
						? 500
						: undefined,
		});
		expect(report.results[0]?.status).toBe("failed");
		const s = summary(report);
		// Without the archived flag, go-homedir becomes a stale candidate whose
		// history is missing from the fake (404).
		expect(s).toContain("lookup-failed 3 info");
		expect(s).toContain("deprecated-package rimraf@3.0.2 low");
		expect(s).toContain("stale-package is-number@7.0.0 low");
		expect(s.some((x) => x.startsWith("archived-repository"))).toBe(false);
		const failed = report.results[0]?.findings.find((f) =>
			f.ruleId.endsWith("/lookup-failed"),
		);
		expect(failed?.message).toContain(
			"/v3alpha/projectbatch returned invalid JSON",
		);
		expect(failed?.message).toContain(
			"/v3/systems/npm/packages/rimraf failed with HTTP 500",
		);
	});

	test("errors when deps.dev is unavailable instead of silently passing", async () => {
		const report = await runHealth([], { fail: () => 503 });
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("HTTP 503");
	});

	test("rejects invalid settings", async () => {
		const report = await runHealth([], { settings: { staleYears: "soon" } });
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("staleYears");
	});

	test("skips when offline without any request", async () => {
		const calls: Call[] = [];
		const report = await runHealth(calls, { offline: true });
		expect(report.results[0]?.status).toBe("skipped");
		expect(calls).toEqual([]);
	});

	test("never merges with a vulnerability finding on the same line", () => {
		const base = {
			category: "supply-chain" as const,
			location: { file: "package-lock.json", line: 37 },
			fingerprint: "",
		};
		const result = (auditor: string, finding: Partial<Finding>) =>
			({
				auditor,
				title: auditor,
				status: "failed",
				durationMs: 0,
				findings: [{ ...base, auditor, ...finding } as Finding],
			}) as unknown as AuditorResult;
		const [vuln, health] = correlate([
			result("code.dependencies", {
				ruleId: "code.dependencies/vulnerable-dependency",
				severity: "high",
				fingerprint: "a",
				tags: ["owasp-a06", "cwe-1333", "ghsa-c2qf-rxjj-qqgw"],
			}),
			result(DEPENDENCY_HEALTH_ID, {
				ruleId: `${DEPENDENCY_HEALTH_ID}/deprecated-package`,
				severity: "low",
				fingerprint: "b",
				tags: ["cwe-1104", "owasp-a06"],
			}),
		]);
		expect(vuln?.findings[0]?.alsoReportedBy).toBeUndefined();
		expect(health?.findings[0]?.duplicateOf).toBeUndefined();
	});
});
