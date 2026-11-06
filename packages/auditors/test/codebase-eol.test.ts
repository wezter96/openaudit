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
	assessDeclaration,
	cycleOf,
	EOL_API,
	EOL_ID,
	eol,
	findDeclarations,
	lowestVersion,
	oldestSupported,
	type Product,
	parseProduct,
} from "../src/codebase/eol";
import { fixture } from "./helpers";

// repo/ holds version files, manifests and lockfiles stored as `*.fixture`, so
// other scanners ignore them; api/ holds endoflife.date v1 responses recorded
// on 2026-11-06 (trimmed to the fields the auditor reads).
const FIXTURE_DIR = fixture("codebase", "eol");
const REPO_DIR = join(FIXTURE_DIR, "repo");
const API_DIR = join(FIXTURE_DIR, "api");
const NOW = Date.parse("2026-11-07T00:00:00Z");
let root = "";

const api = async (id: string): Promise<unknown> =>
	JSON.parse(await readFile(join(API_DIR, `${id}.json`), "utf8"));

const product = async (id: string): Promise<Product> => {
	const p = parseProduct(await api(id));
	if (!p) throw new Error(`no recorded product ${id}`);
	return p;
};

const repoFiles = async () =>
	Promise.all(
		(await readdir(REPO_DIR)).map(async (name) => ({
			path: name.slice(0, -".fixture".length),
			text: await readFile(join(REPO_DIR, name), "utf8"),
		})),
	);

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "openaudit-eol-"));
	await cp(REPO_DIR, root, { recursive: true });
	for (const name of await readdir(root))
		await rename(
			join(root, name),
			join(root, name.slice(0, -".fixture".length)),
		);
});

afterAll(() => rm(root, { recursive: true, force: true }));

describe("code.eol versions", () => {
	test("a range is judged by its lowest allowed version", () => {
		expect(lowestVersion(">=3.8,<4")).toBe("3.8");
		expect(lowestVersion("^7.4 || ^8.0")).toBe("7.4");
		expect(lowestVersion("~> 2.7")).toBe("2.7");
		expect(lowestVersion("<4, >=3.10")).toBe("3.10");
		expect(lowestVersion("*")).toBeUndefined();
	});

	test("endoflife.date products, cycles and the oldest supported release", async () => {
		const node = await product("nodejs");
		expect(node.label).toBe("Node.js");
		expect(node.link).toBe("https://endoflife.date/nodejs");
		expect(cycleOf(node, "16.20.2")?.name).toBe("16");
		expect(cycleOf(await product("python"), "3.10.4")?.name).toBe("3.10");
		expect(cycleOf(await product("ruby"), "2.0.0")?.name).toBe("2.0.0");
		expect(cycleOf(node, "99")).toBeUndefined();
		expect(oldestSupported(node, NOW)).toBe("22");
		expect(oldestSupported(await product("python"), NOW)).toBe("3.11");
		expect(parseProduct({ error: "not found" })).toBeUndefined();
	});
});

describe("code.eol declarations", () => {
	test("reads runtimes from version files and manifests, frameworks from lockfiles", async () => {
		const found = findDeclarations(await repoFiles())
			.map(
				(d) => `${d.file}:${d.line} ${d.product} ${d.version} ${d.confidence}`,
			)
			.sort();
		expect(found).toEqual([
			".java-version:1 eclipse-temurin 11 high",
			".nvmrc:1 nodejs 16.20.2 high",
			".tool-versions:2 python 3.9.18 high",
			".tool-versions:3 ruby 3.4.1 high",
			"App.csproj:3 dotnet 6.0 high",
			"App.csproj:3 dotnet 8.0 high",
			"Gemfile.lock:4 rails 6.1.7 high",
			"Gemfile:3 ruby 2.7 low",
			"composer.json:2 php 7.4 low",
			"composer.lock:2 laravel 9.52.16 high",
			"global.json:2 dotnet 6.0.100 high",
			"go.mod:3 go 1.21 medium",
			"go.mod:5 go 1.22.5 high",
			"mise.toml:2 nodejs 18 high",
			"package-lock.json:6 angular 15.2.0 high",
			"package-lock.json:7 nextjs 13.5.6 high",
			"package-lock.json:8 vue 2.7.16 high",
			"package.json:3 nodejs 14 low",
			"package.json:4 nodejs 20.11.0 high",
			"pom.xml:5 spring-boot 2.7.18 high",
			"pom.xml:8 eclipse-temurin 8 medium",
			"pyproject.toml:3 python 3.8 low",
			"requirements.txt:1 django 3.2.0 high",
		]);
	});

	test("flags past end-of-life cycles and ones ending within 90 days", async () => {
		const declarations = findDeclarations(await repoFiles());
		const findings = [];
		for (const d of declarations)
			findings.push(...assessDeclaration(d, await product(d.product), NOW));
		const summary = findings
			.map(
				(f) =>
					`${f.ruleId.replace(`${EOL_ID}/`, "")} ${f.location?.file} ${f.evidence} ${f.severity}`,
			)
			.sort();
		expect(summary).toEqual([
			"eol-soon App.csproj net8.0 low",
			"framework-eol Gemfile.lock rails@6.1.7 medium",
			"framework-eol composer.lock laravel/framework@9.52.16 medium",
			"framework-eol package-lock.json @angular/core@15.2.0 medium",
			"framework-eol package-lock.json next@13.5.6 medium",
			"framework-eol package-lock.json vue@2.7.16 medium",
			"framework-eol pom.xml 2.7.18 medium",
			"framework-eol requirements.txt django@3.2.0 medium",
			"runtime-eol .nvmrc v16.20.2 high",
			"runtime-eol .tool-versions 3.9.18 high",
			"runtime-eol App.csproj net6.0 high",
			"runtime-eol Gemfile ~> 2.7 medium",
			"runtime-eol composer.json ^7.4 || ^8.0 medium",
			"runtime-eol global.json 6.0.100 high",
			"runtime-eol go.mod 1.21 high",
			"runtime-eol go.mod 1.22.5 high",
			"runtime-eol mise.toml 18 high",
			"runtime-eol package.json 20.11.0 high",
			"runtime-eol package.json >=14 medium",
			"runtime-eol pyproject.toml >=3.8,<4 medium",
		]);
		const py = findings.find((f) => f.location?.file === "pyproject.toml");
		expect(py).toMatchObject({
			title: "Python 3.8 is end-of-life",
			confidence: "low",
			location: { file: "pyproject.toml", line: 3 },
			tags: ["cwe-1104"],
			references: ["https://endoflife.date/python"],
		});
		expect(py?.message).toContain("allows Python `>=3.8,<4` (lowest: 3.8)");
		expect(py?.message).toContain("2024-10-07");
		expect(py?.remediation).toContain("(3.11 or newer)");
	});
});

interface Call {
	readonly url: string;
}

/** Serves the recorded products; `fail` makes a request fail with a status. */
const fakeEolApi = (
	calls: Call[],
	fail?: (url: string) => number | undefined,
) =>
	Layer.succeed(Http, {
		request: (url: string, _init?: HttpRequest) =>
			Effect.promise(async () => {
				calls.push({ url });
				const id = url.slice(EOL_API.length + 1);
				const status = fail?.(url) ?? 200;
				const body =
					status === 200
						? await readFile(join(API_DIR, `${id}.json`), "utf8")
						: "{}";
				return {
					url,
					status,
					headers: new Headers(),
					cookies: [],
					body,
					bytes: body.length,
					redirected: false,
					ttfbMs: 1,
					totalMs: 1,
				};
			}),
	});

const runEol = (
	calls: Call[],
	options: {
		offline?: boolean;
		fail?: (url: string) => number | undefined;
	} = {},
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target: root,
			auditors: [eol],
			options: { offline: options.offline },
			selection: { only: [EOL_ID] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					fakeEolApi(calls, options.fail),
					Exec.layer,
				),
			),
		),
	);

describe("code.eol auditor", () => {
	test("is on by default and declares its network use", () => {
		expect(eol.defaultEnabled).toBeUndefined();
		expect(eol.network).toBe(true);
	});

	test("asks endoflife.date once per product", async () => {
		const calls: Call[] = [];
		const report = await runEol(calls);
		expect(calls.map((c) => c.url.slice(EOL_API.length + 1)).sort()).toEqual([
			"angular",
			"django",
			"dotnet",
			"eclipse-temurin",
			"go",
			"laravel",
			"nextjs",
			"nodejs",
			"php",
			"python",
			"rails",
			"ruby",
			"spring-boot",
			"vue",
		]);
		const ruleIds = report.results.flatMap((r) =>
			r.findings.map((f) => f.ruleId),
		);
		// Cycles already past end-of-life stay so, whatever today is.
		expect(ruleIds).toContain(`${EOL_ID}/runtime-eol`);
		expect(ruleIds).toContain(`${EOL_ID}/framework-eol`);
	});

	test("skips offline and when endoflife.date cannot be reached", async () => {
		const offline = await runEol([], { offline: true });
		expect(offline.results[0]?.status).toBe("skipped");
		const down = await runEol([], { fail: () => 503 });
		expect(down.results[0]?.status).toBe("skipped");
		expect(down.results[0]?.message ?? "").toContain(
			"endoflife.date could not be reached",
		);
	});
});
