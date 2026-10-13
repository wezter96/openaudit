import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import {
	Exec,
	type ExecOptions,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import {
	classifyRefs,
	parseSpectralOutput,
	spectral,
} from "../src/codebase/spectral";
import { fixture } from "./helpers";

const recorded: unknown = JSON.parse(
	readFileSync(fixture("api", "spectral", "spectral-output.json"), "utf8"),
);

interface Call {
	readonly cmd: ReadonlyArray<string>;
	readonly options: ExecOptions | undefined;
	readonly ruleset?: string;
}

const runSpectral = async (
	target: string,
	opts: {
		which?: string | undefined;
		stdout?: string;
		code?: number;
	} = {},
): Promise<{ report: Report; calls: Call[] }> => {
	const calls: Call[] = [];
	const report = await Effect.runPromise(
		runAudit({
			target,
			auditors: [spectral],
			selection: { only: [spectral.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: () =>
							Effect.succeed("which" in opts ? opts.which : "/bin/spectral"),
						run: (cmd: ReadonlyArray<string>, options?: ExecOptions) =>
							Effect.sync((): ExecResult => {
								const i = cmd.indexOf("--ruleset");
								calls.push({
									cmd,
									options,
									ruleset:
										i >= 0 && cmd[i + 1] && existsSync(cmd[i + 1] as string)
											? readFileSync(cmd[i + 1] as string, "utf8")
											: undefined,
								});
								return {
									code: opts.code ?? 0,
									stdout: opts.stdout ?? "[]",
									stderr: "",
								};
							}),
					}),
				),
			),
		),
	);
	return { report, calls };
};

describe("spectral parser", () => {
	test("maps recorded output to findings with 1-based lines", () => {
		const findings = parseSpectralOutput(recorded, "/repo");
		expect(findings.length).toBe(17);
		const invalid = findings.find(
			(f) => f.ruleId === "code.spectral/invalid-ref",
		);
		expect(invalid?.severity).toBe("medium");
		expect(invalid?.location).toEqual({ file: "bad.yaml", line: 9 });
		expect(invalid?.category).toBe("reliability");
		const contact = findings.find(
			(f) =>
				f.ruleId === "code.spectral/info-contact" &&
				f.location?.file === "openapi.yaml",
		);
		expect(contact?.severity).toBe("low");
		expect(contact?.location?.line).toBe(2);
		const latest = findings.find(
			(f) => f.ruleId === "code.spectral/asyncapi-latest-version",
		);
		expect(latest?.severity).toBe("info");
		expect(latest?.evidence).toBe("asyncapi-latest-version: asyncapi");
	});

	test("tolerates empty and unexpected shapes", () => {
		expect(parseSpectralOutput([], "/repo")).toEqual([]);
		expect(parseSpectralOutput(null, "/repo")).toEqual([]);
		expect(parseSpectralOutput([1, {}, { code: "x" }], "/repo").length).toBe(1);
	});
});

describe("spectral $ref guard", () => {
	test("local and in-project relative refs are fine", () => {
		expect(
			classifyRefs(
				"api/openapi.yaml",
				"a: {$ref: '#/x'}\nb: {$ref: './s.yaml#/y'}",
			),
		).toEqual({ kind: "ok", files: ["api/s.yaml"] });
	});

	test("remote, absolute and escaping refs are unsafe", () => {
		for (const ref of [
			"http://169.254.169.254/x",
			"https://evil.example/s.json",
			"file:///etc/passwd",
			"//evil.example/s",
			"/etc/passwd",
			"../../etc/passwd",
		]) {
			expect(classifyRefs("a/openapi.yaml", `$ref: "${ref}"`).kind).toBe(
				"unsafe",
			);
		}
		expect(classifyRefs("o.json", '{"$ref":"https://x.example/a"}').kind).toBe(
			"unsafe",
		);
	});
});

describe("code.spectral", () => {
	test("runs with our own ruleset from a temp cwd and never the project's", async () => {
		const { report, calls } = await runSpectral(
			fixture("api", "spectral-refs", "clean"),
			{
				stdout: JSON.stringify([
					{
						code: "info-contact",
						path: ["info"],
						message: "Info object must have contact",
						severity: 1,
						range: { start: { line: 1, character: 0 } },
						source: `${fixture("api", "spectral-refs", "clean")}/openapi.yaml`,
					},
				]),
			},
		);
		expect(calls.length).toBe(1);
		const call = calls[0];
		expect(call?.cmd.slice(0, 2)).toEqual(["/bin/spectral", "lint"]);
		expect(call?.cmd).toContain("--quiet");
		expect(call?.cmd).toContain("json");
		expect(call?.ruleset).toContain("spectral:oas");
		expect(call?.ruleset).toContain("spectral:asyncapi");
		const ruleset = call?.cmd[call.cmd.indexOf("--ruleset") + 1] ?? "";
		expect(ruleset.startsWith(fixture("api"))).toBe(false);
		expect(call?.options?.cwd).not.toContain("fixtures");
		expect(call?.options?.cwd).toContain("openaudit-spectral-");
		expect(existsSync(call?.options?.cwd ?? "")).toBe(false);
		expect(report.results[0]?.findings.map((f) => f.ruleId)).toEqual([
			"code.spectral/info-contact",
		]);
		expect(report.results[0]?.findings[0]?.location?.file).toBe("openapi.yaml");
	});

	test("does not lint documents with remote, transitive remote or escaping refs", async () => {
		for (const dir of ["remote", "transitive", "escape"]) {
			const { report, calls } = await runSpectral(
				fixture("api", "spectral-refs", dir),
			);
			expect(calls).toEqual([]);
			const findings = report.results[0]?.findings ?? [];
			expect(findings.map((f) => f.ruleId)).toEqual([
				"code.spectral/skipped-unsafe-ref",
			]);
			expect(findings[0]?.severity).toBe("info");
			expect(findings[0]?.location?.file).toBe("openapi.yaml");
		}
	});

	test("skips with an install hint when spectral is missing", async () => {
		const { report } = await runSpectral(fixture("api"), { which: undefined });
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain(
			"npm install -g @stoplight/spectral-cli",
		);
	});

	test("passes with no spec files and no tool invocation", async () => {
		const { report, calls } = await runSpectral(fixture("api", "rest"));
		expect(calls).toEqual([]);
		expect(report.results[0]?.findings).toEqual([]);
	});

	test("a crash (exit 2) is an error, not a pass", async () => {
		const { report } = await runSpectral(
			fixture("api", "spectral-refs", "clean"),
			{
				code: 2,
			},
		);
		expect(report.results[0]?.status).toBe("error");
	});
});
