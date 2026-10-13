import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { shellStrictMode, strictness } from "../src/codebase/strictness";
import { runAuditor } from "./helpers";

const audit = async (files: Record<string, string>) => {
	const dir = await mkdtemp(join(tmpdir(), "openaudit-strictness-"));
	try {
		for (const [name, body] of Object.entries(files)) {
			await mkdir(dirname(join(dir, name)), { recursive: true });
			await writeFile(join(dir, name), body);
		}
		const report = await runAuditor(strictness, dir);
		const result = report.results[0];
		return { result, findings: result?.findings ?? [] };
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

const ids = (findings: ReadonlyArray<{ ruleId: string }>) =>
	findings.map((f) => f.ruleId.replace("code.strictness/", "")).sort();

describe("code.strictness metadata", () => {
	test("is a default-on builtin", () => {
		expect(strictness.id).toBe("code.strictness");
		expect(strictness.engine).toBe("builtin");
		expect(strictness.defaultEnabled).toBe(true);
	});

	test("projects in other languages pass cleanly", async () => {
		const { result } = await audit({
			"index.ts": "export const x = 1;\n",
			"package.json": "{}",
		});
		expect(result?.status).toBe("passed");
		expect(result?.findings).toEqual([]);
	});
});

describe("rust", () => {
	test("flags a lax crate", async () => {
		const { findings } = await audit({
			"Cargo.toml":
				'[package]\nname = "a"\n\n[profile.release]\npanic = "abort"\n',
			"src/main.rs": `#![allow(clippy::all)]
// unsafe { not code }
fn main() {
    let s = "unsafe { in a string }";
    let _ = s;
    unsafe { core::hint::unreachable_unchecked() }
}
`,
		});
		expect(ids(findings)).toEqual([
			"rust-blanket-allow",
			"rust-no-lints-table",
			"rust-panic-abort",
			"rust-release-overflow-checks-off",
			"rust-unsafe-not-forbidden",
			"rust-unsafe-usage",
		]);
		const unsafeUse = findings.find((f) => f.ruleId.endsWith("unsafe-usage"));
		expect(unsafeUse?.title).toStartWith("1 unsafe block");
		expect(unsafeUse?.location).toEqual({ file: "src/main.rs", line: 6 });
		expect(unsafeUse?.severity).toBe("info");
		expect(findings.every((f) => ["info", "low"].includes(f.severity))).toBe(
			true,
		);
	});

	test("a strict crate is quiet", async () => {
		const { findings } = await audit({
			"Cargo.toml": `[package]
name = "a"

[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all = { level = "warn", priority = -1 }

[profile.release]
overflow-checks = true
`,
			"src/lib.rs": "pub fn f() {}\n",
		});
		expect(findings).toEqual([]);
	});

	test("workspace lints and crate-level forbid count", async () => {
		const { findings } = await audit({
			"Cargo.toml": `[workspace]
members = ["a"]

[workspace.lints.clippy]
pedantic = "warn"

[profile.release]
overflow-checks = true
`,
			"a/Cargo.toml": "[package]\nname='a'\n[lints]\nworkspace = true\n",
			"a/src/lib.rs": "#![forbid(unsafe_code)]\n",
		});
		expect(findings).toEqual([]);
	});

	test("widespread unsafe is low severity", async () => {
		const body = Array.from({ length: 12 }, () => "unsafe { f() }").join("\n");
		const { findings } = await audit({
			"Cargo.toml": "[package]\nname='a'\n",
			"src/lib.rs": `fn g() {\n${body}\n}\n`,
		});
		const u = findings.find((f) => f.ruleId.endsWith("unsafe-usage"));
		expect(u?.severity).toBe("low");
		expect(u?.title).toStartWith("12 unsafe");
	});
});

describe("python", () => {
	test("no type checker or linter", async () => {
		const { findings } = await audit({ "app.py": "x = 1\n" });
		expect(ids(findings)).toEqual([
			"python-no-linter-config",
			"python-no-type-checker",
		]);
		expect(findings[0]?.location?.file).toBe("app.py");
	});

	test("lenient mypy and basic pyright", async () => {
		const mypy = await audit({
			"app.py": "x = 1\n",
			"pyproject.toml": "[tool.mypy]\npython_version = '3.12'\n[tool.ruff]\n",
		});
		expect(ids(mypy.findings)).toEqual(["python-mypy-not-strict"]);
		const ini = await audit({
			"app.py": "x = 1\n",
			"mypy.ini": "[mypy]\nstrict = True\n",
			".flake8": "[flake8]\n",
		});
		expect(ini.findings).toEqual([]);
		const pyright = await audit({
			"app.py": "x = 1\n",
			"pyrightconfig.json": '{ "typeCheckingMode": "basic" }',
			"ruff.toml": "",
		});
		expect(ids(pyright.findings)).toEqual(["python-pyright-lenient"]);
		const off = await audit({
			"app.py": "x = 1\n",
			"pyproject.toml":
				'[tool.pyright]\ntypeCheckingMode = "off"\n[tool.pylint]\n',
		});
		expect(off.findings[0]?.severity).toBe("low");
	});

	test("setup.cfg sections and strict pyproject", async () => {
		const cfg = await audit({
			"app.py": "x = 1\n",
			"setup.cfg": "[mypy]\nstrict = true\n\n[flake8]\nmax-line-length = 100\n",
		});
		expect(cfg.findings).toEqual([]);
		const strict = await audit({
			"app.py": "x = 1\n",
			"pyproject.toml": "[tool.mypy]\nstrict = true\n[tool.ruff.lint]\n",
		});
		expect(strict.findings).toEqual([]);
		const based = await audit({
			"app.py": "x = 1\n",
			"pyproject.toml": "[tool.basedpyright]\n[tool.ruff]\n",
		});
		expect(based.findings).toEqual([]);
	});

	test("projects without Python are skipped silently", async () => {
		const { findings } = await audit({ "pyproject.toml": "[tool.mypy]\n" });
		expect(findings).toEqual([]);
	});
});

describe("go", () => {
	test("no golangci config and nolint usage", async () => {
		const lines = Array.from(
			{ length: 11 },
			(_, i) => `\t_ = f${i}() //nolint`,
		);
		const { findings } = await audit({
			"go.mod": "module a\n",
			"main.go": `package main\n\nfunc main() {\n${lines.join("\n")}\n\t_ = g() //nolint:errcheck // ok\n}\n`,
		});
		expect(ids(findings)).toEqual([
			"go-blanket-nolint",
			"go-no-golangci-config",
			"go-nolint-density",
		]);
		const density = findings.find((f) => f.ruleId.endsWith("density"));
		expect(density?.title).toBe("12 //nolint directives");
		expect(density?.location).toEqual({ file: "main.go", line: 4 });
		const blanket = findings.find((f) => f.ruleId.endsWith("blanket-nolint"));
		expect(blanket?.title).toBe("11 blanket //nolint directives");
	});

	test("configured and clean", async () => {
		const { findings } = await audit({
			"go.mod": "module a\n",
			".golangci.yml": "version: '2'\n",
			"main.go": "package main\n\nfunc main() {} //nolint:unused // later\n",
		});
		expect(findings).toEqual([]);
	});
});

describe("shell", () => {
	const script = (head: string) =>
		`${head}\nname=$1\necho "$name"\ncd /tmp\nls\n`;

	test("flags scripts without strict mode, with low confidence", async () => {
		const { findings } = await audit({
			"deploy.sh": script("#!/bin/bash"),
			"bin/run": script("#!/bin/sh"),
			"ok.sh": script("#!/bin/bash\nset -euo pipefail"),
			"posix.sh": script("#!/bin/sh\nset -eu"),
			"long.sh": script(
				"#!/usr/bin/env bash\nset -o errexit -o nounset -o pipefail",
			),
			"tiny.sh": "#!/bin/sh\necho hi\n",
			"zsh.sh": script("#!/bin/zsh"),
			"comment.sh": script("#!/bin/bash\n# set -euo pipefail"),
		});
		expect(findings.map((f) => f.location?.file).sort()).toEqual([
			"bin/run",
			"comment.sh",
			"deploy.sh",
		]);
		for (const f of findings) {
			expect(f.ruleId).toBe("code.strictness/shell-missing-strict-mode");
			expect(f.severity).toBe("low");
			expect(f.confidence).toBe("low");
		}
		expect(
			findings.find((f) => f.location?.file === "bin/run")?.title,
		).toContain("set -eu`");
	});

	test("shellStrictMode reads flags", () => {
		expect(shellStrictMode("set -euo pipefail\n")).toEqual({
			errexit: true,
			nounset: true,
			pipefail: true,
		});
		expect(shellStrictMode("set -e\nset -o pipefail\n")).toEqual({
			errexit: true,
			nounset: false,
			pipefail: true,
		});
		expect(shellStrictMode("# set -e\necho set -e\n")).toEqual({
			errexit: false,
			nounset: false,
			pipefail: false,
		});
	});
});
