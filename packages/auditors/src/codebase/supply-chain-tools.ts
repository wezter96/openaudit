import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import {
	type AuditContext,
	type Auditor,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, cweTags, num, parseJson, severityOf, str } from "../tool";
import {
	type OsvVuln,
	osvSeverity,
	parseBunLock,
	severityFromScore,
} from "./dependencies";
import { isRecord, kebab, truncate } from "./util";

/**
 * Supply-chain wrappers: vulnerable dependencies (govulncheck, pip-audit,
 * cargo-audit, npm/pnpm/bun audit, grype), licences (syft) and repository
 * posture (OpenSSF Scorecard).
 *
 * Safety: none of these installs or builds the target. The package-manager
 * audits read lockfiles only, pip-audit only sees a sanitised `name==version`
 * file we write ourselves, and syft/grype run from a scratch directory so a
 * hostile `.syft.yaml` / `.grype.yaml` in the target is never picked up.
 */

/* -------------------------------------------------------------------------- */
/*                                   Shared                                   */
/* -------------------------------------------------------------------------- */

const MAX_ROOTS = 5;
const NPM_REGISTRY = "https://registry.npmjs.org/";

const STEPS: ReadonlyArray<Severity> = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
];
/** `steps` levels less severe (floored at info). */
const lower = (sev: Severity, steps = 1): Severity =>
	STEPS[Math.min(STEPS.indexOf(sev) + steps, STEPS.length - 1)] ?? "info";

const dirOf = (path: string) =>
	path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
const joinRel = (dir: string, file: string) => (dir ? `${dir}/${file}` : file);
const baseOf = (path: string) => path.slice(path.lastIndexOf("/") + 1);
const depth = (path: string) => path.split("/").length;

/** Workspace files matching `test`, shallowest first, capped. */
const findFiles = (
	ctx: AuditContext,
	test: (path: string) => boolean,
	max = MAX_ROOTS,
) =>
	Effect.gen(function* () {
		const ws = yield* requireWorkspace(ctx);
		const files = yield* ws.files;
		return files
			.filter(test)
			.sort((a, b) => depth(a) - depth(b) || a.localeCompare(b))
			.slice(0, max);
	});

/** Runs `fn` with a scratch directory that is always removed afterwards. */
const withTempDir = <A, E>(
	fn: (dir: string) => Effect.Effect<A, E>,
): Effect.Effect<A, E | AuditorError> =>
	Effect.acquireUseRelease(
		Effect.tryPromise({
			try: () => mkdtemp(join(tmpdir(), "openaudit-sc-")),
			catch: (cause) =>
				new AuditorError({ message: "Could not create temp dir", cause }),
		}),
		fn,
		(dir) => Effect.promise(() => rm(dir, { recursive: true, force: true })),
	);

/** Runs a tool; fails with its stderr unless the exit code is in `okCodes`. */
const run = (
	ctx: AuditContext,
	cmd: ReadonlyArray<string>,
	opts: {
		cwd: string;
		okCodes: ReadonlyArray<number>;
		env?: Record<string, string>;
	},
) =>
	Effect.flatMap(
		ctx.exec.run(cmd, {
			cwd: opts.cwd,
			timeoutMs: 15 * 60_000,
			env: opts.env,
		}),
		(res) =>
			opts.okCodes.includes(res.code)
				? Effect.succeed(res)
				: Effect.fail(
						new AuditorError({
							message: `${baseOf(cmd[0] ?? "tool")} exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
						}),
					),
	);

const advisoryTags = (ids: ReadonlyArray<string>) =>
	ids.filter((a) => /^(CVE|GHSA)-/i.test(a)).map((a) => a.toLowerCase());

/** `<4.17.21` / `>=1.0.0 <1.2.3` → `4.17.21` / `1.2.3`; `<=` has no fix. */
const fixedFromRange = (range: string | undefined): string | undefined => {
	const m = range ? /<\s*(\d[^\s|]*)\s*$/.exec(range.trim()) : null;
	return m?.[1];
};
/** Patched ranges such as `>=1.2.3` → `1.2.3`. */
const fixedFromPatched = (patched: string | undefined): string | undefined => {
	const m = patched ? /^>=\s*(\d\S*)/.exec(patched.trim()) : null;
	return m?.[1];
};
const ghsaOf = (url: string | undefined) =>
	url ? /GHSA(?:-[a-z0-9]{4}){3}/i.exec(url)?.[0] : undefined;

interface VulnInput {
	readonly auditor: string;
	readonly name: string;
	readonly version?: string;
	readonly ecosystem?: string;
	readonly id: string;
	readonly aliases?: ReadonlyArray<string>;
	readonly summary: string;
	readonly severity: Severity;
	readonly fixed: ReadonlyArray<string>;
	/** Used instead of the "no fix" sentence when `fixed` is empty. */
	readonly fixHint?: string;
	readonly file?: string;
	readonly line?: number;
	readonly references: ReadonlyArray<string>;
	readonly confidence?: FindingInput["confidence"];
	readonly note?: string;
	readonly tags?: ReadonlyArray<string>;
}

/** One finding in the shape of `code.osv-scanner`'s vulnerable-dependency. */
const vulnFinding = (v: VulnInput): FindingInput => {
	const aliases = [...new Set(v.aliases ?? [])].filter((a) => a !== v.id);
	const at = v.version ? `${v.name}@${v.version}` : v.name;
	return {
		ruleId: `${v.auditor}/vulnerable-dependency`,
		title: `${at}: ${v.summary}`,
		severity: v.severity,
		category: "supply-chain",
		message: `${v.name}${v.version ? ` ${v.version}` : ""}${v.ecosystem ? ` (${v.ecosystem})` : ""} is affected by ${v.id}${aliases.length ? ` (${aliases.slice(0, 3).join(", ")})` : ""}.${v.note ? ` ${v.note}` : ""}`,
		location: { file: v.file, line: v.line },
		evidence: `${at} ${v.id}`,
		remediation: v.fixed.length
			? `Upgrade ${v.name} to ${[...new Set(v.fixed)].join(" or ")} or later.`
			: (v.fixHint ??
				`No fixed version is published for ${v.name}; consider replacing it or mitigating per the advisory.`),
		references: [...new Set(v.references)],
		confidence: v.confidence ?? "high",
		tags: [
			...new Set([
				"owasp-a06",
				...advisoryTags([v.id, ...aliases]),
				...(v.tags ?? []),
			]),
		],
	};
};

const osvUrl = (id: string) => `https://osv.dev/vulnerability/${id}`;

/** Path as reported by scanners that root their output at `/`. */
const scanPath = (root: string, file: string | undefined) => {
	if (!file) return undefined;
	if (isAbsolute(file) && file.startsWith(root))
		return relative(root, file).split("\\").join("/");
	return file.replace(/^\.?\/+/, "");
};

/* -------------------------------------------------------------------------- */
/*                                 govulncheck                                */
/* -------------------------------------------------------------------------- */

/** Splits a stream of concatenated JSON objects (govulncheck's output). */
export const splitJsonStream = (text: string): unknown[] => {
	const out: unknown[] = [];
	let level = 0;
	let start = -1;
	let inString = false;
	let escaped = false;
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (inString) {
			if (escaped) escaped = false;
			else if (c === "\\") escaped = true;
			else if (c === '"') inString = false;
		} else if (level > 0 && c === '"') {
			inString = true;
		} else if (c === "{") {
			if (level === 0) start = i;
			level++;
		} else if (c === "}" && level > 0) {
			level--;
			if (level === 0 && start >= 0) {
				try {
					out.push(JSON.parse(text.slice(start, i + 1)));
				} catch {
					// Truncated or corrupt message: skip it.
				}
				start = -1;
			}
		}
	}
	return out;
};

type GoLevel = "module" | "package" | "symbol";
const GO_LEVELS: ReadonlyArray<GoLevel> = ["module", "package", "symbol"];

interface GoFinding {
	readonly level: GoLevel;
	readonly osv: string;
	readonly fixed?: string;
	readonly module: string;
	readonly version?: string;
	readonly pkg?: string;
	readonly fn?: string;
	/** Where the main module reaches the vulnerable symbol. */
	readonly caller?: { file?: string; line?: number; fn?: string };
}

const goFinding = (raw: Record<string, unknown>): GoFinding | undefined => {
	const osv = str(raw.osv);
	const trace = arr(raw.trace).filter(isRecord);
	const top = trace[0];
	if (!osv || !top) return undefined;
	const level: GoLevel = str(top.function)
		? "symbol"
		: str(top.package)
			? "package"
			: "module";
	// The last frame is the entry point in the user's own module.
	const entry = [...trace].reverse().find((f) => isRecord(f.position));
	const pos = isRecord(entry?.position) ? entry.position : undefined;
	return {
		level,
		osv,
		fixed: str(raw.fixed_version),
		module: str(top.module) ?? "unknown",
		version: str(top.version),
		pkg: str(top.package),
		fn: str(top.function)
			? `${str(top.receiver) ? `${str(top.receiver)}.` : ""}${str(top.function)}`
			: undefined,
		caller: pos
			? {
					file: str(pos.filename),
					line: num(pos.line),
					fn: str(entry?.function),
				}
			: undefined,
	};
};

/**
 * Parses `govulncheck -format json` (a stream of `config`/`osv`/`finding`
 * messages). Symbol-level findings (the vulnerable function is reachable) are
 * high-confidence; module/package-level ones are imported-but-not-called, so
 * they are reported one severity step lower with low confidence.
 */
export const parseGovulncheckReport = (
	stdout: string,
	_root: string,
	moduleDir = "",
): FindingInput[] => {
	const osvs = new Map<string, OsvVuln>();
	const best = new Map<string, GoFinding>();
	for (const msg of splitJsonStream(stdout)) {
		if (!isRecord(msg)) continue;
		if (isRecord(msg.osv) && typeof msg.osv.id === "string") {
			osvs.set(msg.osv.id, msg.osv as unknown as OsvVuln);
		} else if (isRecord(msg.finding)) {
			const f = goFinding(msg.finding);
			if (!f) continue;
			const key = `${f.osv}|${f.module}`;
			const prev = best.get(key);
			if (!prev || GO_LEVELS.indexOf(f.level) > GO_LEVELS.indexOf(prev.level))
				best.set(key, f);
		}
	}
	const goMod = joinRel(moduleDir, "go.mod");
	return [...best.values()].map((f) => {
		const vuln = osvs.get(f.osv);
		const reachable = f.level === "symbol";
		const base = vuln ? osvSeverity(vuln) : "medium";
		const callerFile =
			f.caller?.file && reachable
				? joinRel(moduleDir, f.caller.file)
				: undefined;
		const stdlib = f.module === "stdlib";
		const where = f.pkg ?? f.module;
		const note = reachable
			? `Your code calls ${f.pkg}.${f.fn}${f.caller?.fn ? ` (from ${f.caller.fn})` : ""}, so the vulnerable code is reachable.`
			: f.level === "package"
				? `${where} is imported but the vulnerable function is not called by your code.`
				: `${f.module} is required but its vulnerable packages are not imported or called by your code.`;
		const fixed = f.fixed?.replace(/^v/, "");
		const finding = vulnFinding({
			auditor: "code.govulncheck",
			name: f.module,
			version: f.version,
			ecosystem: "Go",
			id: f.osv,
			aliases: vuln?.aliases,
			summary: vuln?.summary ?? f.osv,
			severity: reachable ? base : lower(base),
			fixed: fixed ? [f.fixed ?? fixed] : [],
			fixHint: stdlib
				? "Upgrade the Go toolchain to a release containing the fix."
				: undefined,
			file: callerFile ?? goMod,
			line: callerFile ? f.caller?.line : undefined,
			references: [
				`https://pkg.go.dev/vuln/${f.osv}`,
				...(vuln?.aliases ?? [])
					.filter((a) => a.startsWith("GHSA-"))
					.map(osvUrl),
			],
			confidence: reachable ? "high" : "low",
			note,
			tags: [reachable ? "reachable" : "not-called"],
		});
		return finding;
	});
};

export const govulncheck = defineAuditor({
	id: "code.govulncheck",
	title: "govulncheck (Go vulnerabilities)",
	description:
		"Runs govulncheck over each Go module. Findings whose vulnerable function is actually called are high-confidence; imported-but-not-called ones are low-confidence and one severity lower. govulncheck loads packages with the Go toolchain (no code is executed, cgo is disabled, toolchain downloads are blocked), so it is opt-in.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "govulncheck",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const mods = yield* findFiles(ctx, (p) => baseOf(p) === "go.mod");
			if (!mods.length) return yield* skip("No go.mod found");
			const bin = yield* requireTool(
				ctx,
				"govulncheck",
				"Install: go install golang.org/x/vuln/cmd/govulncheck@latest.",
			);
			const findings: FindingInput[] = [];
			for (const mod of mods) {
				const dir = dirOf(mod);
				// Exit 0 even with findings in JSON mode; 3 = vulnerabilities (text mode).
				const res = yield* run(ctx, [bin, "-format", "json", "./..."], {
					cwd: ws.absolute(dir || "."),
					okCodes: [0, 3],
					env: { GOTOOLCHAIN: "local", CGO_ENABLED: "0" },
				});
				findings.push(...parseGovulncheckReport(res.stdout, ws.root, dir));
			}
			return findings;
		}),
});

/* -------------------------------------------------------------------------- */
/*                                  pip-audit                                 */
/* -------------------------------------------------------------------------- */

export interface PinnedRequirements {
	/** `name[extras]==version` lines (markers, hashes and options dropped). */
	readonly pins: ReadonlyArray<string>;
	/** Reasons the file is not fully pinned; empty when it is. */
	readonly unpinned: ReadonlyArray<string>;
}

const PIN =
	/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._!+-]*)$/;
// Options that make a file depend on something we do not audit.
const INCLUDE_OPTION = /^(-r|--requirement|-c|--constraint|-e|--editable)\b/;

/** Extracts exact pins from a requirements.txt without resolving anything. */
export const parseRequirementsPins = (text: string): PinnedRequirements => {
	const pins: string[] = [];
	const unpinned: string[] = [];
	const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
	for (const raw of lines) {
		const line = raw.replace(/(^|\s)#.*$/, "").trim();
		if (!line) continue;
		if (line.startsWith("-")) {
			if (INCLUDE_OPTION.test(line))
				unpinned.push(
					`${line.split(/\s+/)[0]} includes other files or editable installs`,
				);
			continue; // --hash, --index-url, ...: irrelevant to which versions are pinned
		}
		const req = line
			.replace(/\s+--[\w-]+(=\S+|\s+\S+)?/g, "")
			.split(";")[0]
			?.trim();
		const m = req ? PIN.exec(req) : null;
		if (m?.[1] && m[3]) pins.push(`${m[1]}${m[2] ?? ""}==${m[3]}`);
		else unpinned.push(truncate(line, 60));
	}
	return { pins, unpinned };
};

/** Exact pins from a `poetry.lock`. */
export const parsePoetryLockPins = (text: string): PinnedRequirements => ({
	pins: [
		...text.matchAll(
			/\[\[package\]\]\s*\r?\nname = "([^"]+)"\s*\r?\nversion = "([^"]+)"/g,
		),
	].map((m) => `${m[1]}==${m[2]}`),
	unpinned: [],
});

/** Exact pins from a `Pipfile.lock` (`default` and `develop`). */
export const parsePipfileLockPins = (text: string): PinnedRequirements => {
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		return { pins: [], unpinned: ["Pipfile.lock is not valid JSON"] };
	}
	const pins: string[] = [];
	if (isRecord(json))
		for (const section of ["default", "develop"]) {
			const deps = json[section];
			if (!isRecord(deps)) continue;
			for (const [name, spec] of Object.entries(deps)) {
				const version = isRecord(spec) ? str(spec.version) : undefined;
				if (version && /^===?\d/.test(version))
					pins.push(`${name}==${version.replace(/^===?/, "")}`);
			}
		}
	return { pins, unpinned: [] };
};

/** Parses `pip-audit --format json`. */
export const parsePipAuditReport = (
	json: unknown,
	_root: string,
	file?: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const d of arr(json.dependencies)) {
		if (!isRecord(d) || str(d.skip_reason)) continue;
		const name = str(d.name) ?? "unknown";
		const version = str(d.version);
		const seen = new Set<string>();
		for (const v of arr(d.vulns)) {
			if (!isRecord(v)) continue;
			const id = str(v.id);
			if (!id || seen.has(id)) continue; // pip-audit repeats advisories
			seen.add(id);
			const aliases = arr(v.aliases).filter(
				(a): a is string => typeof a === "string",
			);
			const description = (str(v.description) ?? "")
				.replace(/\s+/g, " ")
				.trim();
			const first = /^(.{20,160}?[.!?])(\s|$)/.exec(description)?.[1];
			// pip-audit carries no severity; medium is the neutral default.
			findings.push(
				vulnFinding({
					auditor: "code.pip-audit",
					name,
					version,
					ecosystem: "PyPI",
					id,
					aliases,
					summary: first ?? (truncate(description, 120) || id),
					severity: "medium",
					fixed: arr(v.fix_versions).filter(
						(x): x is string => typeof x === "string",
					),
					file,
					references: [
						osvUrl(id),
						...aliases.filter((a) => a.startsWith("GHSA-")).map(osvUrl),
					],
				}),
			);
		}
	}
	return findings;
};

const isPyRequirements = (p: string) =>
	/(^|\/)requirements[^/]*\.txt$/i.test(p) ||
	/(^|\/)requirements\/[^/]+\.txt$/i.test(p);
const PY_LOCKS = new Set(["poetry.lock", "Pipfile.lock"]);

export const pipAudit = defineAuditor({
	id: "code.pip-audit",
	title: "pip-audit (Python vulnerabilities)",
	description:
		"Audits exactly pinned Python requirements (requirements*.txt, poetry.lock, Pipfile.lock) with pip-audit. Pins are rewritten into a temporary name==version file and audited with --no-deps --disable-pip, so nothing is resolved, downloaded or installed and no build script runs. Files that are not fully pinned are skipped.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "pip-audit",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* findFiles(
				ctx,
				(p) => isPyRequirements(p) || PY_LOCKS.has(baseOf(p)),
			);
			if (!files.length) {
				const hasPyproject = (yield* ws.files).some(
					(p) => baseOf(p) === "pyproject.toml",
				);
				return yield* skip(
					hasPyproject
						? "pyproject.toml has no pinned requirements; commit a poetry.lock or a pinned requirements.txt to audit it"
						: "No requirements*.txt, poetry.lock or Pipfile.lock found",
				);
			}
			const bin = yield* requireTool(
				ctx,
				"pip-audit",
				"Install: pipx install pip-audit (or uv tool install pip-audit).",
			);
			const findings: FindingInput[] = [];
			const skipped: string[] = [];
			for (const file of files) {
				const text = yield* ws.readText(file);
				const base = baseOf(file);
				const parsed =
					base === "poetry.lock"
						? parsePoetryLockPins(text)
						: base === "Pipfile.lock"
							? parsePipfileLockPins(text)
							: parseRequirementsPins(text);
				if (parsed.unpinned.length || !parsed.pins.length) {
					skipped.push(
						`${file}: ${parsed.unpinned[0] ?? "no pinned packages"}`,
					);
					continue;
				}
				const out = yield* withTempDir((dir) =>
					Effect.gen(function* () {
						const req = join(dir, "requirements.txt");
						yield* Effect.tryPromise({
							try: () => writeFile(req, `${parsed.pins.join("\n")}\n`),
							catch: (cause) =>
								new AuditorError({ message: "Could not write pins", cause }),
						});
						// Exit 1 = vulnerabilities found.
						return yield* run(
							ctx,
							[
								bin,
								"-r",
								req,
								"--no-deps",
								"--disable-pip",
								"--format",
								"json",
								"--progress-spinner",
								"off",
							],
							{ cwd: dir, okCodes: [0, 1] },
						);
					}),
				);
				if (!out.stdout.trim())
					return yield* Effect.fail(
						new AuditorError({
							message: `pip-audit produced no output: ${truncate(out.stderr, 300)}`,
						}),
					);
				findings.push(
					...parsePipAuditReport(
						yield* parseJson(out.stdout, "pip-audit"),
						ws.root,
						file,
					),
				);
			}
			if (skipped.length === files.length)
				return yield* skip(
					`Not fully pinned, nothing audited (${skipped.join("; ")})`,
				);
			return findings;
		}),
});

/* -------------------------------------------------------------------------- */
/*                                 cargo-audit                                */
/* -------------------------------------------------------------------------- */

const CARGO_WARNINGS: Record<
	string,
	{ rule: string; severity: Severity; label: string }
> = {
	unmaintained: {
		rule: "unmaintained-dependency",
		severity: "low",
		label: "is unmaintained",
	},
	unsound: {
		rule: "unsound-dependency",
		severity: "medium",
		label: "has a soundness issue",
	},
	yanked: {
		rule: "yanked-dependency",
		severity: "low",
		label: "was yanked from crates.io",
	},
	notice: {
		rule: "advisory-notice",
		severity: "low",
		label: "has an advisory notice",
	},
};

/** Parses `cargo-audit audit --json`. */
export const parseCargoAuditReport = (
	json: unknown,
	_root: string,
	file = "Cargo.lock",
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const vulns = isRecord(json.vulnerabilities) ? json.vulnerabilities : {};
	for (const item of arr(vulns.list)) {
		if (!isRecord(item)) continue;
		const advisory = isRecord(item.advisory) ? item.advisory : {};
		const pkg = isRecord(item.package) ? item.package : {};
		const versions = isRecord(item.versions) ? item.versions : {};
		const id = str(advisory.id) ?? "unknown";
		const cvss = str(advisory.cvss);
		const severity = cvss
			? osvSeverity({ id, severity: [{ type: "CVSS_V3", score: cvss }] })
			: "medium";
		const url = str(advisory.url);
		findings.push(
			vulnFinding({
				auditor: "code.cargo-audit",
				name: str(pkg.name) ?? "unknown",
				version: str(pkg.version),
				ecosystem: "crates.io",
				id,
				aliases: arr(advisory.aliases).filter(
					(a): a is string => typeof a === "string",
				),
				summary: str(advisory.title) ?? id,
				severity,
				fixed: arr(versions.patched)
					.filter((p): p is string => typeof p === "string")
					.map((p) => fixedFromPatched(p) ?? p),
				file,
				references: [
					`https://rustsec.org/advisories/${id}.html`,
					...(url ? [url] : []),
				],
			}),
		);
	}
	const warnings = isRecord(json.warnings) ? json.warnings : {};
	for (const [kind, list] of Object.entries(warnings)) {
		const meta = CARGO_WARNINGS[kind] ?? CARGO_WARNINGS.notice;
		if (!meta) continue;
		for (const w of arr(list)) {
			if (!isRecord(w)) continue;
			const pkg = isRecord(w.package) ? w.package : {};
			const advisory = isRecord(w.advisory) ? w.advisory : {};
			const name = str(pkg.name) ?? "unknown";
			const version = str(pkg.version);
			const id = str(advisory.id);
			const at = version ? `${name}@${version}` : name;
			findings.push({
				ruleId: `code.cargo-audit/${meta.rule}`,
				title: `${at}: ${str(advisory.title) ?? meta.label}`,
				severity: meta.severity,
				category: "supply-chain",
				message: `${at} ${meta.label}${id ? ` (${id})` : ""}.`,
				location: { file },
				evidence: id ? `${at} ${id}` : at,
				remediation: `Replace or upgrade ${name}; see the advisory for maintained alternatives.`,
				references: id ? [`https://rustsec.org/advisories/${id}.html`] : [],
				confidence: "high",
				tags: [
					"owasp-a06",
					...advisoryTags([
						id ?? "",
						...arr(advisory.aliases).filter(
							(a): a is string => typeof a === "string",
						),
					]),
				],
			});
		}
	}
	return findings;
};

export const cargoAudit = defineAuditor({
	id: "code.cargo-audit",
	title: "cargo-audit (Rust advisories)",
	description:
		"Checks Cargo.lock against the RustSec advisory database with cargo-audit. Reads the lockfile only; nothing is compiled or fetched from the project.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "cargo-audit",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const locks = yield* findFiles(ctx, (p) => baseOf(p) === "Cargo.lock");
			if (!locks.length) return yield* skip("No Cargo.lock found");
			const bin = yield* requireTool(
				ctx,
				"cargo-audit",
				"Install: cargo install cargo-audit --locked (or brew install cargo-audit).",
			);
			const findings: FindingInput[] = [];
			for (const lock of locks) {
				// Exit 1 = vulnerabilities found.
				const res = yield* run(
					ctx,
					[bin, "audit", "--json", "-f", ws.absolute(lock)],
					{ cwd: ws.root, okCodes: [0, 1] },
				);
				findings.push(
					...parseCargoAuditReport(
						yield* parseJson(res.stdout, "cargo-audit"),
						ws.root,
						lock,
					),
				);
			}
			return findings;
		}),
});

/* -------------------------------------------------------------------------- */
/*                    npm / pnpm / bun audit (lockfile only)                  */
/* -------------------------------------------------------------------------- */

export interface LockText {
	readonly file: string;
	readonly text: string;
}

const errorMessage = (json: unknown): string | undefined => {
	if (!isRecord(json) || !isRecord(json.error)) return undefined;
	return (
		str(json.error.summary) ??
		str(json.error.message) ??
		str(json.error.detail) ??
		str(json.error.code) ??
		"audit failed"
	);
};

const jsRefs = (url: string | undefined, id?: string) => [
	...(url ? [url] : []),
	...(id ? [osvUrl(id)] : []),
];

/** Parses `npm audit --json` (npm v7+: `vulnerabilities` map with `via`). */
export const parseNpmAuditReport = (
	json: unknown,
	_root: string,
	lock?: LockText,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.vulnerabilities)) return [];
	let packages: Record<string, unknown> = {};
	try {
		const parsed: unknown = lock ? JSON.parse(lock.text) : undefined;
		if (isRecord(parsed) && isRecord(parsed.packages))
			packages = parsed.packages;
	} catch {
		// Versions are optional.
	}
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const [key, entry] of Object.entries(json.vulnerabilities)) {
		if (!isRecord(entry)) continue;
		const node = str(arr(entry.nodes)[0]);
		const locked = node ? packages[node] : undefined;
		const version = isRecord(locked) ? str(locked.version) : undefined;
		const fa = entry.fixAvailable;
		for (const via of arr(entry.via)) {
			// String entries only name another vulnerable package (reported on its own).
			if (!isRecord(via)) continue;
			const name = str(via.name) ?? key;
			const url = str(via.url);
			const id = ghsaOf(url) ?? String(via.source ?? url ?? "unknown");
			const dedupe = `${name}|${id}`;
			if (seen.has(dedupe)) continue;
			seen.add(dedupe);
			const fixed = fixedFromRange(str(via.range));
			const cwes = arr(via.cwe).filter(
				(c): c is string => typeof c === "string",
			);
			findings.push(
				vulnFinding({
					auditor: "code.npm-audit",
					name,
					version,
					ecosystem: "npm",
					id,
					summary: str(via.title) ?? id,
					severity: severityOf(via.severity),
					fixed: fixed ? [fixed] : [],
					fixHint: isRecord(fa)
						? `Upgrade ${str(fa.name) ?? name} to ${str(fa.version) ?? "the latest version"} (npm audit fix${fa.isSemVerMajor ? " --force, a breaking change" : ""}).`
						: fa === true
							? "Run npm audit fix to update to a patched version."
							: undefined,
					file: lock?.file,
					references: jsRefs(url),
					tags: cweTags(cwes),
				}),
			);
		}
	}
	return findings;
};

/** Parses `pnpm audit --json` (legacy `advisories` map). */
export const parsePnpmAuditReport = (
	json: unknown,
	_root: string,
	file?: string,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.advisories)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const adv of Object.values(json.advisories)) {
		if (!isRecord(adv)) continue;
		const name = str(adv.module_name) ?? "unknown";
		const url = str(adv.url);
		const id =
			str(adv.github_advisory_id) ?? ghsaOf(url) ?? String(adv.id ?? "unknown");
		const cves = arr(adv.cves).filter(
			(c): c is string => typeof c === "string",
		);
		const cwes = arr(adv.cwe).filter((c): c is string => typeof c === "string");
		const fixed = fixedFromPatched(str(adv.patched_versions));
		const versions = [
			...new Set(
				arr(adv.findings)
					.filter(isRecord)
					.map((f) => str(f.version))
					.filter((v): v is string => !!v),
			),
		];
		for (const version of versions.length ? versions : [undefined]) {
			const dedupe = `${name}|${id}|${version}`;
			if (seen.has(dedupe)) continue;
			seen.add(dedupe);
			findings.push(
				vulnFinding({
					auditor: "code.pnpm-audit",
					name,
					version,
					ecosystem: "npm",
					id,
					aliases: cves,
					summary: str(adv.title) ?? id,
					severity: severityOf(adv.severity),
					fixed: fixed ? [fixed] : [],
					file,
					references: jsRefs(url),
					tags: cweTags(cwes),
				}),
			);
		}
	}
	return findings;
};

/** Parses `bun audit --json` (`{ "<package>": [advisory, ...] }`). */
export const parseBunAuditReport = (
	json: unknown,
	_root: string,
	lock?: LockText,
): FindingInput[] => {
	if (!isRecord(json) || isRecord(json.error)) return [];
	const versions = new Map<string, string[]>();
	if (lock)
		for (const d of parseBunLock(lock.text, lock.file))
			versions.set(d.name, [...(versions.get(d.name) ?? []), d.version]);
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const [name, list] of Object.entries(json)) {
		for (const adv of arr(list)) {
			if (!isRecord(adv) || (!adv.id && !adv.url)) continue;
			const url = str(adv.url);
			const id = ghsaOf(url) ?? String(adv.id ?? "unknown");
			if (seen.has(`${name}|${id}`)) continue;
			seen.add(`${name}|${id}`);
			const fixed = fixedFromRange(str(adv.vulnerable_versions));
			const cwes = arr(adv.cwe).filter(
				(c): c is string => typeof c === "string",
			);
			const known = [...new Set(versions.get(name) ?? [])];
			findings.push(
				vulnFinding({
					auditor: "code.bun-audit",
					name,
					// bun does not print the installed version; take it from bun.lock.
					version: known.length ? known.join(", ") : undefined,
					ecosystem: "npm",
					id,
					summary: str(adv.title) ?? id,
					severity: severityOf(adv.severity),
					fixed: fixed ? [fixed] : [],
					file: lock?.file,
					references: jsRefs(url),
					tags: cweTags(cwes),
				}),
			);
		}
	}
	return findings;
};

const jsAudit = (opts: {
	id: string;
	title: string;
	tool: string;
	lockfiles: ReadonlyArray<string>;
	install: string;
	args: ReadonlyArray<string>;
	env?: Record<string, string>;
	parse: (
		json: unknown,
		root: string,
		file: string,
		lockText: string,
	) => FindingInput[];
}): Auditor =>
	defineAuditor({
		id: opts.id,
		title: opts.title,
		description: `Runs \`${opts.tool} ${opts.args.join(" ")}\` per lockfile (${opts.lockfiles.join(", ")}). Reads the lockfile only: nothing is installed and no lifecycle script runs. The registry is pinned to registry.npmjs.org so a project .npmrc cannot redirect the request; private registries are therefore not audited.`,
		categories: ["supply-chain", "security"],
		targets: ["codebase"],
		engine: "external",
		tool: opts.tool,
		network: true,
		defaultEnabled: true,
		run: (ctx) =>
			Effect.gen(function* () {
				const ws = yield* requireWorkspace(ctx);
				const locks = yield* findFiles(ctx, (p) =>
					opts.lockfiles.includes(baseOf(p)),
				);
				if (!locks.length)
					return yield* skip(`No ${opts.lockfiles.join(" / ")} found`);
				const bin = yield* requireTool(ctx, opts.tool, opts.install);
				const findings: FindingInput[] = [];
				for (const lock of locks) {
					// Exit 1 = vulnerabilities found (or an error, reported as JSON).
					const res = yield* run(
						ctx,
						[bin, ...opts.args, "--registry", NPM_REGISTRY],
						{
							cwd: ws.absolute(dirOf(lock) || "."),
							okCodes: [0, 1],
							env: opts.env,
						},
					);
					const json = yield* parseJson(res.stdout || "{}", opts.tool);
					const err = errorMessage(json);
					if (err)
						return yield* Effect.fail(
							new AuditorError({
								message: `${opts.tool} audit failed: ${truncate(err, 300)}`,
							}),
						);
					const text = yield* ws
						.readText(lock)
						.pipe(Effect.orElseSucceed(() => ""));
					findings.push(...opts.parse(json, ws.root, lock, text));
				}
				return findings;
			}),
	});

export const npmAudit = jsAudit({
	id: "code.npm-audit",
	title: "npm audit",
	tool: "npm",
	lockfiles: ["package-lock.json", "npm-shrinkwrap.json"],
	install: "Install Node.js (npm ships with it): https://nodejs.org.",
	args: ["audit", "--json", "--package-lock-only"],
	parse: (json, root, file, text) =>
		parseNpmAuditReport(json, root, { file, text }),
});

export const pnpmAudit = jsAudit({
	id: "code.pnpm-audit",
	title: "pnpm audit",
	tool: "pnpm",
	lockfiles: ["pnpm-lock.yaml"],
	install: "Install: npm install -g pnpm (or corepack enable).",
	// A project's pnpm-workspace.yaml/.npmrc overrides env config but not
	// `--config.*` flags. Never run the project's .pnpmfile.cjs (pnpm loads it
	// even for `audit`) or let its packageManager field download another pnpm.
	args: [
		"audit",
		"--json",
		"--config.ignore-pnpmfile=true",
		"--config.manage-package-manager-versions=false",
	],
	env: {
		npm_config_ignore_pnpmfile: "true",
		npm_config_manage_package_manager_versions: "false",
	},
	parse: (json, root, file) => parsePnpmAuditReport(json, root, file),
});

export const bunAudit = jsAudit({
	id: "code.bun-audit",
	title: "bun audit",
	tool: "bun",
	lockfiles: ["bun.lock"],
	install:
		"Install: curl -fsSL https://bun.sh/install | bash (bun >= 1.2.15 has `bun audit`).",
	args: ["audit", "--json"],
	parse: (json, root, file, text) =>
		parseBunAuditReport(json, root, { file, text }),
});

/* -------------------------------------------------------------------------- */
/*                                    grype                                   */
/* -------------------------------------------------------------------------- */

const grypeSeverity = (vuln: Record<string, unknown>): Severity => {
	const label = str(vuln.severity)?.toLowerCase();
	if (label === "negligible") return "info";
	if (label && label !== "unknown") return severityOf(label);
	const scores = arr(vuln.cvss).flatMap((c) =>
		isRecord(c) && isRecord(c.metrics) && num(c.metrics.baseScore) !== undefined
			? [num(c.metrics.baseScore) as number]
			: [],
	);
	return scores.length ? severityFromScore(Math.max(...scores)) : "medium";
};

/** Parses `grype -o json`. */
export const parseGrypeReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const m of arr(json.matches)) {
		if (!isRecord(m) || !isRecord(m.vulnerability) || !isRecord(m.artifact))
			continue;
		const vuln = m.vulnerability;
		const art = m.artifact;
		const id = str(vuln.id) ?? "unknown";
		const name = str(art.name) ?? "unknown";
		const version = str(art.version);
		const loc = arr(art.locations).find(isRecord);
		const file = scanPath(root, loc ? str(loc.path) : undefined);
		const key = `${id}|${name}|${version}|${file}`;
		if (seen.has(key)) continue;
		seen.add(key);
		const related = arr(m.relatedVulnerabilities)
			.filter(isRecord)
			.map((r) => str(r.id))
			.filter((r): r is string => !!r);
		const fix = isRecord(vuln.fix) ? vuln.fix : {};
		const state = str(fix.state);
		const details = arr(m.matchDetails).find(isRecord);
		const fuzzy = (str(details?.type) ?? "").includes("cpe");
		const urls = arr(vuln.urls).filter(
			(u): u is string => typeof u === "string",
		);
		const description = str(vuln.description);
		findings.push(
			vulnFinding({
				auditor: "code.grype",
				name,
				version,
				ecosystem: str(art.type),
				id,
				aliases: related,
				summary: truncate((description ?? id).split("\n")[0] ?? id, 140),
				severity: grypeSeverity(vuln),
				fixed: arr(fix.versions).filter(
					(v): v is string => typeof v === "string",
				),
				fixHint:
					state === "wont-fix"
						? `The vendor will not fix this in ${name}; consider replacing it.`
						: undefined,
				file,
				references: [
					...(str(vuln.dataSource) ? [str(vuln.dataSource) as string] : []),
					...urls.slice(0, 2),
				],
				confidence: fuzzy ? "low" : "high",
				note: fuzzy
					? "Matched by CPE, which can produce false positives."
					: undefined,
				tags: cweTags(
					arr(vuln.cwes)
						.filter(isRecord)
						.map((c) => str(c.cwe) ?? ""),
				),
			}),
		);
	}
	return findings;
};

export const grype = defineAuditor({
	id: "code.grype",
	title: "grype vulnerability scan",
	description:
		"Scans the directory with Anchore grype (builds an SBOM with syft, matches against the grype database). Overlaps osv-scanner and trivy, so it is opt-in. Runs from a scratch directory so project-level grype config is ignored; the vulnerability database is downloaded on first use.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "grype",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"grype",
				"Install: brew install grype or curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh.",
			);
			const res = yield* withTempDir((dir) =>
				run(ctx, [bin, `dir:${ws.root}`, "-o", "json", "-q"], {
					cwd: dir,
					okCodes: [0],
					env: { GRYPE_CHECK_FOR_APP_UPDATE: "false" },
				}),
			);
			return parseGrypeReport(yield* parseJson(res.stdout, "grype"), ws.root);
		}),
});

/* -------------------------------------------------------------------------- */
/*                               syft (licences)                              */
/* -------------------------------------------------------------------------- */

type LicenseClass = "strong" | "weak" | "permissive";
const RANK: Record<LicenseClass, number> = {
	permissive: 0,
	weak: 1,
	strong: 2,
};

const classifyLicense = (id: string): LicenseClass => {
	const s = id.trim();
	if (/^(A?GPL|SSPL|EUPL|OSL)\b/i.test(s)) return "strong";
	if (/^(LGPL|MPL|EPL|CDDL)\b/i.test(s)) return "weak";
	// Free-form names used by registries that do not use SPDX ids.
	if (/lesser general public|library general public/i.test(s)) return "weak";
	if (/(affero|general public license)/i.test(s)) return "strong";
	if (/mozilla public license|eclipse public license/i.test(s)) return "weak";
	return "permissive";
};

/**
 * Worst-case class of an SPDX expression: `OR` lets the consumer pick the
 * least restrictive alternative, `AND` takes the most restrictive, and `WITH`
 * exceptions are ignored.
 */
export const classifyLicenseExpression = (expr: string): LicenseClass => {
	const tokens = expr.match(/\(|\)|[^\s()]+/g) ?? [];
	let i = 0;
	const atom = (): LicenseClass => {
		if (tokens[i] === "(") {
			i++;
			const v = or();
			if (tokens[i] === ")") i++;
			return v;
		}
		const id = tokens[i++] ?? "";
		if (tokens[i]?.toUpperCase() === "WITH") i += 2;
		return classifyLicense(id);
	};
	const and = (): LicenseClass => {
		let v = atom();
		while (tokens[i]?.toUpperCase() === "AND") {
			i++;
			const next = atom();
			if (RANK[next] > RANK[v]) v = next;
		}
		return v;
	};
	const or = (): LicenseClass => {
		let v = and();
		while (tokens[i]?.toUpperCase() === "OR") {
			i++;
			const next = and();
			if (RANK[next] < RANK[v]) v = next;
		}
		return v;
	};
	const result = tokens.length ? or() : "permissive";
	// Free-form text ("GNU General Public License v3") does not tokenise usefully.
	return result === "permissive" &&
		tokens.length > 1 &&
		!/\b(AND|OR)\b/i.test(expr)
		? classifyLicense(expr)
		: result;
};

const licenseValues = (art: Record<string, unknown>): string[] =>
	arr(art.licenses).flatMap((l) => {
		if (typeof l === "string") return [l];
		if (!isRecord(l)) return [];
		const v = str(l.spdxExpression) || str(l.value);
		return v ? [v] : [];
	});

/** Turns `syft -o syft-json` into licence-policy findings. */
export const parseSyftLicenses = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	const unlicensed: string[] = [];
	let total = 0;
	for (const art of arr(json.artifacts)) {
		if (!isRecord(art)) continue;
		// The project's own lockfile entry (no source, no integrity) is not a dependency.
		const meta = isRecord(art.metadata) ? art.metadata : {};
		if (
			str(art.metadataType) === "javascript-npm-package-lock-entry" &&
			!str(meta.resolved) &&
			!str(meta.integrity)
		)
			continue;
		const name = str(art.name) ?? "unknown";
		const version = str(art.version);
		const at = version ? `${name}@${version}` : name;
		const loc = arr(art.locations).find(isRecord);
		const file = scanPath(root, loc ? str(loc.path) : undefined);
		const key = `${str(art.type)}|${at}`;
		if (seen.has(key)) continue;
		seen.add(key);
		total++;
		const licenses = licenseValues(art);
		if (!licenses.length) {
			unlicensed.push(at);
			continue;
		}
		for (const license of licenses) {
			const cls = classifyLicenseExpression(license);
			if (cls === "permissive") continue;
			const strong = cls === "strong";
			findings.push({
				ruleId: `code.syft-licenses/${strong ? "strong-copyleft" : "weak-copyleft"}`,
				title: `${at}: ${license} (${strong ? "strong" : "weak"} copyleft)`,
				severity: strong ? "medium" : "low",
				category: "compliance",
				message: `${at} is licensed under ${license}, a ${strong ? "strong" : "weak"} copyleft licence${strong ? " whose terms can extend to software that links or distributes it" : " that applies to modifications of the component itself"}.`,
				location: { file },
				evidence: `${at} ${license}`,
				remediation: `Whether this is a problem depends on how the project is distributed (SaaS, shipped binary, internal tool, library). Review ${license} with legal counsel, and replace ${name} or seek a commercial licence if it conflicts with your distribution model.`,
				references: [
					"https://spdx.org/licenses/",
					"https://choosealicense.com/licenses/",
				],
				confidence: "high",
				tags: ["licence", strong ? "strong-copyleft" : "weak-copyleft"],
			});
		}
	}
	if (unlicensed.length) {
		const shown = unlicensed.slice(0, 10).join(", ");
		findings.push({
			ruleId: "code.syft-licenses/missing-license",
			title: `${unlicensed.length} of ${total} packages have no licence information`,
			severity: "info",
			category: "compliance",
			message: `syft found no licence for ${unlicensed.length} of ${total} cataloged packages: ${shown}${unlicensed.length > 10 ? ", ..." : ""}.`,
			evidence: `${unlicensed.length}/${total} packages without licence`,
			remediation:
				"Check these packages' repositories for a licence before redistributing them. Lockfiles often omit licence metadata, so a clean result needs the installed packages or an SBOM from a build; what is acceptable depends on how the project is distributed.",
			references: ["https://spdx.org/licenses/"],
			confidence: "medium",
			tags: ["licence", "unknown-license"],
		});
	}
	return findings;
};

/** `sbomOut` must be a plain, non-empty path string. */
export const validSbomPath = (value: unknown): string | undefined =>
	typeof value === "string" &&
	value.length > 0 &&
	value.length <= 1024 &&
	// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
	!/[\u0000-\u001f]/.test(value) &&
	!value.includes(",") &&
	!value.startsWith("-")
		? value
		: undefined;

export const syftLicenses = defineAuditor({
	id: "code.syft-licenses",
	title: "syft licence policy",
	description:
		'Builds an SBOM with syft and flags copyleft licences: strong (AGPL, GPL, SSPL, EUPL, OSL) as medium, weak (LGPL, MPL, EPL, CDDL) as low, and one aggregated info finding for packages with no licence. Set settings["code.syft-licenses"].sbomOut to also write the CycloneDX SBOM to that path. Policy relevance depends on how the project is distributed, so it is opt-in.',
	categories: ["supply-chain", "compliance"],
	targets: ["codebase"],
	engine: "external",
	tool: "syft",
	network: false,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"syft",
				"Install: brew install syft or curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh.",
			);
			const rawOut = ctx.options.settings?.["code.syft-licenses"]?.sbomOut;
			let sbomOut: string | undefined;
			if (rawOut !== undefined) {
				sbomOut = validSbomPath(rawOut);
				if (!sbomOut)
					return yield* Effect.fail(
						new AuditorError({
							message:
								"code.syft-licenses sbomOut must be a plain path string (no control characters or commas, not starting with '-')",
						}),
					);
			}
			const args = [bin, "scan", `dir:${ws.root}`, "-o", "syft-json", "-q"];
			if (sbomOut)
				args.push("-o", `cyclonedx-json=${resolve(ws.root, sbomOut)}`);
			const res = yield* withTempDir((dir) =>
				run(ctx, args, {
					cwd: dir,
					okCodes: [0],
					env: { SYFT_CHECK_FOR_APP_UPDATE: "false" },
				}),
			);
			return parseSyftLicenses(yield* parseJson(res.stdout, "syft"), ws.root);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                  scorecard                                 */
/* -------------------------------------------------------------------------- */

/** Risk per check, from https://github.com/ossf/scorecard/blob/main/docs/checks.md. */
const SCORECARD_RISK: Record<string, Severity> = {
	"Dangerous-Workflow": "critical",
	Webhooks: "critical",
	"Binary-Artifacts": "high",
	"Branch-Protection": "high",
	"Code-Review": "high",
	"Dependency-Update-Tool": "high",
	Maintained: "high",
	"Signed-Releases": "high",
	"Token-Permissions": "high",
	Vulnerabilities: "high",
	Fuzzing: "medium",
	Packaging: "medium",
	"Pinned-Dependencies": "medium",
	SAST: "medium",
	"Security-Policy": "medium",
	"CI-Tests": "low",
	"CII-Best-Practices": "low",
	Contributors: "low",
	License: "low",
};

/** Risk lowered by how well the repository scored: 0-3 keeps it, 4-6 -1, 7-9 -2. */
export const scorecardSeverity = (risk: Severity, score: number): Severity =>
	lower(risk, score <= 3 ? 0 : score <= 6 ? 1 : 2);

/** Parses `scorecard --format json`. Inconclusive (-1) and perfect scores are skipped. */
export const parseScorecardReport = (json: unknown): FindingInput[] => {
	if (!isRecord(json)) return [];
	const repo = isRecord(json.repo) ? str(json.repo.name) : undefined;
	const findings: FindingInput[] = [];
	for (const c of arr(json.checks)) {
		if (!isRecord(c)) continue;
		const name = str(c.name);
		const score = num(c.score);
		if (!name || score === undefined || score < 0 || score >= 10) continue;
		const doc = isRecord(c.documentation) ? c.documentation : {};
		const url =
			str(doc.url) ??
			`https://github.com/ossf/scorecard/blob/main/docs/checks.md#${kebab(name)}`;
		const details = arr(c.details).filter(
			(d): d is string => typeof d === "string",
		);
		findings.push({
			ruleId: `code.scorecard/${kebab(name)}`,
			title: `OpenSSF Scorecard ${name}: ${score}/10`,
			severity: scorecardSeverity(SCORECARD_RISK[name] ?? "medium", score),
			category: "supply-chain",
			message: `${repo ? `${repo}: ` : ""}${str(c.reason) ?? `${name} scored ${score}/10`}${str(doc.short) ? ` (${str(doc.short)})` : ""}`,
			evidence: details.length
				? truncate(details.slice(0, 3).join(" | "), 240)
				: undefined,
			remediation: `Follow the Scorecard guidance for ${name} to raise the score: ${url}`,
			references: [url],
			confidence: "high",
			tags: ["openssf-scorecard"],
		});
	}
	return findings;
};

/** `owner/repo` of the `origin` remote when it points at GitHub. */
export const githubRepoFromGitConfig = (
	config: string,
): { owner: string; repo: string } | undefined => {
	const section = /\[remote "origin"\]([^[]*)/.exec(config)?.[1];
	const url = section ? /^\s*url\s*=\s*(\S+)/m.exec(section)?.[1] : undefined;
	const m = url
		? /github\.com[:/]+([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(url)
		: null;
	return m?.[1] && m[2] ? { owner: m[1], repo: m[2] } : undefined;
};

export const scorecard = defineAuditor({
	id: "code.scorecard",
	title: "OpenSSF Scorecard",
	description:
		"Runs OpenSSF Scorecard against the GitHub repository named by the workspace's origin remote and reports checks that scored 0-9, with severity from each check's documented risk scaled by score. Needs GITHUB_AUTH_TOKEN or GITHUB_TOKEN; it calls the GitHub API about the remote repository, not the local files.",
	categories: ["supply-chain"],
	targets: ["codebase"],
	engine: "external",
	tool: "scorecard",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const config = yield* ws
				.readText(".git/config")
				.pipe(Effect.orElseSucceed(() => undefined));
			if (!config)
				return yield* skip("No .git/config found (not a git checkout)");
			const gh = githubRepoFromGitConfig(config);
			if (!gh)
				return yield* skip("The origin remote is not a GitHub repository");
			const token = process.env.GITHUB_AUTH_TOKEN || process.env.GITHUB_TOKEN;
			if (!token)
				return yield* skip(
					"Set GITHUB_AUTH_TOKEN or GITHUB_TOKEN to run OpenSSF Scorecard",
				);
			const bin = yield* requireTool(
				ctx,
				"scorecard",
				"Install: brew install scorecard or go install github.com/ossf/scorecard/v5@latest.",
			);
			const res = yield* run(
				ctx,
				[bin, `--repo=github.com/${gh.owner}/${gh.repo}`, "--format", "json"],
				{ cwd: ws.root, okCodes: [0], env: { GITHUB_AUTH_TOKEN: token } },
			);
			return parseScorecardReport(yield* parseJson(res.stdout, "scorecard"));
		}),
});

export const supplyChainToolAuditors: ReadonlyArray<Auditor> = [
	govulncheck,
	pipAudit,
	cargoAudit,
	npmAudit,
	pnpmAudit,
	bunAudit,
	grype,
	syftLicenses,
	scorecard,
];
