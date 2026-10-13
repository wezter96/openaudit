import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	DEFAULT_IGNORES,
	defineAuditor,
	type FindingInput,
	redact,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { cweUrl, extOf, isRecord, kebab, scrubLine, truncate } from "./util";

/**
 * Secret scanning (trufflehog) and SAST wrappers (bandit, gosec, brakeman,
 * CodeQL). None of them builds or runs the target's code.
 */

type Confidence = "high" | "medium" | "low";

const SEVERITY_ORDER: ReadonlyArray<Severity> = [
	"info",
	"low",
	"medium",
	"high",
	"critical",
];

/** Lowers a severity by one step when the tool itself is unsure about it. */
const discount = (severity: Severity, confidence: Confidence): Severity => {
	if (confidence !== "low") return severity;
	const i = SEVERITY_ORDER.indexOf(severity);
	return SEVERITY_ORDER[Math.max(1, i - 1)] ?? severity;
};

/** `HIGH`/`MEDIUM`/`LOW` (bandit, gosec) to our severity scale. */
const labelSeverity = (label: unknown): Severity => {
	switch (str(label)?.toUpperCase()) {
		case "HIGH":
			return "high";
		case "LOW":
			return "low";
		default:
			return "medium";
	}
};

const labelConfidence = (label: unknown): Confidence => {
	switch (str(label)?.toLowerCase()) {
		case "high":
			return "high";
		case "low":
		case "weak":
			return "low";
		default:
			return "medium";
	}
};

const strings = (v: unknown): string[] =>
	arr(v).filter((s): s is string => typeof s === "string");

const FILE_LIMIT = 10;

/* -------------------------------------------------------------------------- */
/*                                 trufflehog                                 */
/* -------------------------------------------------------------------------- */

/**
 * Parses `trufflehog filesystem --json` output (NDJSON; log lines and other
 * non-JSON lines are ignored). `Raw`/`RawV2` hold the secret and are only ever
 * surfaced redacted.
 */
export const parseTrufflehogReport = (
	stdout: string,
	root: string,
): FindingInput[] =>
	stdout.split("\n").flatMap((line) => {
		const text = line.trim();
		if (!text.startsWith("{")) return [];
		let item: unknown;
		try {
			item = JSON.parse(text);
		} catch {
			return [];
		}
		if (!isRecord(item)) return [];
		const detector = str(item.DetectorName);
		if (!detector) return [];
		const data = isRecord(item.SourceMetadata) ? item.SourceMetadata : {};
		const inner = isRecord(data.Data) ? data.Data : {};
		const source = Object.values(inner).find(isRecord) ?? {};
		const verified = item.Verified === true;
		const raw = str(item.RawV2) || str(item.Raw) || "";
		const description = str(item.DetectorDescription);
		return [
			{
				ruleId: `code.trufflehog/${kebab(detector)}`,
				title: `${detector} secret detected`,
				// Verified = the provider confirmed the credential is live.
				severity: verified ? "critical" : "high",
				category: "security",
				message: verified
					? `trufflehog verified a live ${detector} credential against the provider.`
					: `trufflehog detector \`${detector}\` matched a likely secret (not verified).${description ? ` ${description}` : ""}`,
				location: {
					file: relPath(root, str(source.file)),
					line: num(source.line),
				},
				evidence: raw ? `${detector}: ${redact(raw)}` : undefined,
				remediation:
					"Revoke and rotate the credential, purge it from the repository and git history, and load it from a secret manager or environment variable.",
				references: [
					cweUrl(798),
					"https://github.com/trufflesecurity/trufflehog",
				],
				confidence: verified ? "high" : "medium",
				tags: ["cwe-798", "owasp-a07", "secrets", kebab(detector)],
			},
		];
	});

export const trufflehog = defineAuditor({
	id: "code.trufflehog",
	title: "trufflehog secret scan",
	description:
		'Runs trufflehog over the working tree for hardcoded secrets. Credentials are NOT verified by default (--no-verification), so nothing leaves the machine; set settings["code.trufflehog"].verify = true to let trufflehog send each found secret to its provider\'s API to confirm it is live (verified secrets are reported as critical).',
	categories: ["security"],
	targets: ["codebase"],
	engine: "external",
	tool: "trufflehog",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"trufflehog",
				"Install: brew install trufflehog (https://github.com/trufflesecurity/trufflehog#floppy_disk-installation).",
			);
			const verify = ctx.options.settings?.["code.trufflehog"]?.verify === true;
			// Skip the directories every built-in auditor skips (dependencies,
			// .git objects, build output, caches): one regex per line.
			const excludes = join(
				tmpdir(),
				`openaudit-trufflehog-${crypto.randomUUID()}.txt`,
			);
			yield* Effect.promise(() =>
				Bun.write(
					excludes,
					DEFAULT_IGNORES.map(
						(d) => `(^|/)${d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/`,
					).join("\n"),
				),
			);
			const res = yield* runTool(
				ctx,
				[
					bin,
					"filesystem",
					ws.root,
					"--json",
					"--no-update",
					`--exclude-paths=${excludes}`,
					...(verify ? [] : ["--no-verification"]),
				],
				ws.root,
				[0],
			).pipe(
				Effect.ensuring(Effect.promise(() => rm(excludes, { force: true }))),
			);
			return parseTrufflehogReport(res.stdout, ws.root);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                   bandit                                   */
/* -------------------------------------------------------------------------- */

/** Source line `n` out of bandit/gosec's numbered `code` excerpt. */
const excerptLine = (
	code: unknown,
	n: number | undefined,
): string | undefined => {
	const text = str(code);
	if (!text || n === undefined) return undefined;
	for (const line of text.split("\n")) {
		const m = /^(\d+)[: ]\s?(.*)$/.exec(line);
		if (m && Number(m[1]) === n) return m[2]?.trim() || undefined;
	}
	return undefined;
};

/** Hardcoded-credential checks: their snippets contain the secret itself. */
const BANDIT_SECRET_TESTS = new Set(["B105", "B106", "B107"]);

/** Parses `bandit -f json` output. */
export const parseBanditReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.results).flatMap((r) => {
		if (!isRecord(r)) return [];
		const testId = str(r.test_id) ?? "B000";
		const name = str(r.test_name) ?? "issue";
		const cwe = isRecord(r.issue_cwe) ? num(r.issue_cwe.id) : undefined;
		const line = num(r.line_number);
		const snippet = BANDIT_SECRET_TESTS.has(testId)
			? undefined
			: excerptLine(r.code, line);
		const confidence = labelConfidence(r.issue_confidence);
		const text = str(r.issue_text) ?? name;
		return [
			{
				ruleId: `code.bandit/${testId.toLowerCase()}-${kebab(name)}`,
				title: truncate(text.replace(/\.$/, ""), 100),
				// issue_severity, one step lower when bandit has low confidence.
				severity: discount(labelSeverity(r.issue_severity), confidence),
				category: "security",
				message: `${text} (bandit ${testId}: ${name})`,
				location: {
					file: relPath(root, str(r.filename)),
					line,
					column:
						num(r.col_offset) === undefined
							? undefined
							: (num(r.col_offset) as number) + 1,
				},
				evidence: snippet ? truncate(scrubLine(snippet)) : undefined,
				remediation:
					"Follow the bandit rule documentation to replace the flagged construct with a safe alternative, or add a justified `# nosec` if it is a false positive.",
				references: [
					...(str(r.more_info) ? [str(r.more_info) as string] : []),
					...(cwe ? [cweUrl(cwe)] : []),
				],
				confidence,
				tags: cwe ? [`cwe-${cwe}`] : [],
			},
		];
	});
};

export const bandit = defineAuditor({
	id: "code.bandit",
	title: "Bandit Python SAST",
	description:
		"Runs Bandit over Python sources (static analysis only, the code is never imported or executed). Skipped when the workspace has no .py files.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "external",
	tool: "bandit",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			if (!(yield* ws.files).some((f) => extOf(f) === "py"))
				return yield* skip("No Python files in the workspace");
			const bin = yield* requireTool(
				ctx,
				"bandit",
				"Install: pipx install bandit or pip install bandit (https://bandit.readthedocs.io).",
			);
			// Exit 1 = issues found.
			const res = yield* runTool(
				ctx,
				[
					bin,
					"-r",
					ws.root,
					"-f",
					"json",
					"-q",
					"-x",
					"*/node_modules/*,*/.venv/*,*/venv/*,*/.git/*,*/site-packages/*",
				],
				ws.root,
				[0, 1],
			);
			return parseBanditReport(
				yield* parseJson(res.stdout || "{}", "bandit"),
				ws.root,
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                    gosec                                   */
/* -------------------------------------------------------------------------- */

/** Parses `gosec -fmt json` output. */
export const parseGosecReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.Issues).flatMap((i) => {
		if (!isRecord(i) || i.nosec === true) return [];
		const rule = str(i.rule_id) ?? "G000";
		const cwe = isRecord(i.cwe) ? str(i.cwe.id) : undefined;
		const line = Number.parseInt(str(i.line) ?? "", 10);
		const column = Number.parseInt(str(i.column) ?? "", 10);
		const details = str(i.details) ?? rule;
		const confidence = labelConfidence(i.confidence);
		// G101 = hardcoded credentials: the snippet is the secret.
		const snippet =
			rule === "G101"
				? undefined
				: excerptLine(i.code, Number.isFinite(line) ? line : undefined);
		return [
			{
				ruleId: `code.gosec/${rule.toLowerCase()}`,
				title: truncate(details, 100),
				severity: discount(labelSeverity(i.severity), confidence),
				category: "security",
				message: `${details} (gosec ${rule})`,
				location: {
					file: relPath(root, str(i.file)),
					line: Number.isFinite(line) ? line : undefined,
					column: Number.isFinite(column) ? column : undefined,
				},
				evidence: snippet ? truncate(scrubLine(snippet)) : undefined,
				remediation:
					"See the gosec rule documentation for the recommended fix, or annotate a justified false positive with `#nosec`.",
				references: [
					`https://securego.io/docs/rules/${rule.toLowerCase()}.html`,
					...(cwe && /^\d+$/.test(cwe) ? [cweUrl(Number(cwe))] : []),
				],
				confidence,
				tags: cwe && /^\d+$/.test(cwe) ? [`cwe-${cwe}`] : [],
			},
		];
	});
};

export const gosec = defineAuditor({
	id: "code.gosec",
	title: "gosec Go SAST",
	description:
		"Runs gosec over each Go module (go.mod). gosec type-checks packages through the Go toolchain (`go list`), which may download missing modules but never compiles or runs the target's code. Skipped when there is no go.mod.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "external",
	tool: "gosec",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const modules = (yield* ws.files)
				.filter((f) => f === "go.mod" || f.endsWith("/go.mod"))
				.map((f) => dirname(f))
				.slice(0, FILE_LIMIT);
			if (modules.length === 0)
				return yield* skip("No go.mod in the workspace");
			const bin = yield* requireTool(
				ctx,
				"gosec",
				"Install: brew install gosec or go install github.com/securego/gosec/v2/cmd/gosec@latest.",
			);
			const findings: FindingInput[] = [];
			for (const dir of modules) {
				// GOTOOLCHAIN=local: a target's go.mod `toolchain` line must not make
				// go download and run another toolchain. No cgo: no C compiler runs.
				const res = yield* ctx.exec.run(
					[bin, "-fmt", "json", "-quiet", "-no-fail", "./..."],
					{
						cwd: ws.absolute(dir),
						timeoutMs: 15 * 60_000,
						env: { GOTOOLCHAIN: "local", CGO_ENABLED: "0" },
					},
				);
				if (res.code !== 0 && res.code !== 1)
					return yield* Effect.fail(
						new AuditorError({
							message: `gosec exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
						}),
					);
				if (!res.stdout.trim()) continue;
				findings.push(
					...parseGosecReport(yield* parseJson(res.stdout, "gosec"), ws.root),
				);
			}
			return findings;
		}),
});

/* -------------------------------------------------------------------------- */
/*                                  brakeman                                  */
/* -------------------------------------------------------------------------- */

/** Brakeman warning types whose `code` can contain credentials. */
const BRAKEMAN_SECRET_TYPES = /basic auth|secret|password|hardcoded/i;

/**
 * Parses `brakeman -f json` output. `prefix` is the Rails app directory
 * relative to the workspace root (brakeman reports paths relative to the app).
 */
export const parseBrakemanReport = (
	json: unknown,
	root: string,
	prefix = "",
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.warnings).flatMap((w) => {
		if (!isRecord(w)) return [];
		const type = str(w.warning_type) ?? "Warning";
		const file = str(w.file);
		const code = str(w.code);
		const cwe = arr(w.cwe_id).filter((n): n is number => typeof n === "number");
		const link = str(w.link);
		const confidence = labelConfidence(str(w.confidence)?.toLowerCase());
		// Confidence is brakeman's only signal: High -> high, Medium -> medium,
		// Weak -> low. Dependency hygiene warnings are capped at medium.
		const dependency = /dependency|rails \d|eol|end of life/i.test(type);
		const severity: Severity = dependency
			? confidence === "low"
				? "low"
				: "medium"
			: confidence === "high"
				? "high"
				: confidence === "medium"
					? "medium"
					: "low";
		return [
			{
				ruleId: `code.brakeman/${kebab(type)}`,
				title: `${type}: ${str(w.message) ?? type}`.slice(0, 120),
				severity,
				category: dependency ? "supply-chain" : "security",
				message: `${str(w.message) ?? type} (brakeman check ${str(w.check_name) ?? "unknown"})`,
				location: {
					file: file
						? relPath(root, prefix ? `${prefix}/${file}` : file)
						: undefined,
					line: num(w.line),
				},
				evidence:
					code && !BRAKEMAN_SECRET_TYPES.test(type)
						? truncate(scrubLine(code))
						: undefined,
				remediation: link
					? `See the brakeman warning documentation: ${link}`
					: "See the brakeman documentation for this warning type.",
				references: [...(link ? [link] : []), ...cwe.slice(0, 2).map(cweUrl)],
				confidence,
				tags: cwe.map((n) => `cwe-${n}`),
			},
		];
	});
};

export const brakeman = defineAuditor({
	id: "code.brakeman",
	title: "Brakeman Rails SAST",
	description:
		"Runs Brakeman statically over a Ruby on Rails app (the app is never booted). Skipped unless the Gemfile mentions rails or config/application.rb exists.",
	categories: ["security", "supply-chain"],
	targets: ["codebase"],
	engine: "external",
	tool: "brakeman",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			const appConfig = files.find(
				(f) =>
					f === "config/application.rb" || f.endsWith("/config/application.rb"),
			);
			let appDir = appConfig ? dirname(dirname(appConfig)) : undefined;
			if (appDir === undefined) {
				const gemfiles = files
					.filter((f) => f === "Gemfile" || f.endsWith("/Gemfile"))
					.slice(0, FILE_LIMIT);
				for (const gemfile of gemfiles) {
					const text = yield* ws
						.readText(gemfile)
						.pipe(Effect.orElseSucceed(() => ""));
					if (/^\s*gem\s+["']rails["']/m.test(text)) {
						appDir = dirname(gemfile);
						break;
					}
				}
			}
			if (appDir === undefined)
				return yield* skip("No Rails application found");
			const bin = yield* requireTool(
				ctx,
				"brakeman",
				"Install: gem install brakeman or brew install brakeman (https://brakemanscanner.org).",
			);
			const res = yield* runTool(
				ctx,
				[
					bin,
					"-f",
					"json",
					"-q",
					"--no-pager",
					"--no-exit-on-warn",
					"--no-exit-on-error",
					"-p",
					ws.absolute(appDir),
				],
				ws.root,
				[0],
			);
			return parseBrakemanReport(
				yield* parseJson(res.stdout, "brakeman"),
				ws.root,
				appDir === "." ? "" : appDir,
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                    SARIF                                   */
/* -------------------------------------------------------------------------- */

/** CVSS v3 qualitative bands, as GitHub uses for `security-severity`. */
const severityFromCvss = (score: number): Severity =>
	score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";

const sarifLevelSeverity = (level: unknown): Severity => {
	switch (str(level)) {
		case "error":
			return "high";
		case "note":
			return "low";
		case "none":
			return "info";
		default:
			return "medium";
	}
};

/** `external/cwe/cwe-079` -> `cwe-79`; `external/owasp/2021/A03` -> `owasp-a03`. */
const sarifTags = (tags: ReadonlyArray<string>): string[] => {
	const out = new Set<string>();
	for (const tag of tags) {
		const cwe = /cwe[-/]0*(\d+)/i.exec(tag);
		if (cwe) out.add(`cwe-${cwe[1]}`);
		const owasp = /owasp.*?\b(a\d{2})\b/i.exec(tag);
		if (owasp?.[1]) out.add(`owasp-${owasp[1].toLowerCase()}`);
	}
	return [...out];
};

/** Section of a CodeQL query-help document, by `##` heading. */
const helpSection = (help: string, heading: string): string | undefined => {
	const m = new RegExp(
		`^## ${heading}\\s*\\n([\\s\\S]*?)(?=^## |(?![\\s\\S]))`,
		"m",
	).exec(help);
	return m?.[1]?.trim() || undefined;
};

/** `[text](1)` link placeholders in SARIF messages become plain text. */
const plainMessage = (text: string) =>
	text.replace(/\[([^\]]+)\]\(\d+\)/g, "$1");

const sarifUri = (uri: string | undefined) =>
	uri?.startsWith("file://") ? decodeURIComponent(uri.slice(7)) : uri;

/**
 * Parses SARIF 2.1.0 (CodeQL flavour, but generic): rules come from
 * `tool.driver.rules` and `tool.extensions[].rules`. Suppressed results are
 * dropped. Rule ids become `<auditorId>/<kebab-rule>`.
 */
export const parseSarif = (
	sarif: unknown,
	root: string,
	auditorId: string,
): FindingInput[] => {
	if (!isRecord(sarif)) return [];
	return arr(sarif.runs).flatMap((run) => {
		if (!isRecord(run)) return [];
		const tool = isRecord(run.tool) ? run.tool : {};
		const driver = isRecord(tool.driver) ? tool.driver : {};
		const components = [driver, ...arr(tool.extensions).filter(isRecord)];
		const rules = new Map<string, Record<string, unknown>>();
		for (const component of components)
			for (const rule of arr(component.rules))
				if (isRecord(rule) && typeof rule.id === "string")
					rules.set(rule.id, rule);
		const driverRules = arr(driver.rules);

		return arr(run.results).flatMap((result) => {
			if (!isRecord(result) || arr(result.suppressions).length > 0) return [];
			const ref = isRecord(result.rule) ? result.rule : {};
			const ruleId = str(result.ruleId) ?? str(ref.id) ?? "unknown";
			const idx = num(result.ruleIndex);
			const indexed = idx === undefined ? undefined : driverRules[idx];
			const rule =
				rules.get(ruleId) ?? (isRecord(indexed) ? indexed : undefined) ?? {};
			const props = isRecord(rule.properties) ? rule.properties : {};
			const config = isRecord(rule.defaultConfiguration)
				? rule.defaultConfiguration
				: {};
			const short = isRecord(rule.shortDescription)
				? str(rule.shortDescription.text)
				: undefined;
			const full = isRecord(rule.fullDescription)
				? str(rule.fullDescription.text)
				: undefined;
			const help = isRecord(rule.help) ? str(rule.help.text) : undefined;
			const tags = strings(props.tags);
			const cvss = Number(
				str(props["security-severity"]) ?? props["security-severity"],
			);
			const levelSeverity = sarifLevelSeverity(
				str(result.level) ?? str(config.level),
			);
			const isSecurity =
				tags.includes("security") ||
				Number.isFinite(cvss) ||
				tags.some((t) => /cwe/.test(t));
			const severity =
				Number.isFinite(cvss) && cvss > 0
					? severityFromCvss(cvss)
					: levelSeverity;
			const precision = str(props.precision);
			const loc = arr(result.locations).find(isRecord);
			const physical =
				loc && isRecord(loc.physicalLocation) ? loc.physicalLocation : {};
			const artifact = isRecord(physical.artifactLocation)
				? physical.artifactLocation
				: {};
			const region = isRecord(physical.region) ? physical.region : {};
			const snippet = isRecord(region.snippet)
				? str(region.snippet.text)
				: undefined;
			const recommendation = help
				? helpSection(help, "Recommendation")
				: undefined;
			const refs = help ? helpSection(help, "References") : undefined;
			const refUrls = [...(refs ?? "").matchAll(/\]\((https?:\/\/[^)\s]+)\)/g)]
				.map((m) => m[1] as string)
				.slice(0, 3);
			const message = plainMessage(
				(isRecord(result.message) ? str(result.message.text) : undefined) ??
					short ??
					ruleId,
			);
			return [
				{
					ruleId: `${auditorId}/${kebab(ruleId)}`,
					title: truncate(short ?? str(rule.name) ?? ruleId, 100),
					severity,
					category: isSecurity
						? "security"
						: tags.includes("maintainability")
							? "maintainability"
							: tags.includes("reliability") || tags.includes("correctness")
								? "reliability"
								: "best-practices",
					message,
					location: {
						file: relPath(root, sarifUri(str(artifact.uri))),
						line: num(region.startLine),
						column: num(region.startColumn),
					},
					evidence: snippet ? truncate(scrubLine(snippet)) : undefined,
					remediation: recommendation
						? truncate(recommendation.replace(/\s+/g, " "), 400)
						: (full ?? "See the rule documentation for the recommended fix."),
					references: [
						...(str(rule.helpUri) ? [str(rule.helpUri) as string] : []),
						...refUrls,
					],
					confidence:
						precision === "very-high" || precision === "high"
							? "high"
							: precision === "low"
								? "low"
								: "medium",
					tags: sarifTags(tags),
				},
			];
		});
	});
};

/* -------------------------------------------------------------------------- */
/*                                   CodeQL                                   */
/* -------------------------------------------------------------------------- */

interface CodeqlLanguage {
	/** Value for `--language`. */
	readonly id: string;
	/** Query pack and suite prefix. */
	readonly pack: string;
	readonly extensions: ReadonlyArray<string>;
}

/**
 * Only languages CodeQL can extract without building the project
 * (`--build-mode=none`), so the target's build is never executed. Go, C/C++
 * and Swift need a real build and are deliberately absent.
 */
export const CODEQL_LANGUAGES: ReadonlyArray<CodeqlLanguage> = [
	{
		id: "javascript-typescript",
		pack: "javascript",
		extensions: ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"],
	},
	{ id: "python", pack: "python", extensions: ["py"] },
	{ id: "ruby", pack: "ruby", extensions: ["rb"] },
	{ id: "java-kotlin", pack: "java", extensions: ["java", "kt"] },
	{ id: "csharp", pack: "csharp", extensions: ["cs"] },
];

const NEEDS_BUILD = new Set(["go", "c", "cpp", "h", "hpp", "cc", "swift"]);

export const detectCodeqlLanguages = (
	files: ReadonlyArray<string>,
): { supported: CodeqlLanguage[]; unsupported: string[] } => {
	const exts = new Set(files.map(extOf));
	return {
		supported: CODEQL_LANGUAGES.filter((l) =>
			l.extensions.some((e) => exts.has(e)),
		),
		unsupported: [...exts].filter((e) => NEEDS_BUILD.has(e)),
	};
};

const CODEQL_TIMEOUT_MS = 30 * 60_000;

const execOk = (ctx: AuditContext, cmd: ReadonlyArray<string>, cwd: string) =>
	Effect.flatMap(
		ctx.exec.run(cmd, { cwd, timeoutMs: CODEQL_TIMEOUT_MS }),
		(res) =>
			res.code === 0
				? Effect.succeed(res)
				: Effect.fail(
						new AuditorError({
							message: `codeql ${cmd[1] ?? ""} ${cmd[2] ?? ""} exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
						}),
					),
	);

export const codeql = defineAuditor({
	id: "code.codeql",
	title: "CodeQL SAST",
	description:
		"Runs CodeQL's security-extended query suites on JavaScript/TypeScript, Python, Ruby, Java/Kotlin and C# using --build-mode=none, so the target is never built or executed. Go, C/C++ and Swift are skipped because they need a build. Downloads query packs from GitHub and can take many minutes, so it is opt-in.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "external",
	tool: "codeql",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const { supported, unsupported } = detectCodeqlLanguages(yield* ws.files);
			if (supported.length === 0)
				return yield* skip(
					unsupported.length
						? "Only languages that need a build to analyse were found (Go, C/C++, Swift); CodeQL is limited to --build-mode=none languages so the target is never built"
						: "No CodeQL-supported languages found",
				);
			const bin = yield* requireTool(
				ctx,
				"codeql",
				"Install: brew install codeql or download the CodeQL CLI bundle from https://github.com/github/codeql-action/releases.",
			);
			const dir = yield* Effect.tryPromise({
				try: () => mkdtemp(join(tmpdir(), "openaudit-codeql-")),
				catch: (cause) =>
					new AuditorError({
						message: "Cannot create a temp directory",
						cause,
					}),
			});
			return yield* Effect.gen(function* () {
				const db = join(dir, "db");
				const cluster = supported.length > 1;
				yield* execOk(
					ctx,
					[
						bin,
						"database",
						"create",
						db,
						...(cluster ? ["--db-cluster"] : []),
						`--language=${supported.map((l) => l.id).join(",")}`,
						"--build-mode=none",
						"--source-root",
						ws.root,
						"--overwrite",
					],
					ws.root,
				);
				const findings: FindingInput[] = [];
				for (const lang of supported) {
					const sarifPath = join(dir, `${lang.pack}.sarif`);
					yield* execOk(
						ctx,
						[
							bin,
							"database",
							"analyze",
							cluster ? join(db, lang.id) : db,
							"--format=sarif-latest",
							"--output",
							sarifPath,
							"--download",
							`codeql/${lang.pack}-queries:codeql-suites/${lang.pack}-security-extended.qls`,
						],
						ws.root,
					);
					const text = yield* Effect.tryPromise({
						try: () => Bun.file(sarifPath).text(),
						catch: (cause) =>
							new AuditorError({
								message: "codeql did not write a SARIF file",
								cause,
							}),
					});
					findings.push(
						...parseSarif(
							yield* parseJson(text, "codeql"),
							ws.root,
							"code.codeql",
						),
					);
				}
				return findings;
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			);
		}),
});
