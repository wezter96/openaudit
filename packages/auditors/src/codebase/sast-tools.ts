import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	type Confidence,
	DEFAULT_IGNORES,
	defineAuditor,
	type FindingInput,
	redact,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	arr,
	escapeRegex,
	gitignoredPaths,
	jsonLines,
	num,
	parseJson,
	relPath,
	runTool,
	str,
} from "../tool";
import { listOf, recordOf } from "./report-fields";
import { cweUrl, extOf, isRecord, kebab, scrubLine, truncate } from "./util";

/**
 * Secret scanning (trufflehog) and SAST wrappers (bandit, gosec, brakeman).
 * None of them builds or runs the target's code.
 */

/** A workspace-relative or absolute file path. */
type FilePath = string;

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

const LABEL_SEVERITIES = new Map<string, Severity>([
	["HIGH", "high"],
	["LOW", "low"],
]);

/** `HIGH`/`MEDIUM`/`LOW` (bandit, gosec) to our severity scale. */
const labelSeverity = (label: unknown): Severity =>
	LABEL_SEVERITIES.get(str(label)?.toUpperCase() ?? "") ?? "medium";

const LABEL_CONFIDENCES = new Map<string, Confidence>([
	["high", "high"],
	["low", "low"],
	["weak", "low"],
]);

const labelConfidence = (label: unknown): Confidence =>
	LABEL_CONFIDENCES.get(str(label)?.toLowerCase() ?? "") ?? "medium";

const FILE_LIMIT = 10;

/* -------------------------------------------------------------------------- */
/*                                 trufflehog                                 */
/* -------------------------------------------------------------------------- */

/** The source record (file and line) of a trufflehog result. */
const trufflehogSource = (item: Record<string, unknown>) => {
	const data = recordOf(item.SourceMetadata);
	return Object.values(recordOf(data.Data)).find(isRecord) ?? {};
};

const trufflehogMessage = (
	detector: string,
	verified: boolean,
	description: string | undefined,
): string =>
	verified
		? `trufflehog verified a live ${detector} credential against the provider.`
		: `trufflehog detector \`${detector}\` matched a likely secret (not verified).${description ? ` ${description}` : ""}`;

/** The matched secret, redacted. */
const trufflehogEvidence = (
	item: Record<string, unknown>,
	detector: string,
): string | undefined => {
	const raw = str(item.RawV2) || str(item.Raw) || "";
	return raw ? `${detector}: ${redact(raw)}` : undefined;
};

/**
 * Parses `trufflehog filesystem --json` output (NDJSON; log lines and other
 * non-JSON lines are ignored). `Raw`/`RawV2` hold the secret and are only ever
 * surfaced redacted.
 */
export const parseTrufflehogReport = (
	stdout: string,
	root: FilePath,
): FindingInput[] =>
	jsonLines(stdout).flatMap((item) => {
		const detector = str(item.DetectorName);
		if (!detector) return [];
		const source = trufflehogSource(item);
		const verified = item.Verified === true;
		return [
			{
				ruleId: `code.trufflehog/${kebab(detector)}`,
				title: `${detector} secret detected`,
				// Verified = the provider confirmed the credential is live.
				severity: verified ? "critical" : "high",
				category: "security",
				message: trufflehogMessage(
					detector,
					verified,
					str(item.DetectorDescription),
				),
				location: {
					file: relPath(root, str(source.file)),
					line: num(source.line),
				},
				evidence: trufflehogEvidence(item, detector),
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
			// .git objects, build output, caches) and what .gitignore excludes:
			// one regex per line.
			const root = escapeRegex(ws.root);
			const ignored = (yield* gitignoredPaths(ws)).map((p) =>
				p.endsWith("/")
					? `^${root}/${escapeRegex(p)}`
					: `^${root}/${escapeRegex(p)}$`,
			);
			const excludes = join(
				tmpdir(),
				`openaudit-trufflehog-${crypto.randomUUID()}.txt`,
			);
			yield* Effect.promise(() =>
				Bun.write(
					excludes,
					[
						...DEFAULT_IGNORES.map((d) => `(^|/)${escapeRegex(d)}/`),
						...ignored,
					].join("\n"),
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
	const m = text
		.split("\n")
		.map((line) => /^(\d+)[: ]\s?(.*)$/.exec(line))
		.find((m) => Number(m?.[1]) === n);
	return m?.[2]?.trim() || undefined;
};

/** Hardcoded-credential checks: their snippets contain the secret itself. */
const BANDIT_SECRET_TESTS = new Set(["B105", "B106", "B107"]);

/** bandit's 0-based `col_offset` as a 1-based column. */
const banditColumn = (offset: unknown): number | undefined => {
	const column = num(offset);
	return column === undefined ? undefined : column + 1;
};

const cweList = (cwe: number | undefined): number[] => (cwe ? [cwe] : []);

const banditFinding = (r: unknown, root: FilePath): FindingInput[] => {
	if (!isRecord(r)) return [];
	const testId = str(r.test_id) ?? "B000";
	const name = str(r.test_name) ?? "issue";
	const cwe = cweList(num(recordOf(r.issue_cwe).id));
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
				column: banditColumn(r.col_offset),
			},
			evidence: snippet ? truncate(scrubLine(snippet)) : undefined,
			remediation:
				"Follow the bandit rule documentation to replace the flagged construct with a safe alternative, or add a justified `# nosec` if it is a false positive.",
			references: [...listOf(r.more_info), ...cwe.map(cweUrl)],
			confidence,
			tags: cwe.map((n) => `cwe-${n}`),
		},
	];
};

/** Parses `bandit -f json` output. */
export const parseBanditReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] =>
	isRecord(json)
		? arr(json.results).flatMap((r) => banditFinding(r, root))
		: [];

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
			const ignored = (yield* gitignoredPaths(ws)).map((p) =>
				p.endsWith("/") ? `${ws.root}/${p}*` : `${ws.root}/${p}`,
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
					[
						"*/node_modules/*,*/.venv/*,*/venv/*,*/.git/*,*/site-packages/*",
						...ignored,
					].join(","),
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

/** gosec's string `line`/`column`, when it is a number. */
const gosecNumber = (value: unknown): number | undefined => {
	const n = Number.parseInt(str(value) ?? "", 10);
	return Number.isFinite(n) ? n : undefined;
};

/** The CWE id of a gosec issue, when it is numeric. */
const gosecCwe = (i: Record<string, unknown>): string[] => {
	const cwe = str(recordOf(i.cwe).id);
	return cwe && /^\d+$/.test(cwe) ? [cwe] : [];
};

const gosecFinding = (i: unknown, root: FilePath): FindingInput[] => {
	if (!isRecord(i) || i.nosec === true) return [];
	const rule = str(i.rule_id) ?? "G000";
	const cwe = gosecCwe(i);
	const line = gosecNumber(i.line);
	const details = str(i.details) ?? rule;
	const confidence = labelConfidence(i.confidence);
	// G101 = hardcoded credentials: the snippet is the secret.
	const snippet = rule === "G101" ? undefined : excerptLine(i.code, line);
	return [
		{
			ruleId: `code.gosec/${rule.toLowerCase()}`,
			title: truncate(details, 100),
			severity: discount(labelSeverity(i.severity), confidence),
			category: "security",
			message: `${details} (gosec ${rule})`,
			location: {
				file: relPath(root, str(i.file)),
				line,
				column: gosecNumber(i.column),
			},
			evidence: snippet ? truncate(scrubLine(snippet)) : undefined,
			remediation:
				"See the gosec rule documentation for the recommended fix, or annotate a justified false positive with `#nosec`.",
			references: [
				`https://securego.io/docs/rules/${rule.toLowerCase()}.html`,
				...cwe.map((n) => cweUrl(Number(n))),
			],
			confidence,
			tags: cwe.map((n) => `cwe-${n}`),
		},
	];
};

/** Parses `gosec -fmt json` output. */
export const parseGosecReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] =>
	isRecord(json) ? arr(json.Issues).flatMap((i) => gosecFinding(i, root)) : [];

/** Runs gosec over the Go module in `dir`. */
const gosecModule = (
	ctx: AuditContext,
	ws: Workspace,
	bin: FilePath,
	dir: FilePath,
) =>
	Effect.gen(function* () {
		// GOTOOLCHAIN=local: a target's go.mod `toolchain` line must not make
		// go download and run another toolchain. No cgo: no C compiler runs.
		// No -quiet: with it gosec prints nothing both for a clean module and
		// for one it could not load, and only the JSON tells them apart.
		const res = yield* ctx.exec.run(
			[bin, "-fmt", "json", "-no-fail", "./..."],
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
		if (!res.stdout.trim()) return [];
		const json = yield* parseJson(res.stdout, "gosec");
		const loadError = gosecLoadError(json);
		if (loadError)
			return yield* Effect.fail(
				new AuditorError({
					message: `gosec could not load the Go packages in ${dir === "." ? "the root module" : dir}: ${truncate(loadError, 300)}`,
				}),
			);
		return parseGosecReport(json, ws.root);
	});

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
			for (const dir of modules)
				findings.push(...(yield* gosecModule(ctx, ws, bin, dir)));
			return findings;
		}),
});

/**
 * The first package-loading error when gosec analysed no file at all (for
 * example go.mod needs a newer Go than the one installed), else undefined.
 */
export const gosecLoadError = (json: unknown): string | undefined => {
	if (!isRecord(json)) return undefined;
	if (recordOf(json.Stats).files !== 0) return undefined;
	return Object.values(recordOf(json["Golang errors"]))
		.flatMap((list) => arr(list))
		.filter(isRecord)
		.map((e) => e.error)
		.find((e): e is string => typeof e === "string")
		?.trim();
};

/* -------------------------------------------------------------------------- */
/*                                  brakeman                                  */
/* -------------------------------------------------------------------------- */

/** Brakeman warning types whose `code` can contain credentials. */
const BRAKEMAN_SECRET_TYPES = /basic auth|secret|password|hardcoded/i;

/** Dependency hygiene warnings (outdated Rails, end-of-life versions). */
const BRAKEMAN_DEPENDENCY_TYPES = /dependency|rails \d|eol|end of life/i;

/**
 * Confidence is brakeman's only signal: High -> high, Medium -> medium,
 * Weak -> low. Dependency hygiene warnings are capped at medium.
 */
const brakemanSeverity = (
	dependency: boolean,
	confidence: Confidence,
): Severity => {
	if (dependency) return confidence === "low" ? "low" : "medium";
	return confidence;
};

/** The warning's file relative to the workspace, from one relative to the app. */
const brakemanFile = (
	root: FilePath,
	prefix: FilePath,
	file: string | undefined,
): string | undefined => {
	if (!file) return undefined;
	return relPath(root, prefix ? `${prefix}/${file}` : file);
};

/** The flagged code, unless the warning type means it can hold a credential. */
const brakemanEvidence = (
	code: string | undefined,
	type: string,
): string | undefined =>
	code && !BRAKEMAN_SECRET_TYPES.test(type)
		? truncate(scrubLine(code))
		: undefined;

/**
 * Parses `brakeman -f json` output. `prefix` is the Rails app directory
 * relative to the workspace root (brakeman reports paths relative to the app).
 */
export const parseBrakemanReport = (
	json: unknown,
	root: FilePath,
	prefix = "",
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.warnings).flatMap((w) => {
		if (!isRecord(w)) return [];
		const type = str(w.warning_type) ?? "Warning";
		const cwe = arr(w.cwe_id).filter((n): n is number => typeof n === "number");
		const link = str(w.link);
		const confidence = labelConfidence(str(w.confidence)?.toLowerCase());
		const dependency = BRAKEMAN_DEPENDENCY_TYPES.test(type);
		return [
			{
				ruleId: `code.brakeman/${kebab(type)}`,
				title: `${type}: ${str(w.message) ?? type}`.slice(0, 120),
				severity: brakemanSeverity(dependency, confidence),
				category: dependency ? "supply-chain" : "security",
				message: `${str(w.message) ?? type} (brakeman check ${str(w.check_name) ?? "unknown"})`,
				location: {
					file: brakemanFile(root, prefix, str(w.file)),
					line: num(w.line),
				},
				evidence: brakemanEvidence(str(w.code), type),
				remediation: link
					? `See the brakeman warning documentation: ${link}`
					: "See the brakeman documentation for this warning type.",
				references: [...listOf(link), ...cwe.slice(0, 2).map(cweUrl)],
				confidence,
				tags: cwe.map((n) => `cwe-${n}`),
			},
		];
	});
};

const isAppConfig = (f: FilePath) =>
	f === "config/application.rb" || f.endsWith("/config/application.rb");

const isGemfile = (f: FilePath) => f === "Gemfile" || f.endsWith("/Gemfile");

/**
 * The Rails app directory: the one holding config/application.rb, else that
 * of the first Gemfile that depends on rails.
 */
const railsAppDir = (ws: Workspace, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		const appConfig = files.find(isAppConfig);
		if (appConfig) return dirname(dirname(appConfig));
		for (const gemfile of files.filter(isGemfile).slice(0, FILE_LIMIT)) {
			const text = yield* ws
				.readText(gemfile)
				.pipe(Effect.orElseSucceed(() => ""));
			if (/^\s*gem\s+["']rails["']/m.test(text)) return dirname(gemfile);
		}
		return undefined;
	});

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
			const appDir = yield* railsAppDir(ws, files);
			if (appDir === undefined)
				return yield* skip("No Rails application found");
			// Brakeman refuses (exit 4) a directory without app/.
			const appPrefix = appDir === "." ? "app/" : `${appDir}/app/`;
			if (!files.some((f) => f.startsWith(appPrefix)))
				return yield* skip(
					`The Rails app in ${appDir === "." ? "the root" : appDir} has no app/ directory, which Brakeman needs`,
				);
			const bin = yield* requireTool(
				ctx,
				"brakeman",
				"Install: gem install brakeman or brew install brakeman (https://brakemanscanner.org).",
			);
			// Brakeman reads config/brakeman.yml from the app unless -c names an
			// existing file, and that config can add Ruby check paths that
			// Brakeman loads (code execution). Pass an empty config instead.
			const config = join(
				tmpdir(),
				`openaudit-brakeman-${crypto.randomUUID()}.yml`,
			);
			yield* Effect.promise(() => Bun.write(config, "---\n{}\n"));
			const res = yield* runTool(
				ctx,
				[
					bin,
					"-c",
					config,
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
			).pipe(
				Effect.ensuring(Effect.promise(() => rm(config, { force: true }))),
			);
			return parseBrakemanReport(
				yield* parseJson(res.stdout, "brakeman"),
				ws.root,
				appDir === "." ? "" : appDir,
			);
		}),
});
