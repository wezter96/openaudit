import {
	type AuditorError,
	MAX_TEXT_BYTES,
	redact,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import type {
	CharCount,
	CweId,
	FilePath,
	Language,
	Offset,
	SourceText,
	StandardId,
} from "./util-types";

export { nonCodeMask } from "./util-noncode";

/** Shared helpers for codebase auditors: file selection, reading, matching. */

/** Max files any single codebase auditor reads, to stay fast on huge repos. */
export const MAX_SCAN_FILES = 5000;
/** Files larger than this are never read as text by codebase auditors. */
export const MAX_SCAN_BYTES = 1024 * 1024;

const BINARY_EXTENSIONS = new Set([
	"png",
	"jpg",
	"jpeg",
	"gif",
	"bmp",
	"ico",
	"icns",
	"tif",
	"tiff",
	"webp",
	"avif",
	"heic",
	"psd",
	"ai",
	"sketch",
	"fig",
	"mp3",
	"mp4",
	"m4a",
	"m4v",
	"mov",
	"avi",
	"mkv",
	"webm",
	"wav",
	"ogg",
	"flac",
	"ttf",
	"otf",
	"woff",
	"woff2",
	"eot",
	"zip",
	"gz",
	"tgz",
	"bz2",
	"xz",
	"7z",
	"rar",
	"jar",
	"war",
	"ear",
	"class",
	"dex",
	"apk",
	"aab",
	"ipa",
	"so",
	"dylib",
	"dll",
	"exe",
	"bin",
	"o",
	"a",
	"lib",
	"wasm",
	"pyc",
	"pyo",
	"pdf",
	"doc",
	"docx",
	"xls",
	"xlsx",
	"ppt",
	"pptx",
	"db",
	"sqlite",
	"sqlite3",
	"lockb",
	"node",
	"keystore",
	"jks",
	"p12",
	"pfx",
	"der",
]);

/** Lowercase extension without the dot (`""` for none or dotfiles). */
export const extOf = (path: FilePath): string => {
	const base = baseName(path);
	const dot = base.lastIndexOf(".");
	return dot <= 0 ? "" : base.slice(dot + 1).toLowerCase();
};

export const baseName = (path: FilePath): string =>
	path.slice(path.lastIndexOf("/") + 1);

export const isBinaryPath = (path: FilePath): boolean =>
	BINARY_EXTENSIONS.has(extOf(path));

const LOCKFILE =
	/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|Pipfile\.lock|uv\.lock|Gemfile\.lock|composer\.lock|go\.sum|packages\.lock\.json|pubspec\.lock|Podfile\.lock|mix\.lock|flake\.lock)$/;

export const isLockfile = (path: FilePath): boolean => LOCKFILE.test(path);

export const isMinifiedPath = (path: FilePath): boolean =>
	/[.-]min\.(m?js|css)$|[.-]bundle\.m?js$|\.(map|chunk\.js)$/.test(path);

/** Long lines with little whitespace: bundled or minified output. */
export const looksMinified = (text: SourceText): boolean => {
	if (text.length < 4000) return false;
	const sample = text.slice(0, 20_000);
	const lines = sample.split("\n");
	const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
	return longest > 3000 || sample.length / lines.length > 400;
};

const TEST_PATH =
	/(^|\/)(__tests__|__mocks__|tests?|spec|specs|e2e|cypress|playwright)\/|(^|\/)[^/]*[._-](test|spec|stories|story)\.[^/]+$|(^|\/)test_[^/]+\.py$|_test\.(go|py|rb)$|(^|\/)[^/]*Tests?\.(java|kt|cs|swift)$/;

/** Test and story sources. */
export const isTestPath = (path: FilePath): boolean => TEST_PATH.test(path);

/** Test fixtures and snapshots: often intentionally insecure or fake data. */
export const isFixturePath = (path: FilePath): boolean =>
	/(^|\/)(fixtures?|__fixtures__|testdata|test-data|__snapshots__|mocks?)\//.test(
		path,
	);

/** Generated or vendored code that the project does not maintain by hand. */
export const isGeneratedPath = (path: FilePath): boolean =>
	/\.d\.[cm]?ts$|[._-](gen|generated|pb)\.\w+$|(^|\/)(generated|__generated__|third[_-]party|bower_components|vendor)\//.test(
		path,
	);

/** Extensions of hand-written source code, by language. */
export const LANGUAGE_BY_EXT: Readonly<Record<string, string>> = {
	js: "js",
	jsx: "js",
	mjs: "js",
	cjs: "js",
	ts: "js",
	tsx: "js",
	mts: "js",
	cts: "js",
	vue: "js",
	svelte: "js",
	astro: "js",
	py: "python",
	go: "go",
	php: "php",
	rb: "ruby",
	java: "java",
	kt: "java",
	scala: "java",
	cs: "csharp",
	rs: "rust",
	swift: "swift",
	c: "c",
	h: "c",
	cc: "c",
	cpp: "c",
	hpp: "c",
	dart: "dart",
};

export const languageOf = (path: FilePath): Language | undefined =>
	LANGUAGE_BY_EXT[extOf(path)];

export const isSourcePath = (path: FilePath): boolean =>
	languageOf(path) !== undefined;

export interface SourceFile {
	readonly path: string;
	readonly text: string;
}

export interface ReadOptions {
	readonly limit?: number;
	readonly maxBytes?: number;
	/** Keep minified/bundled files (default false). */
	readonly allowMinified?: boolean;
}

const isMinified = (file: SourceFile): boolean =>
	isMinifiedPath(file.path) || looksMinified(file.text);

/** Whether a file's text is worth scanning: no NUL bytes, minified only on request. */
const keepFile = (file: SourceFile, options: ReadOptions): boolean => {
	if (file.text.includes("\u0000")) return false;
	return options.allowMinified === true || !isMinified(file);
};

const readSourceFile = (
	ws: Workspace,
	path: FilePath,
	options: ReadOptions,
): Effect.Effect<SourceFile | undefined> =>
	Effect.gen(function* () {
		const size = yield* ws.size(path);
		if (size === 0 || size > (options.maxBytes ?? MAX_SCAN_BYTES))
			return undefined;
		// readText refuses files over MAX_TEXT_BYTES; callers that allow
		// more (lockfiles, up to 20 MB) read the bytes instead.
		const text =
			size > MAX_TEXT_BYTES
				? new TextDecoder().decode(yield* ws.readBytes(path))
				: yield* ws.readText(path);
		const file: SourceFile = { path, text };
		return keepFile(file, options) ? file : undefined;
	}).pipe(Effect.orElseSucceed(() => undefined));

/**
 * Reads up to `limit` text files whose path satisfies `include`, skipping
 * binaries, empty/oversized files, NUL-containing content and minified output.
 * Per-file read errors are ignored; only listing failures propagate.
 */
export const readTextFiles = (
	ws: Workspace,
	include: (path: FilePath) => boolean,
	options: ReadOptions = {},
): Effect.Effect<ReadonlyArray<SourceFile>, AuditorError> =>
	Effect.gen(function* () {
		const limit = options.limit ?? MAX_SCAN_FILES;
		const paths = (yield* ws.files)
			.filter((f) => !isBinaryPath(f) && include(f))
			.slice(0, limit);
		const read = yield* Effect.forEach(
			paths,
			(path) => readSourceFile(ws, path, options),
			{ concurrency: 16 },
		);
		return read.filter((f): f is SourceFile => f !== undefined);
	});

/** Offsets at which each line of `text` starts. */
const lineStarts = (text: SourceText): Offset[] => {
	const starts = [0];
	for (let i = 0; i < text.length; i++) {
		if (text.charCodeAt(i) === 10) starts.push(i + 1);
	}
	return starts;
};

/** 1-based line of `index`, by binary search over line starts. */
const lineOfOffset = (starts: ReadonlyArray<Offset>, index: Offset): number => {
	let lo = 0;
	let hi = starts.length - 1;
	while (lo < hi) {
		const mid = (lo + hi + 1) >> 1;
		if ((starts[mid] ?? 0) <= index) lo = mid;
		else hi = mid - 1;
	}
	return lo + 1;
};

/** Returns a fast `index → 1-based line` lookup for `text`. */
export const lineLocator = (text: SourceText): ((index: Offset) => number) => {
	const starts = lineStarts(text);
	return (index) => lineOfOffset(starts, index);
};

/** The full (untrimmed) line containing `index`. */
export const fullLineAt = (text: SourceText, index: Offset): string => {
	const start = text.lastIndexOf("\n", index - 1) + 1;
	const end = text.indexOf("\n", index);
	return text.slice(start, end === -1 ? undefined : end);
};

/** True for lines that are entirely a comment in C-like, hash or HTML syntax. */
export const isCommentLine = (line: SourceText): boolean =>
	/^\s*(\/\/|\/\*|\*|#(?![[!{])|<!--|--\s)/.test(line);

/** Truncates evidence to a readable length. */
export const truncate = (s: SourceText, max: CharCount = 160): string => {
	const t = s.trim();
	return t.length > max ? `${t.slice(0, max)}…` : t;
};

/** Shannon entropy in bits per character. */
export const shannonEntropy = (s: SourceText): number => {
	if (!s) return 0;
	const counts = new Map<string, number>();
	for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
	let h = 0;
	for (const n of counts.values()) {
		const p = n / s.length;
		h -= p * Math.log2(p);
	}
	return h;
};

export { parseJsonc } from "@openaudit/core";

export const isRecord = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);

/* ------------------------------- references ------------------------------- */

export const cweUrl = (id: CweId) =>
	`https://cwe.mitre.org/data/definitions/${id}.html`;

const OWASP_2021: Readonly<Record<string, string>> = {
	a01: "A01_2021-Broken_Access_Control",
	a02: "A02_2021-Cryptographic_Failures",
	a03: "A03_2021-Injection",
	a04: "A04_2021-Insecure_Design",
	a05: "A05_2021-Security_Misconfiguration",
	a06: "A06_2021-Vulnerable_and_Outdated_Components",
	a07: "A07_2021-Identification_and_Authentication_Failures",
	a08: "A08_2021-Software_and_Data_Integrity_Failures",
	a09: "A09_2021-Security_Logging_and_Monitoring_Failures",
	a10: "A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
};

/** OWASP Top 10 (2021) page for a category such as `a03`. */
export const owaspUrl = (category: StandardId) =>
	`https://owasp.org/Top10/${OWASP_2021[category.toLowerCase()] ?? ""}/`;

const OWASP_LLM_2025: Readonly<Record<string, string>> = {
	llm01: "llm01-prompt-injection",
	llm02: "llm022025-sensitive-information-disclosure",
	llm03: "llm032025-supply-chain",
	llm04: "llm042025-data-and-model-poisoning",
	llm05: "llm052025-improper-output-handling",
	llm06: "llm062025-excessive-agency",
	llm07: "llm072025-system-prompt-leakage",
	llm08: "llm082025-vector-and-embedding-weaknesses",
	llm09: "llm092025-misinformation",
	llm10: "llm102025-unbounded-consumption",
};

/** OWASP Top 10 for LLM Applications (2025) page for a risk such as `llm01`. */
export const owaspLlmUrl = (risk: StandardId) =>
	`https://genai.owasp.org/llmrisk/${OWASP_LLM_2025[risk.toLowerCase()] ?? ""}/`;

const WCAG_SLUGS: Readonly<Record<string, string>> = {
	"1.1.1": "non-text-content",
	"1.3.1": "info-and-relationships",
	"1.4.4": "resize-text",
	"2.1.1": "keyboard",
	"2.4.3": "focus-order",
	"2.4.4": "link-purpose-in-context",
	"2.4.7": "focus-visible",
	"3.1.1": "language-of-page",
	"3.2.1": "on-focus",
	"3.3.2": "labels-or-instructions",
	"4.1.2": "name-role-value",
};

/** WCAG 2.2 "Understanding" page for a success criterion such as `1.1.1`. */
export const wcagUrl = (sc: StandardId) =>
	`https://www.w3.org/WAI/WCAG22/Understanding/${WCAG_SLUGS[sc] ?? ""}.html`;

/** Converts an arbitrary identifier to kebab-case for rule ids. */
export const kebab = (s: SourceText): string =>
	s
		.replace(/([a-z0-9])([A-Z])/g, "$1-$2")
		.replace(/[^A-Za-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.toLowerCase();

/* ------------------------------- scrubbing -------------------------------- */

/** Token shapes that are credentials wherever they appear. */
const CREDENTIAL_PATTERNS: ReadonlyArray<RegExp> = [
	/\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
	/\bgh[pousr]_[A-Za-z0-9]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}/g,
	/\bgl(?:pat|dt|rt|ptt|cbt)-[A-Za-z0-9_-]{20,}/g,
	/\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
	/https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9/]+/g,
	/\b(?:sk|rk)_live_[A-Za-z0-9]{10,}/g,
	/\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g,
	/\bAIza[0-9A-Za-z_-]{35}/g,
	/\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
	/\bnpm_[A-Za-z0-9]{36}\b/g,
	/\bSK[0-9a-f]{32}\b/g,
	/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];

/** `user:password@` in URLs. */
const URL_CREDENTIALS = /(:\/\/[^:/\s"'`@]+:)([^@\s"'`/]+)@/g;

/** `secretish_name = value` (quoted or not). */
const SECRET_ASSIGNMENT =
	/((?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth|credential|private[_-]?key|signing[_-]?key|bearer)[\w.-]*["']?\s*(?::=|=>|=|:)\s*["'`]?)([^\s"'`,;]{4,})/gi;

/** Long base64/hex-like runs that mix letters and digits (key material). */
const KEY_MATERIAL = /[A-Za-z0-9+/=_-]{32,}/g;

/** A credential, or a fragment of text that may hold one. */
type Secret = string;

const maskKnownSecrets = (
	line: SourceText,
	known: ReadonlyArray<Secret>,
): SourceText => {
	let out = line;
	for (const secret of known)
		if (secret) out = out.split(secret).join(redact(secret));
	return out;
};

const maskUrlPassword = (_m: SourceText, pre: SourceText, pw: Secret) =>
	pw.includes("*") ? `${pre}${pw}@` : `${pre}${redact(pw, 0)}@`;

const maskAssignedSecret = (_m: SourceText, pre: SourceText, value: Secret) =>
	/^\w{0,4}\*+$|^redacted$/i.test(value)
		? `${pre}${value}`
		: `${pre}${redact(value)}`;

/** Key material mixes letters and digits and is not already masked. */
const isKeyMaterial = (m: Secret): boolean =>
	/\d/.test(m) && /[A-Za-z]/.test(m) && !m.includes("*");

const maskKeyMaterial = (m: Secret) => (isKeyMaterial(m) ? redact(m) : m);

/**
 * Masks every credential-looking value in a line so it is safe to put into
 * evidence. `known` secrets (e.g. the one that triggered a finding) are
 * always masked, wherever they occur.
 */
export const scrubLine = (
	line: SourceText,
	known: ReadonlyArray<Secret> = [],
): string => {
	let out = maskKnownSecrets(line, known);
	out = out.replace(
		/(-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----).*/g,
		"$1****",
	);
	out = out.replace(URL_CREDENTIALS, maskUrlPassword);
	for (const re of CREDENTIAL_PATTERNS) out = out.replace(re, (m) => redact(m));
	out = out.replace(SECRET_ASSIGNMENT, maskAssignedSecret);
	out = out.replace(KEY_MATERIAL, maskKeyMaterial);
	return out;
};
