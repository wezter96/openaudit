import {
	type AuditorError,
	MAX_TEXT_BYTES,
	redact,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

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
export const extOf = (path: string): string => {
	const base = baseName(path);
	const dot = base.lastIndexOf(".");
	return dot <= 0 ? "" : base.slice(dot + 1).toLowerCase();
};

export const baseName = (path: string): string =>
	path.slice(path.lastIndexOf("/") + 1);

export const isBinaryPath = (path: string): boolean =>
	BINARY_EXTENSIONS.has(extOf(path));

const LOCKFILE =
	/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|Pipfile\.lock|uv\.lock|Gemfile\.lock|composer\.lock|go\.sum|packages\.lock\.json|pubspec\.lock|Podfile\.lock|mix\.lock|flake\.lock)$/;

export const isLockfile = (path: string): boolean => LOCKFILE.test(path);

export const isMinifiedPath = (path: string): boolean =>
	/[.-]min\.(m?js|css)$|[.-]bundle\.m?js$|\.(map|chunk\.js)$/.test(path);

/** Long lines with little whitespace: bundled or minified output. */
export const looksMinified = (text: string): boolean => {
	if (text.length < 4000) return false;
	const sample = text.slice(0, 20_000);
	const lines = sample.split("\n");
	const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
	return longest > 3000 || sample.length / lines.length > 400;
};

const TEST_PATH =
	/(^|\/)(__tests__|__mocks__|tests?|spec|specs|e2e|cypress|playwright)\/|(^|\/)[^/]*[._-](test|spec|stories|story)\.[^/]+$|(^|\/)test_[^/]+\.py$|_test\.(go|py|rb)$|(^|\/)[^/]*Tests?\.(java|kt|cs|swift)$/;

/** Test and story sources. */
export const isTestPath = (path: string): boolean => TEST_PATH.test(path);

/** Test fixtures and snapshots: often intentionally insecure or fake data. */
export const isFixturePath = (path: string): boolean =>
	/(^|\/)(fixtures?|__fixtures__|testdata|test-data|__snapshots__|mocks?)\//.test(
		path,
	);

/** Generated or vendored code that the project does not maintain by hand. */
export const isGeneratedPath = (path: string): boolean =>
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

export const languageOf = (path: string): string | undefined =>
	LANGUAGE_BY_EXT[extOf(path)];

export const isSourcePath = (path: string): boolean =>
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

/**
 * Reads up to `limit` text files whose path satisfies `include`, skipping
 * binaries, empty/oversized files, NUL-containing content and minified output.
 * Per-file read errors are ignored; only listing failures propagate.
 */
export const readTextFiles = (
	ws: Workspace,
	include: (path: string) => boolean,
	options: ReadOptions = {},
): Effect.Effect<ReadonlyArray<SourceFile>, AuditorError> =>
	Effect.gen(function* () {
		const limit = options.limit ?? MAX_SCAN_FILES;
		const maxBytes = options.maxBytes ?? MAX_SCAN_BYTES;
		const paths = (yield* ws.files)
			.filter((f) => !isBinaryPath(f) && include(f))
			.slice(0, limit);
		const read = yield* Effect.forEach(
			paths,
			(path) =>
				Effect.gen(function* () {
					const size = yield* ws.size(path);
					if (size === 0 || size > maxBytes) return undefined;
					// readText refuses files over MAX_TEXT_BYTES; callers that allow
					// more (lockfiles, up to 20 MB) read the bytes instead.
					const text =
						size > MAX_TEXT_BYTES
							? new TextDecoder().decode(yield* ws.readBytes(path))
							: yield* ws.readText(path);
					if (text.includes("\u0000")) return undefined;
					if (
						!options.allowMinified &&
						(isMinifiedPath(path) || looksMinified(text))
					)
						return undefined;
					return { path, text } satisfies SourceFile;
				}).pipe(Effect.orElseSucceed(() => undefined)),
			{ concurrency: 16 },
		);
		return read.filter((f): f is SourceFile => f !== undefined);
	});

/** Returns a fast `index → 1-based line` lookup for `text`. */
export const lineLocator = (text: string): ((index: number) => number) => {
	const starts = [0];
	for (let i = 0; i < text.length; i++) {
		if (text.charCodeAt(i) === 10) starts.push(i + 1);
	}
	return (index) => {
		let lo = 0;
		let hi = starts.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if ((starts[mid] ?? 0) <= index) lo = mid;
			else hi = mid - 1;
		}
		return lo + 1;
	};
};

/** The full (untrimmed) line containing `index`. */
export const fullLineAt = (text: string, index: number): string => {
	const start = text.lastIndexOf("\n", index - 1) + 1;
	const end = text.indexOf("\n", index);
	return text.slice(start, end === -1 ? undefined : end);
};

/** True for lines that are entirely a comment in C-like, hash or HTML syntax. */
export const isCommentLine = (line: string): boolean =>
	/^\s*(\/\/|\/\*|\*|#(?![[!{])|<!--|--\s)/.test(line);

/** Truncates evidence to a readable length. */
export const truncate = (s: string, max = 160): string => {
	const t = s.trim();
	return t.length > max ? `${t.slice(0, max)}…` : t;
};

/** Shannon entropy in bits per character. */
export const shannonEntropy = (s: string): number => {
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

/**
 * Parses JSON with comments and trailing commas (tsconfig, bun.lock).
 * Returns undefined when the text is not valid JSONC.
 */
export const parseJsonc = (text: string): unknown => {
	let out = "";
	let i = 0;
	const n = text.length;
	while (i < n) {
		const ch = text[i];
		if (ch === '"') {
			let j = i + 1;
			while (j < n && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
			out += text.slice(i, j + 1);
			i = j + 1;
		} else if (ch === "/" && text[i + 1] === "/") {
			while (i < n && text[i] !== "\n") i++;
		} else if (ch === "/" && text[i + 1] === "*") {
			const end = text.indexOf("*/", i + 2);
			i = end === -1 ? n : end + 2;
		} else if (ch === ",") {
			let j = i + 1;
			while (j < n && /\s/.test(text[j] ?? "")) j++;
			if (text[j] !== "}" && text[j] !== "]") out += ch;
			i++;
		} else {
			out += ch;
			i++;
		}
	}
	try {
		return JSON.parse(out);
	} catch {
		return undefined;
	}
};

export const isRecord = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);

/* ------------------------------- references ------------------------------- */

export const cweUrl = (id: number) =>
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
export const owaspUrl = (category: string) =>
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
export const owaspLlmUrl = (risk: string) =>
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
export const wcagUrl = (sc: string) =>
	`https://www.w3.org/WAI/WCAG22/Understanding/${WCAG_SLUGS[sc] ?? ""}.html`;

/** Converts an arbitrary identifier to kebab-case for rule ids. */
export const kebab = (s: string): string =>
	s
		.replace(/([a-z0-9])([A-Z])/g, "$1-$2")
		.replace(/[^A-Za-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.toLowerCase();

/* ---------------------------- string/comment mask --------------------------- */

const REGEX_PRECEDER =
	/[(,=:[!&|?{};+\-*%<>~^]$|(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|void|yield|await|delete|throw|new)$/;

/**
 * Marks characters inside string literals, comments and (JS) regex literals
 * with 1, so pattern matches in prose can be ignored. Opening delimiters stay
 * 0, so rules may still match on a quote. `${...}` inside JS templates is code.
 * Best-effort lexer: it never throws and degrades to "code" on odd input.
 */
export const nonCodeMask = (text: string, lang: string): Uint8Array => {
	const mask = new Uint8Array(text.length);
	const n = text.length;
	const slashComments = lang !== "python" && lang !== "ruby";
	const hashComments = lang === "python" || lang === "ruby" || lang === "php";
	const templates = lang === "js" || lang === "go";
	const triple = lang === "python";
	const fill = (from: number, to: number) =>
		mask.fill(1, from, Math.min(to, n));

	const lineEnd = (i: number) => {
		const e = text.indexOf("\n", i);
		return e === -1 ? n : e;
	};

	const scanQuoted = (i: number, quote: string): number => {
		let j = i + 1;
		while (j < n && text[j] !== quote && text[j] !== "\n")
			j += text[j] === "\\" ? 2 : 1;
		fill(i + 1, j);
		return j + 1;
	};

	const scanTemplate = (i: number): number => {
		let j = i + 1;
		let segment = j;
		while (j < n) {
			const ch = text[j];
			if (ch === "\\") j += 2;
			else if (ch === "`") break;
			else if (lang === "js" && ch === "$" && text[j + 1] === "{") {
				fill(segment, j);
				j = scanCode(j + 2, true);
				segment = j;
			} else j++;
		}
		fill(segment, j);
		return j + 1;
	};

	const scanRegex = (i: number): number => {
		let j = i + 1;
		let inClass = false;
		while (j < n && text[j] !== "\n") {
			const ch = text[j];
			if (ch === "\\") j++;
			else if (ch === "[") inClass = true;
			else if (ch === "]") inClass = false;
			else if (ch === "/" && !inClass) break;
			j++;
		}
		if (j >= n || text[j] === "\n") return i + 1; // not a regex after all
		fill(i, j + 1);
		return j + 1;
	};

	function scanCode(start: number, untilBrace: boolean): number {
		let i = start;
		let depth = 0;
		let prev = "";
		while (i < n) {
			const ch = text[i] ?? "";
			const next = text[i + 1];
			if (slashComments && ch === "/" && next === "/") {
				const e = lineEnd(i);
				fill(i, e);
				i = e;
				continue;
			}
			if (slashComments && ch === "/" && next === "*") {
				const e = text.indexOf("*/", i + 2);
				const end = e === -1 ? n : e + 2;
				fill(i, end);
				i = end;
				continue;
			}
			if (hashComments && ch === "#" && !(lang === "ruby" && next === "{")) {
				const e = lineEnd(i);
				fill(i, e);
				i = e;
				continue;
			}
			if (triple && (text.startsWith('"""', i) || text.startsWith("'''", i))) {
				const q = text.slice(i, i + 3);
				const e = text.indexOf(q, i + 3);
				const end = e === -1 ? n : e;
				fill(i + 3, end);
				i = end + 3;
				prev = "x";
				continue;
			}
			if (ch === '"' || ch === "'") {
				i = scanQuoted(i, ch);
				prev = "x";
				continue;
			}
			if (templates && ch === "`") {
				i = scanTemplate(i);
				prev = "x";
				continue;
			}
			if (lang === "js" && ch === "/" && REGEX_PRECEDER.test(prev.trimEnd())) {
				const after = scanRegex(i);
				if (after > i + 1) {
					i = after;
					prev = "x";
					continue;
				}
			}
			if (untilBrace) {
				if (ch === "{") depth++;
				else if (ch === "}") {
					if (depth === 0) return i + 1;
					depth--;
				}
			}
			if (!/\s/.test(ch)) prev = (prev + ch).slice(-8);
			else if (prev && !prev.endsWith(" ")) prev = `${prev} `.slice(-8);
			i++;
		}
		return n;
	}

	scanCode(0, false);
	return mask;
};

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

/**
 * Masks every credential-looking value in a line so it is safe to put into
 * evidence. `known` secrets (e.g. the one that triggered a finding) are
 * always masked, wherever they occur.
 */
export const scrubLine = (
	line: string,
	known: ReadonlyArray<string> = [],
): string => {
	let out = line;
	for (const secret of known)
		if (secret) out = out.split(secret).join(redact(secret));
	out = out.replace(
		/(-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----).*/g,
		"$1****",
	);
	out = out.replace(URL_CREDENTIALS, (_m, pre: string, pw: string) =>
		pw.includes("*") ? `${pre}${pw}@` : `${pre}${redact(pw, 0)}@`,
	);
	for (const re of CREDENTIAL_PATTERNS) out = out.replace(re, (m) => redact(m));
	out = out.replace(SECRET_ASSIGNMENT, (_m, pre: string, value: string) =>
		/^\w{0,4}\*+$|^redacted$/i.test(value)
			? `${pre}${value}`
			: `${pre}${redact(value)}`,
	);
	out = out.replace(KEY_MATERIAL, (m) =>
		/\d/.test(m) && /[A-Za-z]/.test(m) && !m.includes("*") ? redact(m) : m,
	);
	return out;
};
