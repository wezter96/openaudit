import type { FindingInput } from "@openaudit/core";

import {
	evidenceOf,
	type FilePath,
	type FileScan,
	fileScan,
	finding,
	type LineNumber,
	type Offset,
	type SourceLine,
	type SourceText,
} from "./privacy-shared";
import {
	cweUrl,
	fullLineAt,
	isCommentLine,
	languageOf,
	nonCodeMask,
	type SourceFile,
	truncate,
} from "./util";

/* ------------------------------ PII in logs ------------------------------- */

type LogLang = "js" | "python" | "go" | "ruby" | "java";
/** The argument text of a logging call. */
type CallArgs = string;
/** An identifier found in code. */
type Identifier = string;
/** A single source character. */
type Char = string;

const LOG_CALLS: Record<LogLang, ReadonlyArray<RegExp>> = {
	js: [
		/(?<![\w$])console\.(?:log|info|warn|error|debug|trace)(?=\s*\()/g,
		/(?<![\w$])[\w$.]*[lL]og(?:ger)?\.(?:log|info|warn|error|debug|trace|fatal|verbose|silly|notice)(?=\s*\()/g,
	],
	python: [
		/(?<![\w.])print(?=\s*\()/g,
		/(?<![\w])(?:logging|[\w.]*(?:logger|log|LOGGER))\.(?:debug|info|warning|warn|error|critical|exception)(?=\s*\()/g,
	],
	go: [
		/\b(?:log|fmt)\.(?:Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)(?=\s*\()/g,
		/\b[\w.]*(?:[lL]og|[lL]ogger|[sS]ugar)\.(?:Info|Warn|Error|Debug)(?:f|w|ln)?(?=\s*\()/g,
	],
	ruby: [
		/(?<![\w.])(?:puts|Rails\.logger\.(?:debug|info|warn|error|fatal)|logger\.(?:debug|info|warn|error|fatal))(?![\w])/g,
	],
	java: [
		/\b[\w.]*(?:[lL]og|[lL]ogger|LOGGER)\.(?:trace|debug|info|warn|error|fatal)(?=\s*\()/g,
		/\bSystem\.(?:out|err)\.print(?:ln|f)?(?=\s*\()/g,
		/(?<![\w.])Log\.[dviwe](?=\s*\()/g,
		/(?<![\w.])println(?=\s*\()/g,
	],
};

const PII_IDENTIFIER =
	/e-?mail|phone|mobile_?(?:no|num)|(?:^|[^a-z])ssn(?![a-z])|social_?sec|passw(?:or)?d|(?:^|[^a-z])pwd(?![a-z])|(?:^|[^a-z])dob(?![a-z])|birth_?(?:date|day)|date_?of_?birth|credit_?card|card_?(?:number|no|num)|(?:^|[^a-z])cvv|(?:^|[^a-z])iban(?![a-z])|(?:user|home|billing|shipping|street|postal|customer)_?address|address_?line|(?:^|[^a-z])ip(?:_?addr(?:ess)?)?(?![a-z])|client_?ip|remote_?addr|national_?id|passport/i;
const CAMEL_IP = /[a-z]I[pP](?![a-z])/;
/** Identifiers that merely describe PII (flags, counts, types, helpers). */
const BENIGN_IDENTIFIER =
	/^(?:is|has|send|validate|check|verify)[A-Z_]|(?:sent|verified|valid|validation|enabled|count|length|exists|type|domain|template|service|provider|config|queue|worker|error|status|subject|field|label|regex|pattern|schema)$/i;
const MASKING_CALL =
	/(?:mask|redact|hash|anonymi[sz]|sanitiz|obfuscat|scrub|encrypt)\w*\s*\(/i;
const IGNORE_MARKER = /openaudit-ignore|nosec|NOSONAR/;
const QUOTES = new Set(['"', "'", "`"]);

const skipBlanks = (text: SourceText, index: Offset): Offset => {
	let i = index;
	while (text[i] === " " || text[i] === "\t") i++;
	return i;
};

const restOfLine = (text: SourceText, index: Offset): SourceLine => {
	const end = text.indexOf("\n", index);
	return text.slice(index, end === -1 ? undefined : end);
};

/** Position and state while looking for the `)` that closes a call. */
interface ParenScan {
	at: Offset;
	depth: number;
	quote: string;
}

const stepInQuote = (scan: ParenScan, ch: Char) => {
	if (ch === "\\") scan.at++;
	else if (ch === scan.quote) scan.quote = "";
};

/** Advances past one code character; true when it closes the call. */
const stepInCode = (scan: ParenScan, ch: Char): boolean => {
	if (QUOTES.has(ch)) scan.quote = ch;
	else if (ch === "(") scan.depth++;
	else if (ch === ")") return --scan.depth === 0;
	return false;
};

/** Index of the `)` matching the `(` at `open`, or -1 before `limit`. */
const closingParen = (
	text: SourceText,
	open: Offset,
	limit: Offset,
): Offset => {
	const scan: ParenScan = { at: open, depth: 0, quote: "" };
	for (; scan.at < limit; scan.at++) {
		const ch = text[scan.at] ?? "";
		if (scan.quote) stepInQuote(scan, ch);
		else if (stepInCode(scan, ch)) return scan.at;
	}
	return -1;
};

/** Text inside the balanced parentheses of a call starting at `index`, or the rest of the line. */
const callArguments = (
	text: SourceText,
	index: Offset,
	lang: LogLang,
): CallArgs => {
	const i = skipBlanks(text, index);
	if (text[i] !== "(") return lang === "ruby" ? restOfLine(text, i) : "";
	const limit = Math.min(text.length, i + 2000);
	const close = closingParen(text, i, limit);
	return text.slice(i + 1, close === -1 ? limit : close);
};

/** Index just past the `}` matching the `{` at `open`. */
const closeBrace = (s: CallArgs, open: Offset): Offset => {
	let depth = 0;
	for (let i = open; i < s.length; i++) {
		if (s[i] === "{") depth++;
		else if (s[i] === "}" && --depth === 0) return i + 1;
	}
	return s.length;
};

/** A string literal in call arguments and the interpolation forms it allows. */
interface Literal {
	readonly args: CallArgs;
	readonly quote: string;
	readonly dollarBrace: boolean;
	readonly hashBrace: boolean;
	readonly fstring: boolean;
	readonly javaVariable: boolean;
}

const FSTRING_PREFIX = /(?:^|[^\w])(?:[rR]?[fF]|[fF][rR]?)$/;

const literalAt = (args: CallArgs, start: Offset, lang: LogLang): Literal => {
	const quote = args[start] ?? "";
	const doubleQuoted = quote === '"';
	return {
		args,
		quote,
		dollarBrace: lang !== "go" && lang !== "python",
		hashBrace: lang === "ruby" && doubleQuoted,
		fstring:
			lang === "python" &&
			FSTRING_PREFIX.test(args.slice(Math.max(0, start - 2), start)),
		javaVariable: lang === "java" && doubleQuoted,
	};
};

const isFstringBrace = (args: CallArgs, j: Offset) =>
	args[j] === "{" && args[j + 1] !== "{";

/** Index of the `{` opening an interpolation at `j`, or -1. */
const interpolationOpen = (lit: Literal, j: Offset): Offset => {
	const pair = lit.args.slice(j, j + 2);
	if (pair === "${" && lit.dollarBrace) return j + 1;
	if (pair === "#{" && lit.hashBrace) return j + 1;
	if (lit.fstring && isFstringBrace(lit.args, j)) return j;
	return -1;
};

/** A Java string template's `$name`, padded, or nothing. */
const javaVariableAt = (lit: Literal, j: Offset): CallArgs => {
	if (!lit.javaVariable || lit.args[j] !== "$") return "";
	if (!/[A-Za-z_]/.test(lit.args[j + 1] ?? "")) return "";
	const m = lit.args.slice(j + 1).match(/^\w+/);
	return ` ${m?.[0] ?? ""} `;
};

/** Code kept from one step through a literal, and where the next step starts. */
interface LiteralStep {
	readonly code: CallArgs;
	readonly next: Offset;
}

const literalStep = (lit: Literal, j: Offset): LiteralStep => {
	if (lit.args[j] === "\\") return { code: "", next: j + 2 };
	const open = interpolationOpen(lit, j);
	if (open === -1) return { code: javaVariableAt(lit, j), next: j + 1 };
	const end = closeBrace(lit.args, open);
	return { code: ` ${lit.args.slice(open + 1, end - 1)} `, next: end };
};

/** The interpolated code of the literal opening at `start`, and the index past it. */
const scanLiteral = (lit: Literal, start: Offset): LiteralStep => {
	let code = "";
	let j = start + 1;
	while (j < lit.args.length && lit.args[j] !== lit.quote) {
		const step = literalStep(lit, j);
		code += step.code;
		j = step.next;
	}
	return { code, next: j + 1 };
};

/**
 * Keeps only code from call arguments: string literals are dropped (so
 * "Invalid email" is not a hit) except for their interpolated expressions.
 */
const codeOnly = (args: CallArgs, lang: LogLang): CallArgs => {
	let out = "";
	for (let i = 0; i < args.length; ) {
		const ch = args[i] ?? "";
		if (!QUOTES.has(ch)) {
			out += ch;
			i++;
			continue;
		}
		const literal = scanLiteral(literalAt(args, i, lang), i);
		out += ` ${literal.code} `;
		i = literal.next;
	}
	return out;
};

const looksLikePii = (id: Identifier) =>
	PII_IDENTIFIER.test(id) || CAMEL_IP.test(id);

const piiIdentifier = (expr: CallArgs): Identifier | undefined => {
	if (MASKING_CALL.test(expr)) return undefined;
	return (expr.match(/[A-Za-z_$][\w$]*/g) ?? []).find(
		(id) => looksLikePii(id) && !BENIGN_IDENTIFIER.test(id),
	);
};

const isIgnoredLine = (line: SourceLine) =>
	isCommentLine(line) || IGNORE_MARKER.test(line);

/** A file being scanned for log calls, with the findings so far. */
interface LogScan extends FileScan {
	readonly lang: LogLang;
	readonly mask: Uint8Array;
	readonly out: FindingInput[];
	readonly seen: Set<LineNumber>;
}

const piiInLogsFinding = (
	scan: LogScan,
	id: Identifier,
	lineNo: LineNumber,
	line: SourceLine,
): FindingInput =>
	finding({
		ruleId: "code.privacy/pii-in-logs",
		title: "Personal data may be written to logs",
		severity: "medium",
		message: `A logging call includes \`${truncate(id, 40)}\`, which looks like personal or sensitive data. Logs are copied to third-party aggregators, kept for long periods and widely readable, which defeats access controls and retention limits on the original data.`,
		location: { file: scan.path, line: lineNo },
		evidence: evidenceOf(line),
		remediation:
			"Log opaque identifiers (user id, request id) instead of the value, or mask/hash it before logging. Add a redaction filter to the logger for known field names.",
		references: [
			cweUrl(532),
			"https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		],
		confidence: "low",
		tags: ["cwe-532", "gdpr"],
	});

const checkLogCall = (scan: LogScan, m: RegExpExecArray) => {
	const index = m.index ?? 0;
	if (scan.mask[index] || scan.out.length >= 10) return;
	const line = fullLineAt(scan.text, index);
	if (isIgnoredLine(line)) return;
	const args = callArguments(scan.text, index + m[0].length, scan.lang);
	const id = piiIdentifier(codeOnly(args, scan.lang));
	const lineNo = scan.lineOf(index);
	if (!id || scan.seen.has(lineNo)) return;
	scan.seen.add(lineNo);
	scan.out.push(piiInLogsFinding(scan, id, lineNo, line));
};

const logLanguageOf = (path: FilePath): LogLang | undefined => {
	const lang = languageOf(path) as LogLang | undefined;
	return lang && lang in LOG_CALLS ? lang : undefined;
};

export const scanPiiInLogs = (file: SourceFile): FindingInput[] => {
	const lang = logLanguageOf(file.path);
	if (!lang) return [];
	const scan: LogScan = {
		...fileScan(file),
		lang,
		mask: nonCodeMask(file.text, lang),
		out: [],
		seen: new Set(),
	};
	for (const re of LOG_CALLS[lang])
		for (const m of file.text.matchAll(re)) checkLogCall(scan, m);
	return scan.out;
};
