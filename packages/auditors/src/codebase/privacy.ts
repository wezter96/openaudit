import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	type Ecosystem,
	TRACKERS,
	type Tracker,
	trackerForUrl,
} from "../privacy-data";
import {
	baseName,
	cweUrl,
	extOf,
	fullLineAt,
	isCommentLine,
	isFixturePath,
	isGeneratedPath,
	isLockfile,
	isRecord,
	isTestPath,
	languageOf,
	lineLocator,
	nonCodeMask,
	readTextFiles,
	type SourceFile,
	scrubLine,
	truncate,
} from "./util";

/* ------------------------------ file classes ------------------------------ */

const HTML_EXTS = new Set([
	"html",
	"htm",
	"xhtml",
	"ejs",
	"hbs",
	"handlebars",
	"njk",
	"twig",
	"liquid",
	"erb",
	"jinja",
	"jinja2",
	"j2",
	"cshtml",
	"razor",
	"mustache",
	"pug",
	"php",
]);
const STYLE_EXTS = new Set(["css", "scss", "sass", "less", "styl"]);

type Manifest = Ecosystem;

const manifestOf = (path: string): Manifest | undefined => {
	const base = baseName(path);
	if (base === "package.json") return "npm";
	if (base === "composer.json") return "composer";
	if (base === "pyproject.toml" || base === "Pipfile") return "pypi";
	if (
		/^requirements[^/]*\.txt$/.test(base) ||
		/(^|\/)requirements\/[^/]+\.txt$/.test(path)
	)
		return /dev|test|lint|docs/i.test(base) ? undefined : "pypi";
	if (base === "Podfile") return "pod";
	if (base === "go.mod") return "go";
	if (base === "Gemfile") return "gem";
	if (/^build\.gradle(\.kts)?$|^libs\.versions\.toml$/.test(base))
		return "gradle";
	if (base === "pubspec.yaml") return "pub";
	return undefined;
};

const NPM_LOCKFILE =
	/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$/;

const isEnvFile = (path: string) => /^\.env(\.|$)/.test(baseName(path));

const isHtmlLike = (path: string) => HTML_EXTS.has(extOf(path));
const isStyle = (path: string) => STYLE_EXTS.has(extOf(path));
const isCode = (path: string) => {
	const lang = languageOf(path);
	return (
		lang === "js" ||
		lang === "python" ||
		lang === "go" ||
		lang === "ruby" ||
		lang === "java"
	);
};
const isUiSource = (path: string) =>
	isHtmlLike(path) || isStyle(path) || languageOf(path) === "js";

const shouldRead = (path: string) =>
	!isTestPath(path) &&
	!isFixturePath(path) &&
	!isGeneratedPath(path) &&
	!/(^|\/)(node_modules|docs?|examples?)\//.test(path) &&
	(manifestOf(path) !== undefined ||
		isUiSource(path) ||
		isCode(path) ||
		isEnvFile(path));

/* ------------------------------- SDK inventory ------------------------------- */

const PACKAGE_INDEX = new Map<string, Tracker>();
for (const t of TRACKERS)
	for (const [eco, names] of Object.entries(t.packages ?? {}))
		for (const n of names ?? [])
			PACKAGE_INDEX.set(`${eco}:${n.toLowerCase()}`, t);

const trackerForPackage = (
	eco: Ecosystem,
	name: string,
): Tracker | undefined => {
	const key = name.toLowerCase().replace(/\s+/g, "");
	const exact = PACKAGE_INDEX.get(`${eco}:${key}`);
	if (exact) return exact;
	if (eco === "pypi")
		return PACKAGE_INDEX.get(`${eco}:${key.replace(/_/g, "-")}`);
	// Go modules carry a major-version suffix and sub-packages.
	if (eco === "go")
		for (const [k, t] of PACKAGE_INDEX)
			if (k.startsWith("go:") && key.startsWith(`${k.slice(3)}/`)) return t;
	return undefined;
};

const strings = (text: string, re: RegExp, group = 1): string[] =>
	[...text.matchAll(re)].flatMap((m) => (m[group] ? [m[group]] : []));

const withoutComments = (text: string, marker: RegExp) =>
	text
		.split("\n")
		.filter((l) => !marker.test(l))
		.join("\n");

/** Only the `dependencies:` block of a pubspec; dev_dependencies are not shipped. */
const pubDependencyNames = (text: string): string[] => {
	const names: string[] = [];
	let section = "";
	for (const line of text.split("\n")) {
		const top = line.match(/^([a-z_]+):/);
		if (top) section = top[1] ?? "";
		else if (section === "dependencies") {
			const m = line.match(/^ {2}([a-z0-9_]+):/);
			if (m?.[1]) names.push(m[1]);
		}
	}
	return names;
};

/** Package names a manifest depends on directly. */
const dependenciesOf = (eco: Manifest, text: string): string[] => {
	switch (eco) {
		case "npm":
		case "composer": {
			try {
				const json: unknown = JSON.parse(text);
				if (!isRecord(json)) return [];
				return ["dependencies", "optionalDependencies", "require"].flatMap(
					(k) => {
						const section = json[k];
						return isRecord(section) ? Object.keys(section) : [];
					},
				);
			} catch {
				return [];
			}
		}
		case "pypi": {
			const body = withoutComments(text, /^\s*#/);
			return [
				...strings(
					body,
					/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@]|$)/gm,
				),
				...strings(
					body,
					/["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|["'])/g,
				),
				...strings(body, /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/gm),
			];
		}
		case "pod":
			return strings(
				withoutComments(text, /^\s*#/),
				/^\s*pod\s+['"]([^'"]+)['"]/gm,
			);
		case "gem":
			return strings(
				withoutComments(text, /^\s*#/),
				/^\s*gem\s+['"]([^'"]+)['"]/gm,
			);
		case "go":
			return strings(
				withoutComments(text, /^\s*\/\//),
				/^\s*(?:require\s+)?([\w.-]+\.[\w.-]+\/[\w./~-]+)\s+v\d/gm,
			);
		case "gradle":
			return strings(
				withoutComments(text, /^\s*\/\//),
				/["']([\w.-]+:[\w.-]+)(?::[^"']*)?["']/g,
			);
		case "pub":
			return pubDependencyNames(text);
	}
};

/** Names of every package a JS lockfile pins (direct and transitive). */
const lockfilePackages = (path: string, text: string): string[] => {
	const base = baseName(path);
	if (base === "yarn.lock")
		return strings(text, /^"?((?:@[^/@\s"]+\/)?[^@\s"]+)@/gm);
	if (base === "pnpm-lock.yaml")
		return strings(text, /^\s+'?\/?((?:@[^/@\s':]+\/)?[^@\s':]+)@\d/gm);
	if (base === "bun.lock")
		return strings(text, /^\s+"[^"]+":\s*\["((?:@[^/"]+\/)?[^@"]+)@/gm);
	return strings(text, /"node_modules\/((?:@[^/"]+\/)?[^/"]+)"/g);
};

/** A script element or loader line, so a tracker URL in code is a real load. */
const LOADS_SCRIPT =
	/\bsrc\s*[=:]|createElement\(\s*['"]script|loadScript|<script|\.src\s*=|appendChild|import\(\s*['"]https?:/i;
const URL_IN_LINE = /(?:https?:)?\/\/[^\s"'`)<>\\]+/g;

interface Sighting {
	readonly path: string;
	readonly line?: number;
	readonly via: string;
}

/* --------------------------------- rules ---------------------------------- */

const REPLAY_UNMASKED: ReadonlyArray<{
	re: RegExp;
	what: string;
	needs?: RegExp;
}> = [
	{
		re: /\bmaskAllInputs\s*:\s*false\b/g,
		what: "maskAllInputs is disabled, so typed form input (including passwords and personal data) is recorded",
	},
	{
		re: /\bmaskInputOptions\s*:\s*\{[^}]*\bpassword\s*:\s*false/g,
		what: "password fields are explicitly unmasked in the recording",
	},
	{
		re: /\bmaskAllText\s*:\s*false\b/g,
		what: "maskAllText is disabled, so all on-screen text is recorded",
	},
	{
		re: /\b(?:inputSanitizer|textSanitizer)\s*:\s*false\b/g,
		what: "LogRocket's DOM sanitizer is disabled, so input or text is recorded as typed",
		needs: /logrocket/i,
	},
];

const TRACKING_IDS: ReadonlyArray<{
	name: string;
	/** Tracker (by name in the shared list) the ID belongs to. */
	tracker: string;
	/** The capture group holds the id; otherwise the whole match does. */
	re: RegExp;
	needs?: RegExp;
}> = [
	{
		name: "Google Analytics 4 measurement ID",
		tracker: "Google Analytics",
		re: /\bG-[A-Z0-9]{10}\b/g,
		needs:
			/gtag|googletagmanager|google-analytics|measurement|tracking|analytics|\bga\(/i,
	},
	{
		name: "Universal Analytics property ID",
		tracker: "Google Analytics",
		re: /\bUA-\d{5,10}-\d{1,2}\b/g,
	},
	{
		name: "Google Tag Manager container ID",
		tracker: "Google Tag Manager",
		re: /\bGTM-[A-Z0-9]{5,8}\b/g,
		needs: /gtm|googletagmanager|tag.?manager/i,
	},
	{
		name: "Meta Pixel ID",
		tracker: "Meta Pixel / Facebook SDK",
		re: /fbq\(\s*['"]init['"]\s*,\s*['"`](\d{10,18})['"`]/g,
	},
	{
		name: "Meta Pixel ID",
		tracker: "Meta Pixel / Facebook SDK",
		re: /facebook\.com\/tr\?id=(\d{10,18})/g,
	},
];

const GOOGLE_FONTS = /(?:https?:)?\/\/fonts\.(?:googleapis|gstatic)\.com/;
const CSP_LINE =
	/content-security-policy|\b(?:style|font|connect|default)-src\b/i;

/* ------------------------------ PII in logs ------------------------------- */

type LogLang = "js" | "python" | "go" | "ruby" | "java";

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

/** Text inside the balanced parentheses of a call starting at `index`, or the rest of the line. */
const callArguments = (text: string, index: number, lang: LogLang): string => {
	let i = index;
	while (text[i] === " " || text[i] === "\t") i++;
	if (text[i] !== "(") {
		if (lang !== "ruby") return "";
		const end = text.indexOf("\n", i);
		return text.slice(i, end === -1 ? undefined : end);
	}
	let depth = 0;
	let quote = "";
	const limit = Math.min(text.length, i + 2000);
	for (let j = i; j < limit; j++) {
		const ch = text[j];
		if (quote) {
			if (ch === "\\") j++;
			else if (ch === quote) quote = "";
		} else if (ch === '"' || ch === "'" || ch === "`") quote = ch;
		else if (ch === "(") depth++;
		else if (ch === ")" && --depth === 0) return text.slice(i + 1, j);
	}
	return text.slice(i + 1, limit);
};

/** Index just past the `}` matching the `{` at `open`. */
const closeBrace = (s: string, open: number): number => {
	let depth = 0;
	for (let i = open; i < s.length; i++) {
		if (s[i] === "{") depth++;
		else if (s[i] === "}" && --depth === 0) return i + 1;
	}
	return s.length;
};

/**
 * Keeps only code from call arguments: string literals are dropped (so
 * "Invalid email" is not a hit) except for their interpolated expressions.
 */
const codeOnly = (args: string, lang: LogLang): string => {
	let out = "";
	for (let i = 0; i < args.length; ) {
		const ch = args[i] ?? "";
		if (ch !== '"' && ch !== "'" && ch !== "`") {
			out += ch;
			i++;
			continue;
		}
		const fstring =
			lang === "python" &&
			/(?:^|[^\w])(?:[rR]?[fF]|[fF][rR]?)$/.test(
				args.slice(Math.max(0, i - 2), i),
			);
		let j = i + 1;
		out += " ";
		while (j < args.length && args[j] !== ch) {
			if (args[j] === "\\") {
				j += 2;
				continue;
			}
			const next = args[j + 1];
			let open = -1;
			if (args[j] === "$" && next === "{" && lang !== "go" && lang !== "python")
				open = j + 1;
			else if (args[j] === "#" && next === "{" && lang === "ruby" && ch === '"')
				open = j + 1;
			else if (args[j] === "{" && fstring && next !== "{") open = j;
			if (open !== -1) {
				const end = closeBrace(args, open);
				out += ` ${args.slice(open + 1, end - 1)} `;
				j = end;
				continue;
			}
			if (
				args[j] === "$" &&
				lang === "java" &&
				ch === '"' &&
				/[A-Za-z_]/.test(next ?? "")
			) {
				const m = args.slice(j + 1).match(/^\w+/);
				out += ` ${m?.[0] ?? ""} `;
			}
			j++;
		}
		out += " ";
		i = j + 1;
	}
	return out;
};

const piiIdentifier = (expr: string): string | undefined => {
	if (MASKING_CALL.test(expr)) return undefined;
	return (expr.match(/[A-Za-z_$][\w$]*/g) ?? []).find(
		(id) =>
			(PII_IDENTIFIER.test(id) || CAMEL_IP.test(id)) &&
			!BENIGN_IDENTIFIER.test(id),
	);
};

/* -------------------------------- scanning -------------------------------- */

const finding = (
	f: Omit<FindingInput, "category"> & { category?: FindingInput["category"] },
): FindingInput => ({ category: "privacy", ...f });

const scanPiiInLogs = (file: SourceFile): FindingInput[] => {
	const lang = languageOf(file.path) as LogLang | undefined;
	if (!lang || !(lang in LOG_CALLS)) return [];
	const { text, path } = file;
	const lineOf = lineLocator(text);
	const mask = nonCodeMask(text, lang);
	const out: FindingInput[] = [];
	const seen = new Set<number>();
	for (const re of LOG_CALLS[lang]) {
		for (const m of text.matchAll(re)) {
			const index = m.index ?? 0;
			if (mask[index] || out.length >= 10) continue;
			const line = fullLineAt(text, index);
			if (isCommentLine(line) || /openaudit-ignore|nosec|NOSONAR/.test(line))
				continue;
			const args = callArguments(text, index + m[0].length, lang);
			const id = piiIdentifier(codeOnly(args, lang));
			const lineNo = lineOf(index);
			if (!id || seen.has(lineNo)) continue;
			seen.add(lineNo);
			out.push(
				finding({
					ruleId: "code.privacy/pii-in-logs",
					title: "Personal data may be written to logs",
					severity: "medium",
					message: `A logging call includes \`${truncate(id, 40)}\`, which looks like personal or sensitive data. Logs are copied to third-party aggregators, kept for long periods and widely readable, which defeats access controls and retention limits on the original data.`,
					location: { file: path, line: lineNo },
					evidence: truncate(scrubLine(line)),
					remediation:
						"Log opaque identifiers (user id, request id) instead of the value, or mask/hash it before logging. Add a redaction filter to the logger for known field names.",
					references: [
						cweUrl(532),
						"https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
					],
					confidence: "low",
					tags: ["cwe-532", "gdpr"],
				}),
			);
		}
	}
	return out;
};

const scanReplayMasking = (file: SourceFile): FindingInput[] => {
	if (languageOf(file.path) !== "js" && !isHtmlLike(file.path)) return [];
	const { text, path } = file;
	const lineOf = lineLocator(text);
	const out: FindingInput[] = [];
	for (const rule of REPLAY_UNMASKED) {
		if (rule.needs && !rule.needs.test(text)) continue;
		for (const m of text.matchAll(rule.re)) {
			const index = m.index ?? 0;
			const line = fullLineAt(text, index);
			if (isCommentLine(line)) continue;
			out.push(
				finding({
					ruleId: "code.privacy/session-replay-unmasked",
					title: "Session replay configured without masking",
					severity: "medium",
					message: `Session recording is configured with masking turned off: ${rule.what}. Recordings can then contain credentials, health or payment data and identify visitors without their knowledge.`,
					location: { file: path, line: lineOf(index) },
					evidence: truncate(scrubLine(line)),
					remediation:
						"Keep input masking on (maskAllInputs: true), mask or block sensitive elements by selector, record only after consent and exclude checkout, account and health pages.",
					references: [cweUrl(359)],
					confidence: "medium",
					tags: ["cwe-359", "gdpr", "session-replay"],
				}),
			);
		}
	}
	return out;
};

/** Trackers loaded by URL from markup or script-loading code. */
const scanTrackerUrls = (file: SourceFile): Array<[Tracker, Sighting]> => {
	const { text, path } = file;
	const html = isHtmlLike(path);
	if (!html && languageOf(path) !== "js") return [];
	const out: Array<[Tracker, Sighting]> = [];
	const lines = text.split("\n");
	for (let n = 0; n < lines.length; n++) {
		const line = lines[n] ?? "";
		if (!line.includes("//") || isCommentLine(line)) continue;
		if (!html && !LOADS_SCRIPT.test(line)) continue;
		for (const m of line.matchAll(URL_IN_LINE)) {
			const url = m[0].startsWith("//") ? `https:${m[0]}` : m[0];
			const tracker = trackerForUrl(url);
			if (tracker)
				out.push([tracker, { path, line: n + 1, via: "script reference" }]);
		}
	}
	return out;
};

interface IdHit {
	readonly id: string;
	readonly tracker: string;
	readonly finding: FindingInput;
}

const scanTrackingIds = (file: SourceFile): IdHit[] => {
	if (!isUiSource(file.path) && !isEnvFile(file.path)) return [];
	const { text, path } = file;
	const lineOf = lineLocator(text);
	const out: IdHit[] = [];
	for (const rule of TRACKING_IDS) {
		for (const m of text.matchAll(rule.re)) {
			const index = m.index ?? 0;
			const id = m[1] ?? m[0];
			if (
				rule.needs &&
				!rule.needs.test(
					text.slice(Math.max(0, index - 300), index + 300 + id.length),
				)
			)
				continue;
			const line = fullLineAt(text, index);
			if (isCommentLine(line)) continue;
			out.push({
				id,
				tracker: rule.tracker,
				finding: finding({
					ruleId: "code.privacy/tracking-id",
					title: `${rule.name} hard-coded`,
					severity: "info",
					message: `${rule.name} ${id} is hard-coded. It is public by design, not a secret, but it shows which tracking accounts the project reports to; list them in your records of processing and make sure they load only after consent.`,
					location: { file: path, line: lineOf(index) },
					evidence: truncate(line, 160),
					remediation:
						"Move the ID to configuration per environment so that staging and test builds do not report to production accounts.",
					references: ["https://gdpr-info.eu/art-30-gdpr/"],
					tags: ["gdpr", "ropa"],
				}),
			});
		}
	}
	return out;
};

const scanGoogleFonts = (file: SourceFile): FindingInput[] => {
	if (!isUiSource(file.path)) return [];
	const { text, path } = file;
	const lines = text.split("\n");
	for (let n = 0; n < lines.length; n++) {
		const line = lines[n] ?? "";
		if (!GOOGLE_FONTS.test(line) || isCommentLine(line) || CSP_LINE.test(line))
			continue;
		return [
			finding({
				ruleId: "code.privacy/google-fonts",
				title: "Google Fonts loaded from Google's servers",
				severity: "low",
				message:
					"Fonts are fetched from fonts.googleapis.com / fonts.gstatic.com, so every visitor's IP address is sent to Google. A German court held this to violate GDPR without consent (LG München I, 3 O 17493/20).",
				location: { file: path, line: n + 1 },
				evidence: truncate(line, 160),
				remediation:
					"Self-host the font files (download them, serve them from your own origin, or use a bundler/framework font loader that does so at build time).",
				references: ["https://developers.google.com/fonts/faq/privacy"],
				confidence: "medium",
				tags: ["gdpr"],
			}),
		];
	}
	return [];
};

const KIND_LABEL: Record<string, string> = {
	analytics: "Analytics",
	advertising: "Advertising",
	"session-replay": "Session replay",
	fingerprinting: "Fingerprinting",
	attribution: "Attribution",
	marketing: "Marketing",
	"tag-manager": "Tag manager",
	monitoring: "Error tracking / monitoring",
	"privacy-friendly analytics": "Privacy-friendly analytics",
};

const KIND_ORDER = Object.keys(KIND_LABEL);

const where = (s: Sighting) =>
	`${s.path}${s.line ? `:${s.line}` : ""}${s.via === "manifest" ? "" : ` (${s.via})`}`;

/** Exported for tests: builds the SDK inventory and its high-impact findings. */
export const sdkFindings = (
	sightings: ReadonlyMap<string, { tracker: Tracker; at: Sighting[] }>,
): FindingInput[] => {
	if (sightings.size === 0) return [];
	const out: FindingInput[] = [];
	const entries = [...sightings.values()].sort(
		(a, b) =>
			KIND_ORDER.indexOf(a.tracker.kind) - KIND_ORDER.indexOf(b.tracker.kind) ||
			a.tracker.name.localeCompare(b.tracker.name),
	);
	const byKind = new Map<string, typeof entries>();
	for (const e of entries)
		byKind.set(e.tracker.kind, [...(byKind.get(e.tracker.kind) ?? []), e]);
	const summary = [...byKind]
		.map(
			([kind, list]) =>
				`${KIND_LABEL[kind] ?? kind}: ${list.map((e) => `${e.tracker.name} (${where(e.at[0] as Sighting)}${e.at.length > 1 ? ` +${e.at.length - 1}` : ""})`).join(", ")}`,
		)
		.join("; ");
	const first = entries[0]?.at[0] as Sighting;
	out.push(
		finding({
			ruleId: "code.privacy/tracking-sdk-inventory",
			title: `${entries.length} analytics, advertising or tracking SDK${entries.length === 1 ? "" : "s"} in use`,
			severity: "info",
			message: `Third-party SDKs that collect usage or device data: ${summary}. Use this list for the privacy policy, the records of processing (GDPR Art. 30) and the consent configuration; each one needs a legal basis and, for most, a data-processing agreement.`,
			location: { file: first.path, line: first.line },
			evidence: truncate(entries.map((e) => e.tracker.name).join(", "), 200),
			remediation:
				"Confirm each SDK is still needed, disclose it, and load non-essential ones only after consent.",
			references: [
				"https://gdpr-info.eu/art-30-gdpr/",
				"https://gdpr-info.eu/art-13-gdpr/",
			],
			tags: ["gdpr", "ropa"],
		}),
	);
	for (const { tracker, at } of entries) {
		if (tracker.kind !== "session-replay" && tracker.kind !== "fingerprinting")
			continue;
		const replay = tracker.kind === "session-replay";
		const site = at[0] as Sighting;
		out.push(
			finding({
				ruleId: replay
					? "code.privacy/session-replay-sdk"
					: "code.privacy/fingerprinting-sdk",
				title: `${tracker.name} (${replay ? "session replay" : "device fingerprinting"}) in use`,
				severity: "low",
				message: replay
					? `${tracker.name} records what visitors see and type. It can capture credentials, health and payment data unless masking is configured, and in the EU it needs prior consent.`
					: `${tracker.name} builds a persistent device identifier from browser and hardware traits. That identifies people across sites without cookies and needs prior consent in the EU (ePrivacy Art. 5(3)), plus a clear purpose such as fraud prevention.`,
				location: { file: site.path, line: site.line },
				evidence: truncate(`${tracker.name} via ${where(site)}`, 200),
				remediation: replay
					? "Mask all inputs and sensitive elements, exclude sensitive pages, record only after consent and set a short retention."
					: "Use it only for a documented purpose such as fraud prevention, load it after consent where required and disclose it in the privacy policy.",
				references: [
					"https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en",
				],
				confidence: "high",
				tags: ["gdpr", "eprivacy", tracker.kind],
			}),
		);
	}
	return out;
};

export const privacy = defineAuditor({
	id: "code.privacy",
	title: "Privacy (code)",
	description:
		"Inventories analytics, advertising, attribution, session-replay, fingerprinting and error-tracking SDKs from manifests, lockfiles and markup; flags personal data in log calls, session replay configured without masking, Google Fonts loaded from Google, and hard-coded tracking IDs.",
	categories: ["privacy", "compliance"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, shouldRead);
			const lockfiles = yield* readTextFiles(
				ws,
				(p) =>
					NPM_LOCKFILE.test(p) && isLockfile(p) && !p.includes("node_modules/"),
				{ limit: 40, maxBytes: 8 * 1024 * 1024 },
			);

			const sightings = new Map<string, { tracker: Tracker; at: Sighting[] }>();
			const add = (tracker: Tracker, at: Sighting) => {
				const entry = sightings.get(tracker.name) ?? { tracker, at: [] };
				if (!entry.at.some((s) => s.path === at.path && s.via === at.via))
					entry.at.push(at);
				sightings.set(tracker.name, entry);
			};

			const findings: FindingInput[] = [];
			const ids = new Set<string>();
			for (const file of files) {
				const eco = manifestOf(file.path);
				if (eco) {
					for (const name of dependenciesOf(eco, file.text)) {
						const tracker = trackerForPackage(eco, name);
						if (!tracker) continue;
						const at = file.text.indexOf(name);
						add(tracker, {
							path: file.path,
							line: at === -1 ? undefined : lineLocator(file.text)(at),
							via: "manifest",
						});
					}
					continue;
				}
				for (const [tracker, at] of scanTrackerUrls(file)) add(tracker, at);
				for (const hit of scanTrackingIds(file)) {
					const tracker = TRACKERS.find((t) => t.name === hit.tracker);
					if (tracker)
						add(tracker, {
							path: file.path,
							line: hit.finding.location?.line,
							via: "tracking ID",
						});
					// One finding per distinct ID, at its first location.
					if (!ids.has(hit.id)) {
						ids.add(hit.id);
						findings.push(hit.finding);
					}
				}
				findings.push(
					...scanGoogleFonts(file),
					...scanReplayMasking(file),
					...scanPiiInLogs(file),
				);
			}

			// Lockfiles only reveal SDKs no manifest declares (transitive or dev).
			for (const lock of lockfiles) {
				for (const name of new Set(lockfilePackages(lock.path, lock.text))) {
					const tracker = trackerForPackage("npm", name);
					if (tracker && !sightings.has(tracker.name))
						add(tracker, {
							path: lock.path,
							via: "lockfile only: transitive or dev dependency",
						});
				}
			}
			return [...sdkFindings(sightings), ...findings];
		}),
});
