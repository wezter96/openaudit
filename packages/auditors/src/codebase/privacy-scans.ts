import type { FindingInput } from "@openaudit/core";

import { type Tracker, trackerForUrl } from "../privacy-data";
import {
	type CodeSite,
	codeSites,
	contextMatches,
	evidenceOf,
	type FilePath,
	type FileScan,
	fileScan,
	finding,
	isHtmlLike,
	isJs,
	isUiSource,
	type LineNumber,
	type Offset,
	type SourceLine,
	type SourceText,
} from "./privacy-shared";
import { baseName, cweUrl, isCommentLine, type SourceFile } from "./util";

export interface Sighting {
	readonly path: FilePath;
	readonly line?: LineNumber;
	readonly via: string;
}

/** A tracking-account ID such as `G-XXXXXXXXXX`. */
export type TrackingId = string;
/** A tracker's name in the shared list. */
export type TrackerName = string;

export const isEnvFile = (path: FilePath) =>
	/^\.env(\.|$)/.test(baseName(path));

/** A script element or loader line, so a tracker URL in code is a real load. */
const LOADS_SCRIPT =
	/\bsrc\s*[=:]|createElement\(\s*['"]script|loadScript|<script|\.src\s*=|appendChild|import\(\s*['"]https?:/i;
const URL_IN_LINE = /(?:https?:)?\/\/[^\s"'`)<>\\]+/g;

/* --------------------------------- rules ---------------------------------- */

interface ReplayRule {
	re: RegExp;
	what: string;
	needs?: RegExp;
}

const REPLAY_UNMASKED: ReadonlyArray<ReplayRule> = [
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

interface TrackingIdRule {
	name: string;
	/** Tracker (by name in the shared list) the ID belongs to. */
	tracker: TrackerName;
	/** The capture group holds the id; otherwise the whole match does. */
	re: RegExp;
	needs?: RegExp;
}

const TRACKING_IDS: ReadonlyArray<TrackingIdRule> = [
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

/* -------------------------------- scanning -------------------------------- */

const replayFinding = (
	scan: FileScan,
	rule: ReplayRule,
	site: CodeSite,
): FindingInput =>
	finding({
		ruleId: "code.privacy/session-replay-unmasked",
		title: "Session replay configured without masking",
		severity: "medium",
		message: `Session recording is configured with masking turned off: ${rule.what}. Recordings can then contain credentials, health or payment data and identify visitors without their knowledge.`,
		location: { file: scan.path, line: scan.lineOf(site.index) },
		evidence: evidenceOf(site.line),
		remediation:
			"Keep input masking on (maskAllInputs: true), mask or block sensitive elements by selector, record only after consent and exclude checkout, account and health pages.",
		references: [cweUrl(359)],
		confidence: "medium",
		tags: ["cwe-359", "gdpr", "session-replay"],
	});

export const scanReplayMasking = (file: SourceFile): FindingInput[] => {
	if (!isJs(file.path) && !isHtmlLike(file.path)) return [];
	const scan = fileScan(file);
	return REPLAY_UNMASKED.filter((rule) =>
		contextMatches(rule.needs, scan.text),
	).flatMap((rule) =>
		codeSites(scan.text, rule.re).map((site) =>
			replayFinding(scan, rule, site),
		),
	);
};

/** Whether a line can load a script by URL (markup loads anything it names). */
const mayLoadScript = (line: SourceLine, html: boolean) => {
	if (!line.includes("//") || isCommentLine(line)) return false;
	return html || LOADS_SCRIPT.test(line);
};

const trackersInLine = (line: SourceLine): Tracker[] =>
	[...line.matchAll(URL_IN_LINE)].flatMap((m) => {
		const url = m[0].startsWith("//") ? `https:${m[0]}` : m[0];
		const tracker = trackerForUrl(url);
		return tracker ? [tracker] : [];
	});

/** Trackers loaded by URL from markup or script-loading code. */
export const scanTrackerUrls = (
	file: SourceFile,
): Array<[Tracker, Sighting]> => {
	const { text, path } = file;
	const html = isHtmlLike(path);
	if (!html && !isJs(path)) return [];
	return text
		.split("\n")
		.flatMap((line, n) =>
			mayLoadScript(line, html)
				? trackersInLine(line).map((tracker): [Tracker, Sighting] => [
						tracker,
						{ path, line: n + 1, via: "script reference" },
					])
				: [],
		);
};

export interface IdHit {
	readonly id: TrackingId;
	readonly tracker: TrackerName;
	readonly finding: FindingInput;
}

/** The text around an ID that its context pattern must appear in. */
const idWindow = (text: SourceText, index: Offset, id: TrackingId) =>
	text.slice(Math.max(0, index - 300), index + 300 + id.length);

const trackingIdHit = (
	scan: FileScan,
	rule: TrackingIdRule,
	site: CodeSite,
): IdHit[] => {
	const id = site.match[1] ?? site.match[0];
	if (!contextMatches(rule.needs, idWindow(scan.text, site.index, id)))
		return [];
	return [
		{
			id,
			tracker: rule.tracker,
			finding: finding({
				ruleId: "code.privacy/tracking-id",
				title: `${rule.name} hard-coded`,
				severity: "info",
				message: `${rule.name} ${id} is hard-coded. It is public by design, not a secret, but it shows which tracking accounts the project reports to; list them in your records of processing and make sure they load only after consent.`,
				location: { file: scan.path, line: scan.lineOf(site.index) },
				evidence: evidenceOf(site.line),
				remediation:
					"Move the ID to configuration per environment so that staging and test builds do not report to production accounts.",
				references: ["https://gdpr-info.eu/art-30-gdpr/"],
				tags: ["gdpr", "ropa"],
			}),
		},
	];
};

export const scanTrackingIds = (file: SourceFile): IdHit[] => {
	if (!isUiSource(file.path) && !isEnvFile(file.path)) return [];
	const scan = fileScan(file);
	return TRACKING_IDS.flatMap((rule) =>
		codeSites(scan.text, rule.re).flatMap((site) =>
			trackingIdHit(scan, rule, site),
		),
	);
};

const loadsGoogleFonts = (line: SourceLine) =>
	GOOGLE_FONTS.test(line) && !CSP_LINE.test(line);

export const scanGoogleFonts = (file: SourceFile): FindingInput[] => {
	if (!isUiSource(file.path)) return [];
	const lines = file.text.split("\n");
	const n = lines.findIndex(
		(line) => loadsGoogleFonts(line) && !isCommentLine(line),
	);
	if (n === -1) return [];
	return [
		finding({
			ruleId: "code.privacy/google-fonts",
			title: "Google Fonts loaded from Google's servers",
			severity: "low",
			message:
				"Fonts are fetched from fonts.googleapis.com / fonts.gstatic.com, so every visitor's IP address is sent to Google. A German court held this to violate GDPR without consent (LG München I, 3 O 17493/20).",
			location: { file: file.path, line: n + 1 },
			evidence: evidenceOf(lines[n] ?? ""),
			remediation:
				"Self-host the font files (download them, serve them from your own origin, or use a bundler/framework font loader that does so at build time).",
			references: ["https://developers.google.com/fonts/faq/privacy"],
			confidence: "medium",
			tags: ["gdpr"],
		}),
	];
};
