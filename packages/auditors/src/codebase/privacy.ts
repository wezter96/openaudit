import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { TRACKERS, type Tracker, type TrackerKind } from "../privacy-data";
import { scanPiiInLogs } from "./privacy-logs";
import {
	dependenciesOf,
	lockfilePackages,
	type Manifest,
	manifestOf,
	NPM_LOCKFILE,
	trackerForPackage,
} from "./privacy-manifests";
import {
	type IdHit,
	isEnvFile,
	type Sighting,
	scanGoogleFonts,
	scanReplayMasking,
	scanTrackerUrls,
	scanTrackingIds,
	type TrackerName,
	type TrackingId,
} from "./privacy-scans";
import {
	type FilePath,
	finding,
	isCode,
	isUiSource,
	type PackageName,
} from "./privacy-shared";
import {
	isFixturePath,
	isGeneratedPath,
	isLockfile,
	isTestPath,
	lineLocator,
	readTextFiles,
	type SourceFile,
	truncate,
} from "./util";

export { maskPersonalData } from "./privacy-shared";

const isExcludedPath = (path: FilePath) =>
	isTestPath(path) ||
	isFixturePath(path) ||
	isGeneratedPath(path) ||
	/(^|\/)(node_modules|docs?|examples?)\//.test(path);

const isScannedKind = (path: FilePath) =>
	manifestOf(path) !== undefined ||
	isUiSource(path) ||
	isCode(path) ||
	isEnvFile(path);

const shouldRead = (path: FilePath) =>
	!isExcludedPath(path) && isScannedKind(path);

const isNpmLockfile = (path: FilePath) =>
	NPM_LOCKFILE.test(path) &&
	isLockfile(path) &&
	!path.includes("node_modules/");

/* ------------------------------- SDK inventory ------------------------------- */

interface TrackerSightings {
	tracker: Tracker;
	at: Sighting[];
}

type SightingMap = Map<TrackerName, TrackerSightings>;

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

const byKindThenName = (a: TrackerSightings, b: TrackerSightings) =>
	KIND_ORDER.indexOf(a.tracker.kind) - KIND_ORDER.indexOf(b.tracker.kind) ||
	a.tracker.name.localeCompare(b.tracker.name);

const inventorySummary = (entries: TrackerSightings[]) => {
	const byKind = new Map<string, TrackerSightings[]>();
	for (const e of entries)
		byKind.set(e.tracker.kind, [...(byKind.get(e.tracker.kind) ?? []), e]);
	return [...byKind]
		.map(
			([kind, list]) =>
				`${KIND_LABEL[kind] ?? kind}: ${list.map((e) => `${e.tracker.name} (${where(e.at[0] as Sighting)}${e.at.length > 1 ? ` +${e.at.length - 1}` : ""})`).join(", ")}`,
		)
		.join("; ");
};

const inventoryFinding = (entries: TrackerSightings[]): FindingInput => {
	const first = entries[0]?.at[0] as Sighting;
	return finding({
		ruleId: "code.privacy/tracking-sdk-inventory",
		title: `${entries.length} analytics, advertising or tracking SDK${entries.length === 1 ? "" : "s"} in use`,
		severity: "info",
		message: `Third-party SDKs that collect usage or device data: ${inventorySummary(entries)}. Use this list for the privacy policy, the records of processing (GDPR Art. 30) and the consent configuration; each one needs a legal basis and, for most, a data-processing agreement.`,
		location: { file: first.path, line: first.line },
		evidence: truncate(entries.map((e) => e.tracker.name).join(", "), 200),
		remediation:
			"Confirm each SDK is still needed, disclose it, and load non-essential ones only after consent.",
		references: [
			"https://gdpr-info.eu/art-30-gdpr/",
			"https://gdpr-info.eu/art-13-gdpr/",
		],
		tags: ["gdpr", "ropa"],
	});
};

/** Wording for the SDK kinds that get a finding of their own. */
interface HighImpactKind {
	readonly ruleId: string;
	readonly label: string;
	readonly message: (name: TrackerName) => string;
	readonly remediation: string;
}

const HIGH_IMPACT = new Map<TrackerKind, HighImpactKind>([
	[
		"session-replay",
		{
			ruleId: "code.privacy/session-replay-sdk",
			label: "session replay",
			message: (name) =>
				`${name} records what visitors see and type. It can capture credentials, health and payment data unless masking is configured, and in the EU it needs prior consent.`,
			remediation:
				"Mask all inputs and sensitive elements, exclude sensitive pages, record only after consent and set a short retention.",
		},
	],
	[
		"fingerprinting",
		{
			ruleId: "code.privacy/fingerprinting-sdk",
			label: "device fingerprinting",
			message: (name) =>
				`${name} builds a persistent device identifier from browser and hardware traits. That identifies people across sites without cookies and needs prior consent in the EU (ePrivacy Art. 5(3)), plus a clear purpose such as fraud prevention.`,
			remediation:
				"Use it only for a documented purpose such as fraud prevention, load it after consent where required and disclose it in the privacy policy.",
		},
	],
]);

const highImpactFindings = ({
	tracker,
	at,
}: TrackerSightings): FindingInput[] => {
	const kind = HIGH_IMPACT.get(tracker.kind);
	if (!kind) return [];
	const site = at[0] as Sighting;
	return [
		finding({
			ruleId: kind.ruleId,
			title: `${tracker.name} (${kind.label}) in use`,
			severity: "low",
			message: kind.message(tracker.name),
			location: { file: site.path, line: site.line },
			evidence: truncate(`${tracker.name} via ${where(site)}`, 200),
			remediation: kind.remediation,
			references: [
				"https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en",
			],
			confidence: "high",
			tags: ["gdpr", "eprivacy", tracker.kind],
		}),
	];
};

/** Exported for tests: builds the SDK inventory and its high-impact findings. */
export const sdkFindings = (
	sightings: ReadonlyMap<string, TrackerSightings>,
): FindingInput[] => {
	if (sightings.size === 0) return [];
	const entries = [...sightings.values()].sort(byKindThenName);
	return [inventoryFinding(entries), ...entries.flatMap(highImpactFindings)];
};

/* -------------------------------- collecting -------------------------------- */

/** What the scan has found so far across files. */
interface Collected {
	readonly sightings: SightingMap;
	readonly findings: FindingInput[];
	/** Tracking IDs already reported, so each is reported once. */
	readonly ids: Set<TrackingId>;
}

const addSighting = (
	sightings: SightingMap,
	tracker: Tracker,
	at: Sighting,
) => {
	const entry = sightings.get(tracker.name) ?? { tracker, at: [] };
	if (!entry.at.some((s) => s.path === at.path && s.via === at.via))
		entry.at.push(at);
	sightings.set(tracker.name, entry);
};

const manifestSighting = (file: SourceFile, name: PackageName): Sighting => {
	const at = file.text.indexOf(name);
	return {
		path: file.path,
		line: at === -1 ? undefined : lineLocator(file.text)(at),
		via: "manifest",
	};
};

const collectManifest = (c: Collected, file: SourceFile, eco: Manifest) => {
	for (const name of dependenciesOf(eco, file.text)) {
		const tracker = trackerForPackage(eco, name);
		if (tracker)
			addSighting(c.sightings, tracker, manifestSighting(file, name));
	}
};

const collectTrackingId = (c: Collected, file: SourceFile, hit: IdHit) => {
	const tracker = TRACKERS.find((t) => t.name === hit.tracker);
	if (tracker)
		addSighting(c.sightings, tracker, {
			path: file.path,
			line: hit.finding.location?.line,
			via: "tracking ID",
		});
	// One finding per distinct ID, at its first location.
	if (c.ids.has(hit.id)) return;
	c.ids.add(hit.id);
	c.findings.push(hit.finding);
};

const collectSource = (c: Collected, file: SourceFile) => {
	for (const [tracker, at] of scanTrackerUrls(file))
		addSighting(c.sightings, tracker, at);
	for (const hit of scanTrackingIds(file)) collectTrackingId(c, file, hit);
	c.findings.push(
		...scanGoogleFonts(file),
		...scanReplayMasking(file),
		...scanPiiInLogs(file),
	);
};

const collectFile = (c: Collected, file: SourceFile) => {
	const eco = manifestOf(file.path);
	if (eco) collectManifest(c, file, eco);
	else collectSource(c, file);
};

/** Lockfiles only reveal SDKs no manifest declares (transitive or dev). */
const collectLockfile = (sightings: SightingMap, lock: SourceFile) => {
	for (const name of new Set(lockfilePackages(lock.path, lock.text))) {
		const tracker = trackerForPackage("npm", name);
		if (tracker && !sightings.has(tracker.name))
			addSighting(sightings, tracker, {
				path: lock.path,
				via: "lockfile only: transitive or dev dependency",
			});
	}
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
			const lockfiles = yield* readTextFiles(ws, isNpmLockfile, {
				limit: 40,
				maxBytes: 8 * 1024 * 1024,
			});
			const collected: Collected = {
				sightings: new Map(),
				findings: [],
				ids: new Set(),
			};
			for (const file of files) collectFile(collected, file);
			for (const lock of lockfiles) collectLockfile(collected.sightings, lock);
			return [...sdkFindings(collected.sightings), ...collected.findings];
		}),
});
