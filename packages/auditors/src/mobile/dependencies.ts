import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";
import type { UnzipFileInfo } from "fflate";

import {
	type Dependency,
	type Ecosystem,
	osvFindings,
	type VulnWording,
	vulnFinding,
} from "../codebase/dependencies";
import { asDict, type PlistDict, parsePlist } from "./plist";
import { loadMobileTarget, type MobileArtifact, utf8 } from "./shared";

/**
 * Supply-chain inventory and advisory lookup for built mobile artifacts.
 *
 * Android: the Android Gradle plugin and Google libraries leave version
 * markers in the APK/AAB: `META-INF/<group>_<artifact>.version` (androidx,
 * Material, Play Services, Firebase, ...), `META-INF/maven/**\/pom.properties`
 * and `firebase-*.properties` / `play-services-*.properties`. They map
 * directly to Maven coordinates, which OSV indexes.
 *
 * iOS: embedded frameworks only carry a bundle id and version. Bundle ids do
 * not map reliably to a package registry (CocoaPods is not an OSV ecosystem,
 * and SwiftPM needs the repository URL), so they are inventoried, not queried.
 */

/** Components kept per artifact (a hostile zip could list millions of names). */
const MAX_COMPONENTS = 2000;
const MAX_MARKER_BYTES = 64 * 1024;
const MAX_LISTED = 200;

export interface Component {
	readonly group?: string;
	readonly name: string;
	readonly version: string;
	/** Entry inside the artifact the version was read from. */
	readonly entry: string;
	readonly source:
		| "version-file"
		| "pom-properties"
		| "client-properties"
		| "framework";
	/** Bundle identifier, iOS frameworks only. */
	readonly bundleId?: string;
}

/** Path of an entry inside the artifact, such as `META-INF/foo.version`. */
type EntryPath = string;
/** Decoded contents of a version marker. */
type MarkerText = string;
/** Workspace path of the artifact. */
type ArtifactFile = string;
/** Folder name of an embedded iOS framework, without `.framework`. */
type FrameworkName = string;

const coordinate = (c: Component) =>
	c.group ? `${c.group}:${c.name}` : c.name;

const VERSION_RE = /^\d[\w.+-]{0,63}$/;

/** `META-INF/androidx.core_core.version` → androidx.core:core. */
export const parseVersionFile = (
	entry: EntryPath,
	text: MarkerText,
): Component | undefined => {
	const file = entry.split("/").pop() ?? "";
	const [, group, name] =
		/^([A-Za-z][\w.-]*?)_([\w.-]+)\.version$/.exec(file) ?? [];
	const version = (text.split(/\r?\n/, 1)[0] ?? "").trim();
	if (!group || !name) return undefined;
	if (!VERSION_RE.test(version)) return undefined;
	return {
		group,
		name,
		version,
		entry,
		source: "version-file",
	};
};

const parseProperties = (text: MarkerText): Record<string, string> => {
	const out: Record<string, string> = {};
	for (const raw of text.split(/\r?\n/)) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const eq = line.indexOf("=");
		if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
	}
	return out;
};

/** `META-INF/maven/<group>/<artifact>/pom.properties`. */
export const parsePomProperties = (
	entry: EntryPath,
	text: MarkerText,
): Component | undefined => {
	const props = parseProperties(text);
	const [, pathGroup, pathName] =
		/META-INF\/maven\/([^/]+)\/([^/]+)\/pom\.properties$/.exec(entry) ?? [];
	const group = props.groupId ?? pathGroup;
	const name = props.artifactId ?? pathName;
	const version = props.version ?? "";
	if (!group || !name) return undefined;
	if (!VERSION_RE.test(version)) return undefined;
	return { group, name, version, entry, source: "pom-properties" };
};

const GOOGLE_CLIENT_GROUPS: ReadonlyArray<readonly [RegExp, string]> = [
	[/^firebase-/, "com.google.firebase"],
	[/^play-services-/, "com.google.android.gms"],
];

/**
 * `firebase-common.properties` / `play-services-base.properties`:
 * `client=firebase-common`, `firebase-common_client=20.3.2` and sometimes
 * `version=20.3.2`.
 */
export const parseClientProperties = (
	entry: EntryPath,
	text: MarkerText,
): Component | undefined => {
	const file = (entry.split("/").pop() ?? "").replace(/\.properties$/, "");
	const group = GOOGLE_CLIENT_GROUPS.find(([re]) => re.test(file))?.[1];
	if (!group) return undefined;
	const props = parseProperties(text);
	const name = props.client ?? file;
	const version = props[`${name}_client`] ?? props.version ?? "";
	if (!VERSION_RE.test(version)) return undefined;
	return { group, name, version, entry, source: "client-properties" };
};

const ANDROID_MARKER =
	/^(?:(?:base|[^/]+)\/root\/)?(?:META-INF\/(?:[^/]+\.version|maven\/[^/]+\/[^/]+\/pom\.properties)|(?:firebase|play-services)-[^/]+\.properties)$/;
const IOS_FRAMEWORK =
	/^Payload\/[^/]+\.app\/Frameworks\/([^/]+)\.framework\/Info\.plist$/;

const parseMarker = (entry: EntryPath, text: MarkerText) =>
	entry.endsWith(".version")
		? parseVersionFile(entry, text)
		: entry.endsWith("pom.properties")
			? parsePomProperties(entry, text)
			: parseClientProperties(entry, text);

export const androidComponents = (
	entries: Record<string, Uint8Array>,
): Component[] => {
	const seen = new Map<string, Component>();
	for (const entry of Object.keys(entries).sort()) {
		const component = parseMarker(
			entry,
			utf8(entries[entry] ?? new Uint8Array()),
		);
		if (!component) continue;
		const key = `${coordinate(component)}@${component.version}`;
		if (!seen.has(key) && seen.size < MAX_COMPONENTS) seen.set(key, component);
	}
	return [...seen.values()];
};

const plistString = (v: unknown) => (typeof v === "string" ? v : undefined);

const readFrameworkInfo = (bytes: Uint8Array): PlistDict | undefined => {
	try {
		return asDict(parsePlist(bytes));
	} catch {
		return undefined;
	}
};

const frameworkComponent = (
	entry: EntryPath,
	folder: FrameworkName,
	info: PlistDict,
): Component | undefined => {
	const version =
		plistString(info.CFBundleShortVersionString) ??
		plistString(info.CFBundleVersion);
	if (!version) return undefined;
	const bundleId = plistString(info.CFBundleIdentifier);
	return {
		name: plistString(info.CFBundleName) ?? folder,
		version: version.slice(0, 64),
		entry,
		source: "framework",
		...(bundleId ? { bundleId: bundleId.slice(0, 200) } : {}),
	};
};

export const iosComponents = (
	entries: Record<string, Uint8Array>,
): Component[] => {
	const out: Component[] = [];
	for (const entry of Object.keys(entries).sort()) {
		const folder = IOS_FRAMEWORK.exec(entry)?.[1];
		if (!folder) continue;
		const info = readFrameworkInfo(entries[entry] ?? new Uint8Array());
		const component = info && frameworkComponent(entry, folder, info);
		if (component) out.push(component);
	}
	return out.slice(0, MAX_COMPONENTS);
};

/* ------------------------------ OSV findings ------------------------------- */

// `Ecosystem` in code.dependencies does not list Maven yet, but OSV accepts it
// and the batch/detail helpers only forward the string.
const MAVEN = "Maven" as unknown as Ecosystem;

const asDependency = (c: Component, file: ArtifactFile): Dependency => ({
	name: coordinate(c),
	version: c.version,
	ecosystem: MAVEN,
	file: `${file}!/${c.entry}`,
});

const MOBILE_VULN: VulnWording = {
	ruleId: "mobile.dependencies/vulnerable-dependency",
	affected: "is bundled in the app and affected by",
	upgrade:
		" in the app's Gradle dependencies, then rebuild. If the library is pulled in transitively, add a constraint or upgrade the parent SDK.",
	tags: ["owasp-mobile-m2"],
};

type Platform = "android" | "ios";

/** Inventory wording per platform. */
const INVENTORY: Record<
	Platform,
	{
		readonly ruleId: string;
		readonly title: (count: number) => string;
		readonly message: (file: ArtifactFile, count: number) => string;
		readonly confidence: "medium" | "high";
	}
> = {
	android: {
		ruleId: "mobile.dependencies/sdk-inventory",
		title: (n) => `${n} bundled libraries identified`,
		message: (file, n) =>
			`Version markers in ${file} identify ${n} libraries (androidx, Material, Play Services, Firebase and Maven artifacts that ship META-INF version files). Libraries without markers, such as obfuscated or shaded ones, are not listed.`,
		confidence: "medium",
	},
	ios: {
		ruleId: "mobile.dependencies/ios-framework-inventory",
		title: (n) => `${n} embedded frameworks identified`,
		message: (file, n) =>
			`${file} embeds ${n} frameworks. They are inventoried only: iOS bundle identifiers do not map reliably to a package registry, so advisories are not looked up.`,
		confidence: "high",
	},
};

const componentLabel = (c: Component) =>
	c.source === "framework"
		? `${c.name}@${c.version}${c.bundleId ? ` (${c.bundleId})` : ""}`
		: `${coordinate(c)}@${c.version}`;

const inventoryFinding = (
	file: ArtifactFile,
	platform: Platform,
	components: ReadonlyArray<Component>,
): FindingInput => {
	const wording = INVENTORY[platform];
	const lines = components.slice(0, MAX_LISTED).map(componentLabel);
	const more =
		components.length > MAX_LISTED
			? `\n… and ${components.length - MAX_LISTED} more`
			: "";
	return {
		ruleId: wording.ruleId,
		title: wording.title(components.length),
		severity: "info",
		category: "supply-chain",
		message: wording.message(file, components.length),
		location: { file },
		evidence: `${lines.join("\n")}${more}`,
		remediation:
			"Keep this list as the app's software bill of materials and review it when SDKs are updated.",
		confidence: wording.confidence,
		tags: ["sbom", platform],
	};
};

const isFrameworkInfo = (name: EntryPath, info: UnzipFileInfo) =>
	IOS_FRAMEWORK.test(name) && info.originalSize < MAX_MARKER_BYTES;

const isAndroidMarker = (name: EntryPath, info: UnzipFileInfo) =>
	ANDROID_MARKER.test(name) && info.originalSize < MAX_MARKER_BYTES;

const iosInventory = (target: MobileArtifact) =>
	Effect.gen(function* () {
		const frameworks = iosComponents(target.extract(isFrameworkInfo));
		if (frameworks.length === 0)
			return yield* skip(
				`${target.file} embeds no frameworks (Payload/*.app/Frameworks/*.framework)`,
			);
		return [inventoryFinding(target.file, "ios", frameworks)];
	});

const androidFindings = (ctx: AuditContext, target: MobileArtifact) =>
	Effect.gen(function* () {
		const libraries = androidComponents(target.extract(isAndroidMarker));
		if (libraries.length === 0)
			return yield* skip(
				`${target.file} has no library version markers (META-INF/*.version, pom.properties)`,
			);
		const findings: FindingInput[] = [
			inventoryFinding(target.file, "android", libraries),
		];

		const deps = libraries.map((c) => asDependency(c, target.file));
		yield* ctx.log(
			`mobile.dependencies: querying OSV for ${deps.length} libraries`,
		);
		findings.push(
			...(yield* osvFindings(ctx.http, deps, (d, id, vuln) =>
				vulnFinding(MOBILE_VULN, d, id, vuln),
			)),
		);
		return findings;
	});

export const mobileDependencies = defineAuditor({
	id: "mobile.dependencies",
	title: "Mobile dependencies",
	description:
		"Identifies bundled Android libraries from META-INF version markers (androidx, Material, Play Services, Firebase, pom.properties) and checks their Maven coordinates against OSV.dev, and inventories iOS frameworks. Emits an info-level SBOM inventory. Works on built APK/AAB/IPA files only; use code.dependencies for source trees.",
	categories: ["supply-chain", "security"],
	targets: ["mobile"],
	engine: "builtin",
	network: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const target = yield* loadMobileTarget(ctx);
			if (target.kind !== "artifact")
				return yield* skip(
					"Target is a source tree, not a built APK/AAB/IPA (code.dependencies covers lockfiles)",
				);
			if (target.type === "ipa") return yield* iosInventory(target);
			return yield* androidFindings(ctx, target);
		}),
});
