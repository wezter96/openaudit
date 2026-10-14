import { defineAuditor, type FindingInput, skip } from "@openaudit/core";
import { Effect } from "effect";

import {
	type Dependency,
	type Ecosystem,
	osvFindings,
	type VulnWording,
	vulnFinding,
} from "../codebase/dependencies";
import { asDict, parsePlist } from "./plist";
import { loadMobileTarget, utf8 } from "./shared";

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

const coordinate = (c: Component) =>
	c.group ? `${c.group}:${c.name}` : c.name;

const VERSION_RE = /^\d[\w.+-]{0,63}$/;

/** `META-INF/androidx.core_core.version` → androidx.core:core. */
export const parseVersionFile = (
	entry: string,
	text: string,
): Component | undefined => {
	const file = entry.split("/").pop() ?? "";
	const m = /^([A-Za-z][\w.-]*?)_([\w.-]+)\.version$/.exec(file);
	const version = text.split(/\r?\n/, 1)[0]?.trim() ?? "";
	if (!m?.[1] || !m[2] || !VERSION_RE.test(version)) return undefined;
	return {
		group: m[1],
		name: m[2],
		version,
		entry,
		source: "version-file",
	};
};

const parseProperties = (text: string): Record<string, string> => {
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
	entry: string,
	text: string,
): Component | undefined => {
	const props = parseProperties(text);
	const path = /META-INF\/maven\/([^/]+)\/([^/]+)\/pom\.properties$/.exec(
		entry,
	);
	const group = props.groupId ?? path?.[1];
	const name = props.artifactId ?? path?.[2];
	const version = props.version ?? "";
	if (!group || !name || !VERSION_RE.test(version)) return undefined;
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
	entry: string,
	text: string,
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

export const androidComponents = (
	entries: Record<string, Uint8Array>,
): Component[] => {
	const seen = new Map<string, Component>();
	for (const entry of Object.keys(entries).sort()) {
		const text = utf8(entries[entry] ?? new Uint8Array());
		const component = entry.endsWith(".version")
			? parseVersionFile(entry, text)
			: entry.endsWith("pom.properties")
				? parsePomProperties(entry, text)
				: parseClientProperties(entry, text);
		if (!component) continue;
		const key = `${coordinate(component)}@${component.version}`;
		if (!seen.has(key) && seen.size < MAX_COMPONENTS) seen.set(key, component);
	}
	return [...seen.values()];
};

export const iosComponents = (
	entries: Record<string, Uint8Array>,
): Component[] => {
	const out: Component[] = [];
	for (const entry of Object.keys(entries).sort()) {
		const folder = IOS_FRAMEWORK.exec(entry)?.[1];
		if (!folder) continue;
		let info: ReturnType<typeof asDict>;
		try {
			info = asDict(parsePlist(entries[entry] ?? new Uint8Array()));
		} catch {
			continue;
		}
		const str = (v: unknown) => (typeof v === "string" ? v : undefined);
		const version =
			str(info?.CFBundleShortVersionString) ?? str(info?.CFBundleVersion);
		if (!version) continue;
		const bundleId = str(info?.CFBundleIdentifier);
		out.push({
			name: str(info?.CFBundleName) ?? folder,
			version: version.slice(0, 64),
			entry,
			source: "framework",
			...(bundleId ? { bundleId: bundleId.slice(0, 200) } : {}),
		});
	}
	return out.slice(0, MAX_COMPONENTS);
};

/* ------------------------------ OSV findings ------------------------------- */

// `Ecosystem` in code.dependencies does not list Maven yet, but OSV accepts it
// and the batch/detail helpers only forward the string.
const MAVEN = "Maven" as unknown as Ecosystem;

const asDependency = (c: Component, file: string): Dependency => ({
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

const inventoryFinding = (
	file: string,
	platform: "android" | "ios",
	components: ReadonlyArray<Component>,
): FindingInput => {
	const lines = components
		.slice(0, MAX_LISTED)
		.map((c) =>
			c.source === "framework"
				? `${c.name}@${c.version}${c.bundleId ? ` (${c.bundleId})` : ""}`
				: `${coordinate(c)}@${c.version}`,
		);
	const more =
		components.length > MAX_LISTED
			? `\n… and ${components.length - MAX_LISTED} more`
			: "";
	return {
		ruleId:
			platform === "android"
				? "mobile.dependencies/sdk-inventory"
				: "mobile.dependencies/ios-framework-inventory",
		title:
			platform === "android"
				? `${components.length} bundled libraries identified`
				: `${components.length} embedded frameworks identified`,
		severity: "info",
		category: "supply-chain",
		message:
			platform === "android"
				? `Version markers in ${file} identify ${components.length} libraries (androidx, Material, Play Services, Firebase and Maven artifacts that ship META-INF version files). Libraries without markers, such as obfuscated or shaded ones, are not listed.`
				: `${file} embeds ${components.length} frameworks. They are inventoried only: iOS bundle identifiers do not map reliably to a package registry, so advisories are not looked up.`,
		location: { file },
		evidence: `${lines.join("\n")}${more}`,
		remediation:
			"Keep this list as the app's software bill of materials and review it when SDKs are updated.",
		confidence: platform === "android" ? "medium" : "high",
		tags: ["sbom", platform],
	};
};

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

			if (target.type === "ipa") {
				const entries = target.extract(
					(name, info) =>
						IOS_FRAMEWORK.test(name) && info.originalSize < MAX_MARKER_BYTES,
				);
				const frameworks = iosComponents(entries);
				if (frameworks.length === 0)
					return yield* skip(
						`${target.file} embeds no frameworks (Payload/*.app/Frameworks/*.framework)`,
					);
				return [inventoryFinding(target.file, "ios", frameworks)];
			}

			const entries = target.extract(
				(name, info) =>
					ANDROID_MARKER.test(name) && info.originalSize < MAX_MARKER_BYTES,
			);
			const libraries = androidComponents(entries);
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
		}),
});
