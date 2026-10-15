import { lineOf, type Workspace } from "@openaudit/core";
import { Effect } from "effect";
import type { UnzipFileInfo } from "fflate";

import {
	childrenNamed,
	parseAndroidXml,
	parseXmlText,
	type XmlElement,
	type XmlName,
} from "./axml";
import type { MobileArtifact } from "./shared";

/**
 * Loads the Android manifests, network security configs and SDK levels that
 * mobile.android checks, from a built APK/AAB or from a source tree.
 */

export interface XmlDoc {
	/** Location used in findings (`app.apk!/AndroidManifest.xml` for artifacts). */
	readonly file: string;
	readonly root: XmlElement;
	/** Source text, when available, for evidence lines. */
	readonly text?: string;
}

export interface ManifestDoc extends XmlDoc {
	/** The application's own manifest (as opposed to a library module's). */
	readonly main: boolean;
}

export interface SdkLevel {
	readonly value: number;
	readonly file: string;
	readonly line?: number;
}

export interface SdkLevels {
	readonly min?: SdkLevel;
	readonly target?: SdkLevel;
}

export interface Inputs {
	readonly manifests: ReadonlyArray<ManifestDoc>;
	readonly networkConfigs: ReadonlyArray<XmlDoc>;
	readonly sdk: SdkLevels;
	readonly undecodable: ReadonlyArray<string>;
}

/** Workspace path, archive entry name or location of a document. */
type FilePath = string;
/** Contents of a text file. */
type SourceText = string;

const NSC_ROOT = "network-security-config";

const sdkLevels = (
	min: SdkLevel | undefined,
	target: SdkLevel | undefined,
): SdkLevels => ({ ...(min ? { min } : {}), ...(target ? { target } : {}) });

const hasLevels = (levels: SdkLevels) =>
	levels.min !== undefined || levels.target !== undefined;

/** A `<uses-sdk>` attribute of a manifest, located at the element. */
const manifestLevel = (
	doc: XmlDoc | undefined,
	attr: XmlName,
): SdkLevel | undefined => {
	if (!doc) return undefined;
	const usesSdk = childrenNamed(doc.root, "uses-sdk")[0];
	const value = Number.parseInt(usesSdk?.attrs[attr] ?? "", 10);
	if (!Number.isFinite(value)) return undefined;
	return {
		value,
		file: doc.file,
		...(usesSdk?.line ? { line: usesSdk.line } : {}),
	};
};

const hasNamedChild = (el: XmlElement, tag: XmlName, name: XmlName) =>
	childrenNamed(el, tag).some((c) => c.attrs.name === name);

export const isLauncher = (component: XmlElement) =>
	childrenNamed(component, "intent-filter").some(
		(f) =>
			hasNamedChild(f, "action", "android.intent.action.MAIN") &&
			hasNamedChild(f, "category", "android.intent.category.LAUNCHER"),
	);

const hasLauncher = (manifest: XmlElement) =>
	childrenNamed(manifest, "application").some((app) =>
		[
			...childrenNamed(app, "activity"),
			...childrenNamed(app, "activity-alias"),
		].some(isLauncher),
	);

/* -------------------------------- artifacts ------------------------------- */

interface ArtifactLayout {
	readonly prefix: string;
	readonly manifest: string;
}

const APK_LAYOUT: ArtifactLayout = {
	prefix: "",
	manifest: "AndroidManifest.xml",
};
const AAB_LAYOUT: ArtifactLayout = {
	prefix: "base/",
	manifest: "base/manifest/AndroidManifest.xml",
};

/**
 * The manifest, plus resource XML that may be a network security config: those
 * live in res/xml*, or anywhere under res/ once resource names are obfuscated,
 * so they are identified by their root element.
 */
const wantedArtifactXml = (layout: ArtifactLayout) => {
	// The prefix is one of the fixed layouts above.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const xmlRe = new RegExp(
		`^${layout.prefix}res/(xml[^/]*/[^/]+|[^/]+)\\.xml$`,
	);
	return (name: FilePath, info: UnzipFileInfo) =>
		name === layout.manifest ||
		(xmlRe.test(name) && info.originalSize < 256 * 1024);
};

const entryPath = (artifact: MobileArtifact, name: FilePath) =>
	`${artifact.file}!/${name}`;

const artifactManifest = (
	artifact: MobileArtifact,
	name: FilePath,
	bytes: Uint8Array | undefined,
): Pick<Inputs, "manifests" | "undecodable"> => {
	if (!bytes) return { manifests: [], undecodable: [] };
	const file = entryPath(artifact, name);
	const root = parseAndroidXml(bytes);
	return root?.name === "manifest"
		? { manifests: [{ file, root, main: true }], undecodable: [] }
		: { manifests: [], undecodable: [file] };
};

const artifactNetworkConfigs = (
	artifact: MobileArtifact,
	manifest: FilePath,
	entries: Record<string, Uint8Array>,
): XmlDoc[] =>
	Object.entries(entries).flatMap(([name, bytes]) => {
		if (name === manifest) return [];
		const root = parseAndroidXml(bytes);
		return root?.name === NSC_ROOT
			? [{ file: entryPath(artifact, name), root }]
			: [];
	});

export const fromArtifact = (artifact: MobileArtifact): Inputs => {
	const layout = artifact.type === "aab" ? AAB_LAYOUT : APK_LAYOUT;
	const entries = artifact.extract(wantedArtifactXml(layout));
	const { manifests, undecodable } = artifactManifest(
		artifact,
		layout.manifest,
		entries[layout.manifest],
	);
	const networkConfigs = artifactNetworkConfigs(
		artifact,
		layout.manifest,
		entries,
	);
	return {
		manifests,
		networkConfigs,
		sdk: sdkLevels(
			manifestLevel(manifests[0], "minSdkVersion"),
			manifestLevel(manifests[0], "targetSdkVersion"),
		),
		undecodable,
	};
};

/* ------------------------------- source trees ------------------------------ */

/** Debug/test source sets legitimately relax security settings. */
const NON_RELEASE_SOURCE_SET = /(^|\/)src\/(debug|test|androidTest)[^/]*\//;

const GRADLE_SDK_RE =
	/\b(minSdk|minSdkVersion|targetSdk|targetSdkVersion)\b\s*(?:=|\(|\s)\s*(\d+)/g;

const readText = (ws: Workspace, file: FilePath) =>
	ws.readText(file).pipe(Effect.orElseSucceed(() => undefined));

/** The first min and target SDK levels set in a Gradle build file. */
const gradleLevels = (file: FilePath, text: SourceText): SdkLevels => {
	let min: SdkLevels["min"];
	let target: SdkLevels["target"];
	for (const m of text.matchAll(GRADLE_SDK_RE)) {
		const level = {
			value: Number(m[2]),
			file,
			line: lineOf(text, m.index),
		};
		if (m[1]?.startsWith("min")) min ??= level;
		else target ??= level;
	}
	return sdkLevels(min, target);
};

/** SDK levels of the app module, else of the first module that sets any. */
const sdkFromGradle = (
	ws: Workspace,
	files: ReadonlyArray<FilePath>,
): Effect.Effect<SdkLevels> =>
	Effect.gen(function* () {
		const gradle = files.filter((f) => /(^|\/)build\.gradle(\.kts)?$/.test(f));
		let fallback: SdkLevels = {};
		for (const file of gradle) {
			const text = yield* ws
				.readText(file)
				.pipe(Effect.orElseSucceed(() => ""));
			const levels = gradleLevels(file, text);
			if (!hasLevels(levels)) continue;
			if (/com\.android\.application/.test(text)) return levels;
			if (!hasLevels(fallback)) fallback = levels;
		}
		return fallback;
	});

/** Reads and parses each file, keeping the documents `parse` accepts. */
const readDocs = (
	ws: Workspace,
	files: ReadonlyArray<FilePath>,
	parse: (file: FilePath, text: SourceText) => XmlDoc | undefined,
) =>
	Effect.gen(function* () {
		const docs: XmlDoc[] = [];
		for (const file of files) {
			const text = yield* readText(ws, file);
			const doc = text === undefined ? undefined : parse(file, text);
			if (doc) docs.push(doc);
		}
		return docs;
	});

const isReleaseFile = (re: RegExp) => (file: FilePath) =>
	re.test(file) && !NON_RELEASE_SOURCE_SET.test(file);

const parseManifest = (
	file: FilePath,
	text: SourceText,
): XmlDoc | undefined => {
	const root = parseXmlText(text);
	return root?.name === "manifest" ? { file, root, text } : undefined;
};

const parseNetworkConfig = (
	file: FilePath,
	text: SourceText,
): XmlDoc | undefined => {
	if (!text.includes(NSC_ROOT)) return undefined;
	const root = parseXmlText(text);
	return root?.name === NSC_ROOT ? { file, root, text } : undefined;
};

/** Application-level defaults only matter in the app's own manifest. */
const markMain = (parsed: ReadonlyArray<XmlDoc>): ManifestDoc[] => {
	const launchers = parsed.filter((m) => hasLauncher(m.root));
	const mainSet = new Set(
		(launchers.length > 0
			? launchers
			: parsed.filter((m) => childrenNamed(m.root, "application").length)
		).map((m) => m.file),
	);
	return parsed.map((m) => ({ ...m, main: mainSet.has(m.file) }));
};

export const fromSource = (
	ws: Workspace,
	files: ReadonlyArray<FilePath>,
): Effect.Effect<Inputs> =>
	Effect.gen(function* () {
		const manifests = markMain(
			yield* readDocs(
				ws,
				files.filter(isReleaseFile(/(^|\/)AndroidManifest\.xml$/)),
				parseManifest,
			),
		);
		const networkConfigs = yield* readDocs(
			ws,
			files.filter(isReleaseFile(/(^|\/)res\/xml[^/]*\/[^/]+\.xml$/)),
			parseNetworkConfig,
		);
		const gradleSdk = yield* sdkFromGradle(ws, files);
		const main = manifests.find((m) => m.main);
		// Gradle overrides manifest values during manifest merging.
		return {
			manifests,
			networkConfigs,
			sdk: sdkLevels(
				gradleSdk.min ?? manifestLevel(main, "minSdkVersion"),
				gradleSdk.target ?? manifestLevel(main, "targetSdkVersion"),
			),
			undecodable: [],
		};
	});
