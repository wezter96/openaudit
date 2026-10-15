import { basename } from "node:path";
import {
	defineAuditor,
	type FindingInput,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { elfDebugSections, scanDex } from "./binary-headers";
import { asDict, parsePlist } from "./plist";
import {
	type ArtifactType,
	type ExtractLimits,
	loadMobileTarget,
	type MobileArtifact,
} from "./shared";

export {
	type DexStats,
	elfDebugSections,
	scanDex,
} from "./binary-headers";

/**
 * Size and build-quality checks for built mobile artifacts. Everything is
 * derived from the zip directory (sizes, compression methods, names), plus a
 * bounded read of the DEX class table and ELF section headers. Nothing from the
 * artifact is executed.
 */

const MiB = 1024 * 1024;

/**
 * Thresholds, in bytes of the artifact on disk.
 * - APK: Google Play's legacy 100 MB APK limit; above 50 MB installs drop
 *   noticeably on slow networks.
 * - AAB: Play's 200 MB compressed download-size limit (base module), and half of
 *   it as a warning.
 * - IPA: App Store cellular download warnings historically began at 200 MB.
 */
export const SIZE_THRESHOLDS: Record<
	ArtifactType,
	{ readonly high: number; readonly medium: number }
> = {
	apk: { high: 100 * MiB, medium: 50 * MiB },
	aab: { high: 200 * MiB, medium: 100 * MiB },
	ipa: { high: 500 * MiB, medium: 200 * MiB },
};

/** ABIs shipped in one APK before an AAB / ABI split is recommended. */
export const MULTI_ABI_MIN = 3;
/** Native library bytes (uncompressed) in extra ABIs that make it `medium`. */
const EXTRA_ABI_MEDIUM_BYTES = 20 * MiB;
/** An individual non-code entry at or above this is listed as a large asset. */
export const LARGE_ASSET_BYTES = 5 * MiB;
const HUGE_ASSET_BYTES = 50 * MiB;
const TOP_N = 10;
/** Stored (uncompressed) compressible entries at least this large are flagged. */
export const UNCOMPRESSED_MIN_BYTES = 512 * 1024;
/** Minimum defined classes before the minification heuristic is meaningful. */
export const MIN_DEX_CLASSES = 300;
/** Share of short-named classes below which code looks un-minified. */
export const MINIFIED_RATIO = 0.1;
/** iOS: framework / executable size warnings. */
const LARGE_FRAMEWORK_BYTES = 30 * MiB;
const LARGE_EXECUTABLE_BYTES = 100 * MiB;

const DEX_LIMITS: ExtractLimits = {
	maxEntryBytes: 24 * MiB,
	maxTotalBytes: 64 * MiB,
};
const ELF_LIMITS: ExtractLimits = {
	maxEntryBytes: 24 * MiB,
	maxTotalBytes: 96 * MiB,
};
const MAX_ELF_FILES = 40;
const MAX_DEX_FILES = 3;

const mb = (bytes: number) => `${(bytes / MiB).toFixed(1)} MB`;

interface Entry {
	readonly name: string;
	/** Compressed size in the zip. */
	readonly size: number;
	readonly originalSize: number;
	readonly compression: number;
}

const finding = (
	f: Omit<FindingInput, "category" | "tags"> & { tags?: string[] },
): FindingInput => ({ category: "performance", tags: [], ...f });

/* ------------------------------ artifact size ------------------------------ */

const SIZE_REMEDIATION: Record<ArtifactType, string> = {
	apk: "Ship an Android App Bundle so Play delivers per-device splits, enable R8 shrinking and resource shrinking, compress images (WebP/AVIF) and move large content to on-demand delivery.",
	aab: "Move large features to dynamic feature modules or asset packs, enable R8 and resource shrinking, and compress media.",
	ipa: "Use app thinning and on-demand resources, remove unused frameworks and assets, and compress images and media.",
};

export const sizeFinding = (
	file: string,
	type: ArtifactType,
	bytes: number,
): FindingInput | undefined => {
	const limits = SIZE_THRESHOLDS[type];
	const severity: Severity | undefined =
		bytes > limits.high ? "high" : bytes > limits.medium ? "medium" : undefined;
	if (!severity) return undefined;
	return finding({
		ruleId: "mobile.performance/artifact-size",
		title: `${type.toUpperCase()} is ${mb(bytes)}`,
		severity,
		message: `${file} is ${mb(bytes)}, above the ${mb(severity === "high" ? limits.high : limits.medium)} ${severity === "high" ? "limit" : "warning threshold"} for ${type.toUpperCase()} files. Large downloads reduce install conversion and update rates, especially on slow or metered networks.`,
		location: { file },
		evidence: `${bytes} bytes`,
		remediation: SIZE_REMEDIATION[type],
		references: [
			"https://developer.android.com/topic/performance/reduce-apk-size",
		],
		confidence: "high",
		tags: ["size"],
	});
};

/* ------------------------------ native libraries --------------------------- */

const NATIVE_LIB_RE = /^(?:base\/)?lib\/([^/]+)\/[^/]+\.so$/;

const abiOf = (name: string) => NATIVE_LIB_RE.exec(name)?.[1];

const abiFinding = (
	file: string,
	type: ArtifactType,
	entries: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	// AABs are split per ABI by Play, so only APKs ship them all to every device.
	if (type !== "apk") return undefined;
	const byAbi = new Map<string, number>();
	for (const e of entries) {
		const abi = abiOf(e.name);
		if (abi) byAbi.set(abi, (byAbi.get(abi) ?? 0) + e.originalSize);
	}
	if (byAbi.size < MULTI_ABI_MIN) return undefined;
	const sizes = [...byAbi.values()].sort((a, b) => b - a);
	const extra = sizes.slice(1).reduce((a, b) => a + b, 0);
	return finding({
		ruleId: "mobile.performance/multi-abi-native-libs",
		title: `Native libraries for ${byAbi.size} ABIs in one APK`,
		severity: extra >= EXTRA_ABI_MEDIUM_BYTES ? "medium" : "low",
		message: `The APK bundles native libraries for ${byAbi.size} ABIs (${[...byAbi.keys()].sort().join(", ")}). A device only runs one, so about ${mb(extra)} of native code is dead weight on every install.`,
		location: { file },
		evidence: [...byAbi]
			.sort((a, b) => b[1] - a[1])
			.map(([abi, bytes]) => `lib/${abi}: ${mb(bytes)}`)
			.join("\n"),
		remediation:
			"Publish an Android App Bundle so Play serves only the matching ABI, or add `splits { abi { ... } }` / `ndk.abiFilters` to build one APK per ABI.",
		references: ["https://developer.android.com/guide/app-bundle"],
		confidence: "high",
		tags: ["size", "native"],
	});
};

const isInspectableLib = (e: Entry) =>
	NATIVE_LIB_RE.test(e.name) && e.originalSize <= ELF_LIMITS.maxEntryBytes;

/** Symbols are the same in every ABI, so only one ABI's libraries are read. */
const inspectedAbi = (libs: ReadonlyArray<Entry>) => {
	const abis = [...new Set(libs.map((e) => abiOf(e.name) ?? ""))];
	return abis.includes("arm64-v8a") ? "arm64-v8a" : abis[0];
};

interface UnstrippedLib {
	readonly name: string;
	readonly sections: string[];
	readonly size: number;
}

/** Libraries of `abi` that still carry symbol or debug sections, largest first. */
const unstrippedLibs = (
	artifact: MobileArtifact,
	libs: ReadonlyArray<Entry>,
	abi: string | undefined,
): UnstrippedLib[] => {
	const chosen = new Map(
		libs
			.filter((e) => abiOf(e.name) === abi)
			.slice(0, MAX_ELF_FILES)
			.map((e) => [e.name, e] as const),
	);
	const files = artifact.extract((name) => chosen.has(name), ELF_LIMITS);
	return Object.entries(files)
		.flatMap(([name, bytes]) => {
			const sections = elfDebugSections(bytes);
			return sections.length > 0
				? [{ name, sections, size: bytes.length }]
				: [];
		})
		.sort((a, b) => b.size - a.size);
};

const unstrippedFinding = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const libs = entries.filter(isInspectableLib);
	if (libs.length === 0) return undefined;
	const abi = inspectedAbi(libs);
	const bad = unstrippedLibs(artifact, libs, abi);
	if (bad.length === 0) return undefined;
	const hasDebugInfo = bad.some((b) =>
		b.sections.some((s) => s.startsWith(".debug_")),
	);
	return finding({
		ruleId: "mobile.performance/unstripped-native-libs",
		title: `${bad.length} native librar${bad.length === 1 ? "y" : "ies"} not stripped`,
		severity: hasDebugInfo ? "medium" : "low",
		message: `${bad.length} native librar${bad.length === 1 ? "y" : "ies"} in lib/${abi} still contain ${hasDebugInfo ? "debug information" : "symbol tables"}. They inflate the download and install size and make reverse engineering easier.`,
		location: { file: `${artifact.file}!/${bad[0]?.name}` },
		evidence: bad
			.slice(0, TOP_N)
			.map((b) => `${b.name} (${mb(b.size)}): ${b.sections.join(", ")}`)
			.join("\n"),
		remediation:
			"Strip release builds: leave `packaging.jniLibs.keepDebugSymbols` empty (AGP strips by default), run `llvm-strip --strip-unneeded`, and upload native debug symbols to Play Console / Crashlytics separately.",
		references: ["https://developer.android.com/build/include-native-symbols"],
		confidence: "high",
		tags: ["size", "native"],
	});
};

/* ---------------------------------- assets --------------------------------- */

const CODE_ENTRY =
	/(\.dex$|\.so$|\.arsc$|(^|\/)AndroidManifest\.xml$|(^|\/)META-INF\/)/;
const COMPRESSIBLE_EXT =
	/\.(json|xml|txt|csv|html?|js|css|svg|bin|dat|db|sqlite3?|pb|ttf|otf|obj|fbx|ply|tflite|model|pak|plist|strings|yaml|yml|md|wav|bmp|tga|psd)$/i;

/**
 * iOS bundles are dominated by Mach-O code (the main executable has no
 * extension) and frameworks, which are reported separately.
 */
const isIosCode = (e: Entry) =>
	/\.app\/Frameworks\//.test(e.name) || !/\.[A-Za-z0-9]+$/.test(e.name);

const isDataEntry = (type: ArtifactType, e: Entry) =>
	!e.name.endsWith("/") &&
	!CODE_ENTRY.test(e.name) &&
	!(type === "ipa" && isIosCode(e));

const bySizeDesc = (a: Entry, b: Entry) => b.originalSize - a.originalSize;

const totalSize = (entries: ReadonlyArray<Entry>) =>
	entries.reduce((n, e) => n + e.originalSize, 0);

const largeAssetsFinding = (
	file: string,
	data: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const large = data
		.filter((e) => e.originalSize >= LARGE_ASSET_BYTES)
		.sort(bySizeDesc);
	if (large.length === 0) return undefined;
	const total = totalSize(large);
	return finding({
		ruleId: "mobile.performance/large-assets",
		title: `${large.length} large asset${large.length === 1 ? "" : "s"} (${mb(total)})`,
		severity:
			(large[0]?.originalSize ?? 0) >= HUGE_ASSET_BYTES ? "medium" : "low",
		message: `${large.length} bundled file${large.length === 1 ? " is" : "s are"} at least ${mb(LARGE_ASSET_BYTES)}, ${mb(total)} in total. Large resources slow the download and install, and decoding them at start-up delays launch.`,
		location: { file: `${file}!/${large[0]?.name}` },
		evidence: large
			.slice(0, TOP_N)
			.map(
				(e) =>
					`${e.name}: ${mb(e.originalSize)}${e.compression === 0 ? " (stored)" : ""}`,
			)
			.join("\n"),
		remediation:
			"Compress images and media (WebP/AVIF, HEVC/AAC), downscale them to the sizes the UI needs, and deliver bulky content on demand (Play Asset Delivery, On-Demand Resources or a CDN).",
		references: [
			"https://developer.android.com/topic/performance/reduce-apk-size",
		],
		confidence: "high",
		tags: ["size", "assets"],
	});
};

const isStoredCompressible = (e: Entry) =>
	e.compression === 0 &&
	e.originalSize >= UNCOMPRESSED_MIN_BYTES &&
	COMPRESSIBLE_EXT.test(e.name);

const uncompressedFinding = (
	file: string,
	data: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const stored = data.filter(isStoredCompressible).sort(bySizeDesc);
	if (stored.length === 0) return undefined;
	const total = totalSize(stored);
	return finding({
		ruleId: "mobile.performance/uncompressed-assets",
		title: `${stored.length} compressible file${stored.length === 1 ? " is" : "s are"} stored uncompressed`,
		severity: "low",
		message: `${stored.length} text/data file${stored.length === 1 ? " is" : "s are"} stored in the archive without compression (${mb(total)} in total). Compressing them typically saves 60-90% of that space in the download.`,
		location: { file: `${file}!/${stored[0]?.name}` },
		evidence: stored
			.slice(0, TOP_N)
			.map((e) => `${e.name}: ${mb(e.originalSize)}`)
			.join("\n"),
		remediation:
			"Remove these extensions from `aaptOptions.noCompress` / `androidResources.noCompress`, or pre-compress the data (zstd, gzip) and decompress it at runtime.",
		references: [
			"https://developer.android.com/reference/tools/gradle-api/current/com/android/build/api/dsl/AndroidResources#noCompress()",
		],
		confidence: "high",
		tags: ["size", "assets"],
	});
};

const assetFindings = (
	file: string,
	type: ArtifactType,
	entries: ReadonlyArray<Entry>,
): Array<FindingInput | undefined> => {
	const data = entries.filter((e) => isDataEntry(type, e));
	return [
		largeAssetsFinding(file, data),
		type !== "ipa" ? uncompressedFinding(file, data) : undefined,
	];
};

/* ----------------------------------- DEX ---------------------------------- */

const DEX_RE = /^(?:base\/dex\/|)classes\d*\.dex$/;

const isInspectableDex = (e: Entry) =>
	DEX_RE.test(e.name) && e.originalSize <= DEX_LIMITS.maxEntryBytes;

/** Class counts summed over the given DEX files. */
const dexTotals = (
	artifact: MobileArtifact,
	dex: ReadonlyArray<string>,
): { classes: number; short: number; samples: string[] } => {
	const files = artifact.extract((name) => dex.includes(name), DEX_LIMITS);
	const totals = { classes: 0, short: 0, samples: [] as string[] };
	for (const bytes of Object.values(files)) {
		const stats = scanDex(bytes);
		if (!stats) continue;
		totals.classes += stats.classes;
		totals.short += stats.short;
		totals.samples.push(...stats.samples);
	}
	return totals;
};

/** Too few classes to judge, or enough short names to look renamed by R8. */
const looksMinified = ({
	classes,
	short,
}: {
	classes: number;
	short: number;
}) => classes < MIN_DEX_CLASSES || short / classes >= MINIFIED_RATIO;

const minificationFinding = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const dex = entries
		.filter(isInspectableDex)
		.map((e) => e.name)
		.sort()
		.slice(0, MAX_DEX_FILES);
	if (dex.length === 0) return undefined;
	const totals = dexTotals(artifact, dex);
	if (looksMinified(totals)) return undefined;
	const { classes, short, samples } = totals;
	return finding({
		ruleId: "mobile.performance/dex-not-minified",
		title: "Code does not look shrunk or renamed by R8",
		severity: "low",
		message: `Only ${short} of ${classes} classes (${((short / classes) * 100).toFixed(1)}%) in the DEX files have short, renamed-looking names. Release builds with R8 normally rename most classes and remove unused code; skipping it leaves a larger DEX and slower class loading and start-up. This is a heuristic based on class names, so it can misfire for apps that keep most names on purpose.`,
		location: { file: `${artifact.file}!/${dex[0]}` },
		evidence: samples.slice(0, 5).join("\n") || undefined,
		remediation:
			"Enable `minifyEnabled true` (R8 full mode) and `shrinkResources true` for release builds, and keep only the classes that reflection or serialization need.",
		references: [
			"https://developer.android.com/topic/performance/app-optimization/enable-app-optimization",
		],
		confidence: "low",
		tags: ["size", "r8"],
	});
};

/* ----------------------------------- iOS ----------------------------------- */

const FRAMEWORK_DIR = /^(Payload\/[^/]+\.app\/Frameworks\/[^/]+\.framework)\//;
const APP_INFO_PLIST = /^Payload\/[^/]+\.app\/Info\.plist$/;

/** Uncompressed bytes per embedded framework folder. */
const frameworkSizes = (entries: ReadonlyArray<Entry>): Map<string, number> => {
	const frameworks = new Map<string, number>();
	for (const e of entries) {
		const dir = FRAMEWORK_DIR.exec(e.name)?.[1];
		if (dir) frameworks.set(dir, (frameworks.get(dir) ?? 0) + e.originalSize);
	}
	return frameworks;
};

const largeFrameworksFinding = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const large = [...frameworkSizes(entries)]
		.filter(([, bytes]) => bytes >= LARGE_FRAMEWORK_BYTES)
		.sort((a, b) => b[1] - a[1]);
	if (large.length === 0) return undefined;
	return finding({
		ruleId: "mobile.performance/ios-large-framework",
		title: `${large.length} embedded framework${large.length === 1 ? " is" : "s are"} over ${mb(LARGE_FRAMEWORK_BYTES)}`,
		severity: "low",
		message:
			"Large embedded frameworks increase download size and, because dynamic frameworks load at launch, pre-main start-up time.",
		location: { file: `${artifact.file}!/${large[0]?.[0]}` },
		evidence: large
			.slice(0, TOP_N)
			.map(([name, bytes]) => `${name.split("/").pop()}: ${mb(bytes)}`)
			.join("\n"),
		remediation:
			"Link rarely used SDKs statically or remove them, prefer mergeable libraries or static linking for first-party frameworks, and strip unused architectures and resources.",
		confidence: "medium",
		tags: ["size", "startup"],
	});
};

/** CFBundleExecutable from the app's Info.plist, if it can be read. */
const bundleExecutable = (
	artifact: MobileArtifact,
	plistName: string,
): string | undefined => {
	const files = artifact.extract((name) => name === plistName);
	try {
		const info = asDict(parsePlist(files[plistName] ?? new Uint8Array()));
		const executable = info?.CFBundleExecutable;
		return typeof executable === "string" ? executable : undefined;
	} catch {
		return undefined;
	}
};

/** The main executable, named by CFBundleExecutable or else the app name. */
const mainExecutable = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): Entry | undefined => {
	const plist = entries.find((e) => APP_INFO_PLIST.test(e.name));
	if (!plist) return undefined;
	const appDir = plist.name.slice(0, plist.name.lastIndexOf("/"));
	const executable =
		bundleExecutable(artifact, plist.name) ?? basename(appDir, ".app");
	return entries.find((e) => e.name === `${appDir}/${executable}`);
};

const largeExecutableFinding = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const binary = mainExecutable(artifact, entries);
	if (!binary || binary.originalSize < LARGE_EXECUTABLE_BYTES) return undefined;
	return finding({
		ruleId: "mobile.performance/ios-large-executable",
		title: `App binary is ${mb(binary.originalSize)}`,
		severity: "low",
		message: `The main executable is ${mb(binary.originalSize)}. Large binaries take longer to page in at launch and approach App Store limits.`,
		location: { file: `${artifact.file}!/${binary.name}` },
		evidence: `${binary.name}: ${mb(binary.originalSize)}`,
		remediation:
			"Enable dead-code stripping and link-time optimization, strip symbols in release builds, drop unused architectures, and remove unused dependencies.",
		confidence: "medium",
		tags: ["size", "startup"],
	});
};

/* --------------------------------- auditor --------------------------------- */

/** Reading the zip directory records sizes without inflating anything. */
const zipDirectory = (artifact: MobileArtifact): Entry[] => {
	const entries: Entry[] = [];
	artifact.extract((name, info) => {
		entries.push({
			name,
			size: info.size,
			originalSize: info.originalSize,
			compression: info.compression,
		});
		return false;
	});
	return entries;
};

const platformFindings = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): Array<FindingInput | undefined> =>
	artifact.type === "ipa"
		? [
				largeFrameworksFinding(artifact, entries),
				largeExecutableFinding(artifact, entries),
			]
		: [
				abiFinding(artifact.file, artifact.type, entries),
				unstrippedFinding(artifact, entries),
				minificationFinding(artifact, entries),
			];

export const mobilePerformance = defineAuditor({
	id: "mobile.performance",
	title: "Mobile app size and build quality",
	description:
		"Checks built APK/AAB/IPA files for oversized artifacts (APK > 100 MB high, > 50 MB medium; AAB 200/100 MB; IPA 500/200 MB), native libraries for many ABIs in one APK, large or uncompressed assets, unstripped native libraries (ELF .symtab/.debug_info) and DEX that looks neither shrunk nor renamed by R8 (heuristic). On iOS it flags large frameworks and executables. Source trees are not analysed.",
	categories: ["performance"],
	targets: ["mobile"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const target = yield* loadMobileTarget(ctx);
			if (target.kind !== "artifact")
				return yield* skip(
					"Target is a source tree, not a built APK/AAB/IPA (size checks need the artifact)",
				);
			const entries = zipDirectory(target);
			const onDisk = yield* ctx.workspace
				? ctx.workspace.size(target.file).pipe(Effect.orElseSucceed(() => 0))
				: Effect.succeed(0);
			const bytes = onDisk || entries.reduce((n, e) => n + e.size, 0);

			const findings: Array<FindingInput | undefined> = [
				sizeFinding(target.file, target.type, bytes),
				...assetFindings(target.file, target.type, entries),
				...platformFindings(target, entries),
			];
			return findings.filter((f): f is FindingInput => f !== undefined);
		}),
});
