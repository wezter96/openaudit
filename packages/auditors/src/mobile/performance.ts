import { basename } from "node:path";
import {
	defineAuditor,
	type FindingInput,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { asDict, parsePlist } from "./plist";
import {
	type ArtifactType,
	type ExtractLimits,
	loadMobileTarget,
	type MobileArtifact,
} from "./shared";

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
const MAX_DEX_CLASSES = 50_000;

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
		remediation:
			type === "apk"
				? "Ship an Android App Bundle so Play delivers per-device splits, enable R8 shrinking and resource shrinking, compress images (WebP/AVIF) and move large content to on-demand delivery."
				: type === "aab"
					? "Move large features to dynamic feature modules or asset packs, enable R8 and resource shrinking, and compress media."
					: "Use app thinning and on-demand resources, remove unused frameworks and assets, and compress images and media.",
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

/** ELF section names that show a library still carries symbols or debug data. */
const DEBUG_SECTIONS = new Set([
	".symtab",
	".debug_info",
	".debug_line",
	".debug_str",
	".debug_abbrev",
	".debug_frame",
]);

/**
 * Names of symbol/debug sections in an ELF file, read from its section header
 * table. Returns [] for anything that is not a well-formed ELF.
 */
export const elfDebugSections = (bytes: Uint8Array): string[] => {
	if (
		bytes.length < 0x40 ||
		bytes[0] !== 0x7f ||
		bytes[1] !== 0x45 ||
		bytes[2] !== 0x4c ||
		bytes[3] !== 0x46
	)
		return [];
	const is64 = bytes[4] === 2;
	if (!is64 && bytes[4] !== 1) return [];
	const little = bytes[5] !== 2;
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const u16 = (o: number) => view.getUint16(o, little);
	const u32 = (o: number) => view.getUint32(o, little);
	const u64 = (o: number) => {
		const v = view.getBigUint64(o, little);
		return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.NaN : Number(v);
	};
	try {
		const shoff = is64 ? u64(0x28) : u32(0x20);
		const shentsize = u16(is64 ? 0x3a : 0x2e);
		const shnum = u16(is64 ? 0x3c : 0x30);
		const shstrndx = u16(is64 ? 0x3e : 0x32);
		const minEntry = is64 ? 0x40 : 0x28;
		if (
			!Number.isFinite(shoff) ||
			shoff === 0 ||
			shnum === 0 ||
			shnum > 4096 ||
			shentsize < minEntry ||
			shstrndx >= shnum ||
			shoff + shnum * shentsize > bytes.length
		)
			return [];
		const header = (i: number) => shoff + i * shentsize;
		const offsetOf = (h: number) => (is64 ? u64(h + 0x18) : u32(h + 0x10));
		const sizeOf = (h: number) => (is64 ? u64(h + 0x20) : u32(h + 0x14));
		const strOff = offsetOf(header(shstrndx));
		const strSize = sizeOf(header(shstrndx));
		if (
			!Number.isFinite(strOff) ||
			!Number.isFinite(strSize) ||
			strOff + strSize > bytes.length
		)
			return [];
		const found = new Set<string>();
		for (let i = 0; i < shnum; i++) {
			const nameOff = u32(header(i));
			if (nameOff >= strSize) continue;
			let end = strOff + nameOff;
			const limit = Math.min(strOff + strSize, end + 64);
			while (end < limit && bytes[end] !== 0) end++;
			const name = new TextDecoder().decode(
				bytes.subarray(strOff + nameOff, end),
			);
			if (DEBUG_SECTIONS.has(name)) found.add(name);
		}
		return [...found];
	} catch {
		return [];
	}
};

const unstrippedFinding = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const libs = entries.filter(
		(e) =>
			NATIVE_LIB_RE.test(e.name) && e.originalSize <= ELF_LIMITS.maxEntryBytes,
	);
	if (libs.length === 0) return undefined;
	// Symbols are the same in every ABI, so inspect one ABI's libraries.
	const abis = [...new Set(libs.map((e) => abiOf(e.name) ?? ""))];
	const abi = abis.includes("arm64-v8a") ? "arm64-v8a" : abis[0];
	const chosen = new Map(
		libs
			.filter((e) => abiOf(e.name) === abi)
			.slice(0, MAX_ELF_FILES)
			.map((e) => [e.name, e] as const),
	);
	const files = artifact.extract((name) => chosen.has(name), ELF_LIMITS);
	const bad: Array<{ name: string; sections: string[]; size: number }> = [];
	for (const [name, bytes] of Object.entries(files)) {
		const sections = elfDebugSections(bytes);
		if (sections.length > 0) bad.push({ name, sections, size: bytes.length });
	}
	if (bad.length === 0) return undefined;
	bad.sort((a, b) => b.size - a.size);
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

const assetFindings = (
	file: string,
	type: ArtifactType,
	entries: ReadonlyArray<Entry>,
): FindingInput[] => {
	const out: FindingInput[] = [];
	const data = entries.filter(
		(e) =>
			!e.name.endsWith("/") &&
			!CODE_ENTRY.test(e.name) &&
			// iOS bundles are dominated by Mach-O code (the main executable has no
			// extension) and frameworks, which are reported separately.
			!(
				type === "ipa" &&
				(/\.app\/Frameworks\//.test(e.name) || !/\.[A-Za-z0-9]+$/.test(e.name))
			),
	);
	const large = data
		.filter((e) => e.originalSize >= LARGE_ASSET_BYTES)
		.sort((a, b) => b.originalSize - a.originalSize);
	if (large.length > 0) {
		const total = large.reduce((n, e) => n + e.originalSize, 0);
		out.push(
			finding({
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
			}),
		);
	}
	const stored = data
		.filter(
			(e) =>
				e.compression === 0 &&
				e.originalSize >= UNCOMPRESSED_MIN_BYTES &&
				COMPRESSIBLE_EXT.test(e.name),
		)
		.sort((a, b) => b.originalSize - a.originalSize);
	if (stored.length > 0 && type !== "ipa") {
		const total = stored.reduce((n, e) => n + e.originalSize, 0);
		out.push(
			finding({
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
			}),
		);
	}
	return out;
};

/* ----------------------------------- DEX ---------------------------------- */

export interface DexStats {
	/** Classes defined in the DEX (not merely referenced). */
	readonly classes: number;
	/** Of those, classes whose simple name has at most 2 characters. */
	readonly short: number;
	/** Examples of readable class descriptors. */
	readonly samples: ReadonlyArray<string>;
}

/**
 * Counts the classes a DEX file defines and how many carry short, renamed-looking
 * names. Reads only the header, string ids, type ids and class defs; all
 * offsets are bounds-checked.
 */
export const scanDex = (bytes: Uint8Array): DexStats | undefined => {
	if (
		bytes.length < 0x70 ||
		bytes[0] !== 0x64 ||
		bytes[1] !== 0x65 ||
		bytes[2] !== 0x78 ||
		bytes[3] !== 0x0a
	)
		return undefined;
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	try {
		const stringCount = view.getUint32(0x38, true);
		const stringOff = view.getUint32(0x3c, true);
		const typeCount = view.getUint32(0x40, true);
		const typeOff = view.getUint32(0x44, true);
		const classCount = Math.min(view.getUint32(0x60, true), MAX_DEX_CLASSES);
		const classOff = view.getUint32(0x64, true);
		if (
			stringOff + stringCount * 4 > bytes.length ||
			typeOff + typeCount * 4 > bytes.length ||
			classOff + classCount * 32 > bytes.length
		)
			return undefined;
		let counted = 0;
		let short = 0;
		const samples: string[] = [];
		for (let i = 0; i < classCount; i++) {
			const typeIdx = view.getUint32(classOff + i * 32, true);
			if (typeIdx >= typeCount) continue;
			const strIdx = view.getUint32(typeOff + typeIdx * 4, true);
			if (strIdx >= stringCount) continue;
			let p = view.getUint32(stringOff + strIdx * 4, true);
			if (p >= bytes.length) continue;
			// Skip the ULEB128 UTF-16 length, then read the NUL-terminated string.
			while (p < bytes.length && (bytes[p] ?? 0) & 0x80) p++;
			p++;
			let end = p;
			const limit = Math.min(bytes.length, p + 300);
			while (end < limit && bytes[end] !== 0) end++;
			const descriptor = new TextDecoder().decode(bytes.subarray(p, end));
			if (!/^L[\w$/]+;$/.test(descriptor)) continue;
			counted++;
			const simple =
				(descriptor.slice(1, -1).split("/").pop() ?? "").split("$")[0] ?? "";
			if (simple.length <= 2) short++;
			else if (samples.length < 5 && descriptor.includes("/"))
				samples.push(descriptor);
		}
		return { classes: counted, short, samples };
	} catch {
		return undefined;
	}
};

const DEX_RE = /^(?:base\/dex\/|)classes\d*\.dex$/;

const minificationFinding = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): FindingInput | undefined => {
	const dex = entries
		.filter(
			(e) => DEX_RE.test(e.name) && e.originalSize <= DEX_LIMITS.maxEntryBytes,
		)
		.map((e) => e.name)
		.sort()
		.slice(0, MAX_DEX_FILES);
	if (dex.length === 0) return undefined;
	const files = artifact.extract((name) => dex.includes(name), DEX_LIMITS);
	let classes = 0;
	let short = 0;
	const samples: string[] = [];
	for (const bytes of Object.values(files)) {
		const stats = scanDex(bytes);
		if (!stats) continue;
		classes += stats.classes;
		short += stats.short;
		samples.push(...stats.samples);
	}
	if (classes < MIN_DEX_CLASSES || short / classes >= MINIFIED_RATIO)
		return undefined;
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

const iosFindings = (
	artifact: MobileArtifact,
	entries: ReadonlyArray<Entry>,
): FindingInput[] => {
	const out: FindingInput[] = [];
	const frameworks = new Map<string, number>();
	for (const e of entries) {
		const m = /^(Payload\/[^/]+\.app\/Frameworks\/[^/]+\.framework)\//.exec(
			e.name,
		);
		if (m?.[1])
			frameworks.set(m[1], (frameworks.get(m[1]) ?? 0) + e.originalSize);
	}
	const large = [...frameworks]
		.filter(([, bytes]) => bytes >= LARGE_FRAMEWORK_BYTES)
		.sort((a, b) => b[1] - a[1]);
	if (large.length > 0)
		out.push(
			finding({
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
			}),
		);

	// The main executable is named by CFBundleExecutable, falling back to the app name.
	const plist = entries.find((e) =>
		/^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name),
	);
	if (plist) {
		const appDir = plist.name.slice(0, plist.name.lastIndexOf("/"));
		const files = artifact.extract((name) => name === plist.name);
		let executable: string | undefined;
		try {
			const info = asDict(parsePlist(files[plist.name] ?? new Uint8Array()));
			if (typeof info?.CFBundleExecutable === "string")
				executable = info.CFBundleExecutable;
		} catch {
			// Fall back to the bundle folder name below.
		}
		executable ??= basename(appDir, ".app");
		const binary = entries.find((e) => e.name === `${appDir}/${executable}`);
		if (binary && binary.originalSize >= LARGE_EXECUTABLE_BYTES)
			out.push(
				finding({
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
				}),
			);
	}
	return out;
};

/* --------------------------------- auditor --------------------------------- */

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
			// Reading the zip directory records sizes without inflating anything.
			const entries: Entry[] = [];
			target.extract((name, info) => {
				entries.push({
					name,
					size: info.size,
					originalSize: info.originalSize,
					compression: info.compression,
				});
				return false;
			});
			const onDisk = yield* ctx.workspace
				? ctx.workspace.size(target.file).pipe(Effect.orElseSucceed(() => 0))
				: Effect.succeed(0);
			const bytes = onDisk || entries.reduce((n, e) => n + e.size, 0);

			const findings: Array<FindingInput | undefined> = [
				sizeFinding(target.file, target.type, bytes),
				...assetFindings(target.file, target.type, entries),
			];
			if (target.type === "ipa") {
				findings.push(...iosFindings(target, entries));
			} else {
				findings.push(
					abiFinding(target.file, target.type, entries),
					unstrippedFinding(target, entries),
					minificationFinding(target, entries),
				);
			}
			return findings.filter((f): f is FindingInput => f !== undefined);
		}),
});
