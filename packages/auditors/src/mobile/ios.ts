import {
	defineAuditor,
	type FindingInput,
	lineAt,
	lineOf,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import type { UnzipFileInfo } from "fflate";
import { parse as parseYamlText } from "yaml";

import {
	ATS_DOCS,
	checkEntitlements,
	checkInfoPlist,
	customSchemeFinding,
	type FilePath,
	isNonEmptyString,
	MASVS_NETWORK,
	PERMISSIONS,
	type Permission,
	type PlistKey,
	PRIVACY_REFERENCES,
	type SourceText,
} from "./ios-plist";
import {
	asDict,
	extractEmbeddedPlist,
	type PlistDict,
	type PlistValue,
	parsePlist,
} from "./plist";
import { loadMobileTarget, type MobileSource, utf8 } from "./shared";

/* ----------------------------------- IPA ----------------------------------- */

const APP_PLIST_RE = /^Payload\/[^/]+\.app\/Info\.plist$/;
const PROVISION_RE = /^Payload\/[^/]+\.app\/embedded\.mobileprovision$/;
const XCENT_RE = /^Payload\/[^/]+\.app\/[^/]*\.(xcent|entitlements)$/;
const MAX_IPA_ENTRY_BYTES = 20 * 1024 * 1024;

const isIpaConfig = (name: FilePath) =>
	APP_PLIST_RE.test(name) || PROVISION_RE.test(name) || XCENT_RE.test(name);

const wantedIpaEntry = (name: FilePath, info: UnzipFileInfo) =>
	info.originalSize < MAX_IPA_ENTRY_BYTES && isIpaConfig(name);

const provisionFindings = (label: FilePath, bytes: Uint8Array) => {
	const profile = asDict(extractEmbeddedPlist(bytes));
	const ents = asDict(profile?.Entitlements);
	return ents
		? checkEntitlements({ file: label, value: ents, format: "plist" })
		: [];
};

const ipaEntryFindings = (
	label: FilePath,
	name: FilePath,
	bytes: Uint8Array,
): FindingInput[] => {
	const isXml = bytes[0] === 0x3c; // "<"
	const text = isXml ? utf8(bytes) : undefined;
	if (PROVISION_RE.test(name)) return provisionFindings(label, bytes);
	const check = APP_PLIST_RE.test(name)
		? checkInfoPlist
		: XCENT_RE.test(name)
			? checkEntitlements
			: undefined;
	const value = check && asDict(parsePlist(bytes));
	return value ? check({ file: label, value, text, format: "plist" }) : [];
};

const auditIpa = (
	file: FilePath,
	entries: Record<string, Uint8Array>,
): FindingInput[] =>
	Object.entries(entries).flatMap(([name, bytes]) =>
		ipaEntryFindings(`${file}!${name}`, name, bytes),
	);

/* ------------------------------- source tree ------------------------------- */

const readOptional = (ws: Workspace, file: FilePath) =>
	ws.readText(file).pipe(Effect.orElseSucceed(() => undefined));

const plistFromText = (text: SourceText): PlistDict | undefined => {
	try {
		return asDict(parsePlist(new TextEncoder().encode(text)));
	} catch {
		return undefined;
	}
};

const dependencyNames = (file: FilePath, text: SourceText): string[] => {
	try {
		if (file.endsWith("package.json")) {
			const pkg = JSON.parse(text) as Record<string, unknown>;
			return ["dependencies", "devDependencies"].flatMap((k) =>
				Object.keys((pkg[k] as Record<string, unknown> | undefined) ?? {}),
			);
		}
		const doc = parseYamlText(text) as Record<string, unknown> | null;
		return Object.keys((doc?.dependencies as Record<string, unknown>) ?? {});
	} catch {
		return [];
	}
};

/** Findings so far, the Info.plist keys seen, and whether any iOS config exists. */
interface SourceScan {
	readonly ws: Workspace;
	readonly findings: FindingInput[];
	readonly declared: Set<PlistKey>;
	iosFound: boolean;
}

const readPlistFile = (ws: Workspace, file: FilePath) =>
	Effect.map(readOptional(ws, file), (text) => {
		const value = text === undefined ? undefined : plistFromText(text);
		return value && { file, value, text, format: "plist" as const };
	});

const scanInfoPlists = (scan: SourceScan, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		for (const file of files) {
			const src = yield* readPlistFile(scan.ws, file);
			if (!src) continue;
			for (const key of Object.keys(src.value)) scan.declared.add(key);
			scan.findings.push(...checkInfoPlist(src));
		}
	});

const scanEntitlements = (scan: SourceScan, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		for (const file of files) {
			const src = yield* readPlistFile(scan.ws, file);
			if (src) scan.findings.push(...checkEntitlements(src));
		}
	});

const parseJsonText = (text: SourceText): { value: unknown } | undefined => {
	try {
		return { value: JSON.parse(text) };
	} catch {
		return undefined;
	}
};

const expoSchemes = (scheme: unknown): unknown[] =>
	typeof scheme === "string" ? [scheme] : Array.isArray(scheme) ? scheme : [];

const expoSchemeFindings = (
	file: FilePath,
	text: SourceText,
	scheme: unknown,
): FindingInput[] => {
	const idx = text.indexOf('"scheme"');
	const location = {
		file,
		line: idx === -1 ? undefined : lineOf(text, idx),
	};
	return expoSchemes(scheme)
		.filter(isNonEmptyString)
		.map((s) => customSchemeFinding(s, location));
};

/** Findings for an Expo `app.json`, or undefined when it has no `ios` config. */
const expoJsonFindings = (
	file: FilePath,
	text: SourceText,
): FindingInput[] | undefined => {
	const json = parseJsonText(text)?.value as
		| Record<string, unknown>
		| undefined;
	if (json === undefined) return undefined;
	const config = (json.expo ?? json) as Record<string, unknown>;
	const ios = config.ios as Record<string, unknown> | undefined;
	if (!ios) return undefined;
	const infoPlist = asDict(ios.infoPlist as PlistValue | undefined);
	return [
		...(infoPlist
			? checkInfoPlist({ file, value: infoPlist, text, format: "json" })
			: []),
		...expoSchemeFindings(file, text, config.scheme),
	];
};

const expoConfigFinding = (
	file: FilePath,
	text: SourceText,
): FindingInput | undefined => {
	const m = /\bNSAllowsArbitraryLoads["']?\s*:\s*true\b/.exec(text);
	if (!m) return undefined;
	return {
		ruleId: "mobile.ios/ats-arbitrary-loads",
		title: "App Transport Security disabled",
		severity: "high",
		category: "security",
		message:
			"The Expo config sets NSAllowsArbitraryLoads to true, so the app may load any resource over plain HTTP or weak TLS.",
		remediation:
			"Remove NSAllowsArbitraryLoads from ios.infoPlist and serve all endpoints over HTTPS.",
		location: { file, line: lineOf(text, m.index) },
		evidence: lineAt(text, m.index),
		references: [ATS_DOCS, MASVS_NETWORK],
		tags: ["masvs-network-1", "cwe-319"],
	};
};

/** Runs `check` on each readable, non-empty file; a result marks iOS found. */
const scanExpo = (
	scan: SourceScan,
	files: ReadonlyArray<FilePath>,
	check: (file: FilePath, text: SourceText) => FindingInput[] | undefined,
) =>
	Effect.gen(function* () {
		for (const file of files) {
			const text = yield* readOptional(scan.ws, file);
			const found = text ? check(file, text) : undefined;
			if (!found) continue;
			scan.iosFound = true;
			scan.findings.push(...found);
		}
	});

const expoConfigFindings = (file: FilePath, text: SourceText) => {
	const finding = expoConfigFinding(file, text);
	return finding && [finding];
};

const auditSource = (target: MobileSource) =>
	Effect.gen(function* () {
		const { ws, files } = target;
		const infoPlists = files.filter((f) => /(^|\/)Info\.plist$/.test(f));
		const entitlements = files.filter((f) => f.endsWith(".entitlements"));
		const scan: SourceScan = {
			ws,
			findings: [],
			declared: new Set(),
			iosFound: infoPlists.length + entitlements.length > 0,
		};

		yield* scanInfoPlists(scan, infoPlists);
		yield* scanEntitlements(scan, entitlements);
		yield* scanExpo(
			scan,
			files.filter((f) => /(^|\/)app\.json$/.test(f)),
			expoJsonFindings,
		);
		yield* scanExpo(
			scan,
			files.filter((f) => /(^|\/)app\.config\.[cm]?[jt]s$/.test(f)),
			expoConfigFindings,
		);

		if (!scan.iosFound)
			return yield* skip(
				"No iOS project files (Info.plist, entitlements or Expo ios config) found",
			);

		// Missing purpose strings only matter for native projects that own an Info.plist.
		const missing = PERMISSIONS.filter(
			(p) => !p.keys.some((k) => scan.declared.has(k)),
		);
		if (infoPlists.length > 0 && missing.length > 0)
			scan.findings.push(...(yield* findUndeclaredUsage(ws, files, missing)));
		return scan.findings;
	});

/** Where a permission is used: a file and an index into its text. */
interface UsageSite {
	readonly file: FilePath;
	readonly text: SourceText;
	readonly index: number;
}

const usageMissingFinding = (
	perm: Permission,
	{ file, text, index }: UsageSite,
): FindingInput => ({
	ruleId: "mobile.ios/usage-description-missing",
	title: `${perm.label} purpose string missing`,
	severity: "medium",
	category: "privacy",
	message: `The app appears to use ${perm.label.toLowerCase()} access, but no Info.plist declares ${perm.keys.join(" / ")}. iOS terminates apps that request protected resources without a purpose string.`,
	remediation: `Add ${perm.keys[0]} to Info.plist with a clear explanation of why the app needs ${perm.label.toLowerCase()} access.`,
	location: { file, line: lineOf(text, index) },
	evidence: lineAt(text, index),
	references: [...PRIVACY_REFERENCES],
	tags: ["masvs-privacy-1"],
	confidence: "low",
});

/** Permissions not yet reported, and the findings reported so far. */
interface UsageScan {
	readonly pending: Set<Permission>;
	readonly findings: FindingInput[];
}

const report = (scan: UsageScan, perm: Permission, site: UsageSite) => {
	scan.pending.delete(perm);
	scan.findings.push(usageMissingFinding(perm, site));
};

const reportDependencyUsage = (
	scan: UsageScan,
	file: FilePath,
	text: SourceText,
) => {
	for (const dep of dependencyNames(file, text)) {
		const perm = [...scan.pending].find((p) => p.deps.test(dep));
		if (perm)
			report(scan, perm, { file, text, index: Math.max(0, text.indexOf(dep)) });
	}
};

const reportCodeUsage = (scan: UsageScan, file: FilePath, text: SourceText) => {
	for (const perm of scan.pending) {
		const m = perm.code.exec(text);
		if (m) report(scan, perm, { file, text, index: m.index });
	}
};

/** Reads `files` in turn until every pending permission has been reported. */
const scanUsage = (
	ws: Workspace,
	scan: UsageScan,
	files: ReadonlyArray<FilePath>,
	check: (scan: UsageScan, file: FilePath, text: SourceText) => void,
) =>
	Effect.gen(function* () {
		for (const file of files) {
			if (scan.pending.size === 0) break;
			const text = yield* readOptional(ws, file);
			if (text) check(scan, file, text);
		}
	});

const findUndeclaredUsage = (
	ws: Workspace,
	files: ReadonlyArray<FilePath>,
	missing: ReadonlyArray<Permission>,
) =>
	Effect.gen(function* () {
		const scan: UsageScan = { pending: new Set(missing), findings: [] };
		const manifests = files.filter((f) =>
			/(^|\/)(package\.json|pubspec\.yaml)$/.test(f),
		);
		yield* scanUsage(ws, scan, manifests, reportDependencyUsage);
		const sources = files
			.filter((f) => /\.(swift|m|mm)$/.test(f))
			.slice(0, 2000);
		yield* scanUsage(ws, scan, sources, reportCodeUsage);
		return scan.findings;
	});

/** iOS app configuration: ATS, purpose strings, URL schemes, debug entitlements. */
export const ios = defineAuditor({
	id: "mobile.ios",
	title: "iOS app configuration",
	description:
		"Checks Info.plist (source, Expo config or IPA, binary or XML) for App Transport Security exceptions, missing or empty permission purpose strings, file sharing and custom URL schemes, and entitlements/provisioning profiles for debuggable builds.",
	categories: ["security", "privacy"],
	targets: ["mobile"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const target = yield* loadMobileTarget(ctx);
			if (target.kind === "source") return yield* auditSource(target);
			if (target.type !== "ipa")
				return yield* skip(`${target.file} is not an iOS app (.ipa)`);
			const entries = target.extract(wantedIpaEntry);
			if (!Object.keys(entries).some((n) => APP_PLIST_RE.test(n)))
				return yield* skip(
					`${target.file} contains no Payload/*.app/Info.plist`,
				);
			return auditIpa(target.file, entries);
		}),
});
