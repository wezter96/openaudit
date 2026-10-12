import {
	defineAuditor,
	type FindingInput,
	lineAt,
	lineOf,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import { parse as parseYamlText } from "yaml";

import {
	asDict,
	extractEmbeddedPlist,
	isTrue,
	type PlistDict,
	type PlistValue,
	parsePlist,
} from "./plist";
import { loadMobileTarget, type MobileSource, utf8 } from "./shared";

const ATS_DOCS =
	"https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity";
const MASVS_NETWORK = "https://mas.owasp.org/MASVS/08-MASVS-NETWORK/";
const MASVS_PLATFORM = "https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/";
const MASVS_RESILIENCE = "https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/";

/** A parsed plist-like document plus how to find a key's line in its source. */
interface PlistSource {
	readonly file: string;
	readonly value: PlistDict;
	/** Source text (XML or JSON) for line lookups; absent for binary plists. */
	readonly text?: string;
	readonly format: "plist" | "json";
}

const lineFor = (src: PlistSource, key: string): number | undefined => {
	if (!src.text) return undefined;
	const needle = src.format === "json" ? `"${key}"` : `<key>${key}</key>`;
	const idx = src.text.indexOf(needle);
	return idx === -1 ? undefined : lineOf(src.text, idx);
};

const locate = (src: PlistSource, key: string) => ({
	file: src.file,
	line: lineFor(src, key),
});

/** Permissions whose APIs crash or get rejected without a purpose string. */
const PERMISSIONS: ReadonlyArray<{
	readonly label: string;
	readonly keys: ReadonlyArray<string>;
	/** Native API usage in Swift/Objective-C. */
	readonly code: RegExp;
	/** Flutter / React Native packages that use the permission. */
	readonly deps: RegExp;
}> = [
	{
		label: "Camera",
		keys: ["NSCameraUsageDescription"],
		code: /\bAVCaptureDevice\b|sourceType\s*=\s*\.camera\b|UIImagePickerControllerSourceTypeCamera/,
		deps: /^(camera|image_picker|mobile_scanner|react-native-vision-camera|react-native-camera|expo-camera)$/,
	},
	{
		label: "Microphone",
		keys: ["NSMicrophoneUsageDescription"],
		code: /\bAVAudioRecorder\b|\brequestRecordPermission\b/,
		deps: /^(record|flutter_sound|speech_to_text|react-native-audio-recorder-player)$/,
	},
	{
		label: "Location",
		keys: [
			"NSLocationWhenInUseUsageDescription",
			"NSLocationAlwaysAndWhenInUseUsageDescription",
			"NSLocationAlwaysUsageDescription",
		],
		code: /\bCLLocationManager\b/,
		deps: /^(geolocator|location|react-native-geolocation-service|@react-native-community\/geolocation|expo-location)$/,
	},
	{
		label: "Photo library",
		keys: [
			"NSPhotoLibraryUsageDescription",
			"NSPhotoLibraryAddUsageDescription",
		],
		code: /\bPHPhotoLibrary\b|\bUIImageWriteToSavedPhotosAlbum\b/,
		deps: /^(photo_manager|image_picker|image_gallery_saver|@react-native-camera-roll\/camera-roll|expo-media-library)$/,
	},
	{
		label: "Contacts",
		keys: ["NSContactsUsageDescription"],
		code: /\bCNContactStore\b/,
		deps: /^(contacts_service|flutter_contacts|react-native-contacts|expo-contacts)$/,
	},
];

const USAGE_KEYS = PERMISSIONS.flatMap((p) => p.keys);

const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|::1|[\w-]+\.local)$/i;

/** Checks shared by Info.plist files, IPA plists and Expo `ios.infoPlist`. */
const checkInfoPlist = (src: PlistSource): FindingInput[] => {
	const findings: FindingInput[] = [];
	const plist = src.value;

	const ats = asDict(plist.NSAppTransportSecurity);
	if (ats && isTrue(ats.NSAllowsArbitraryLoads))
		findings.push({
			ruleId: "mobile.ios/ats-arbitrary-loads",
			title: "App Transport Security disabled",
			severity: "high",
			category: "security",
			message:
				"NSAllowsArbitraryLoads is true, so the app may load any resource over plain HTTP or weak TLS.",
			remediation:
				"Remove NSAllowsArbitraryLoads and serve all endpoints over HTTPS; use narrowly scoped NSExceptionDomains only where unavoidable.",
			location: locate(src, "NSAllowsArbitraryLoads"),
			evidence: "NSAllowsArbitraryLoads = true",
			references: [
				ATS_DOCS,
				MASVS_NETWORK,
				"https://cwe.mitre.org/data/definitions/319.html",
			],
			tags: ["masvs-network-1", "cwe-319"],
			confidence: "high",
		});
	if (ats && isTrue(ats.NSAllowsArbitraryLoadsInWebContent))
		findings.push({
			ruleId: "mobile.ios/ats-arbitrary-loads-web",
			title: "ATS disabled for web content",
			severity: "medium",
			category: "security",
			message:
				"NSAllowsArbitraryLoadsInWebContent lets WKWebView load content over plain HTTP.",
			remediation:
				"Load web content over HTTPS and remove NSAllowsArbitraryLoadsInWebContent.",
			location: locate(src, "NSAllowsArbitraryLoadsInWebContent"),
			evidence: "NSAllowsArbitraryLoadsInWebContent = true",
			references: [ATS_DOCS, MASVS_NETWORK],
			tags: ["masvs-network-1", "cwe-319"],
		});

	const domains = asDict(ats?.NSExceptionDomains) ?? {};
	for (const [domain, raw] of Object.entries(domains)) {
		const cfg = asDict(raw);
		if (!cfg || LOCAL_HOSTS.test(domain)) continue;
		if (
			isTrue(cfg.NSExceptionAllowsInsecureHTTPLoads) ||
			isTrue(cfg.NSTemporaryExceptionAllowsInsecureHTTPLoads) ||
			isTrue(cfg.NSThirdPartyExceptionAllowsInsecureHTTPLoads)
		)
			findings.push({
				ruleId: "mobile.ios/ats-insecure-exception-domain",
				title: "ATS exception allows plain HTTP",
				severity: "medium",
				category: "security",
				message: `The ATS exception for ${domain} allows insecure HTTP loads, exposing traffic to interception and tampering.`,
				remediation: `Serve ${domain} over HTTPS and remove the insecure-HTTP exception.`,
				location: locate(src, domain),
				evidence: `${domain}: NSExceptionAllowsInsecureHTTPLoads = true`,
				references: [
					ATS_DOCS,
					MASVS_NETWORK,
					"https://cwe.mitre.org/data/definitions/319.html",
				],
				tags: ["masvs-network-1", "cwe-319"],
			});
		const tls =
			cfg.NSExceptionMinimumTLSVersion ??
			cfg.NSTemporaryExceptionMinimumTLSVersion ??
			cfg.NSThirdPartyExceptionMinimumTLSVersion;
		if (tls === "TLSv1.0" || tls === "TLSv1.1")
			findings.push({
				ruleId: "mobile.ios/ats-weak-tls",
				title: "ATS exception allows deprecated TLS",
				severity: "medium",
				category: "security",
				message: `The ATS exception for ${domain} accepts ${tls}, which is deprecated and vulnerable.`,
				remediation: `Support TLS 1.2+ on ${domain} and remove the minimum TLS version override.`,
				location: locate(src, domain),
				evidence: `${domain}: MinimumTLSVersion = ${tls}`,
				references: [
					ATS_DOCS,
					MASVS_NETWORK,
					"https://cwe.mitre.org/data/definitions/326.html",
				],
				tags: ["masvs-network-1", "cwe-326"],
			});
	}

	for (const key of USAGE_KEYS) {
		const value = plist[key];
		if (typeof value === "string" && value.trim() === "")
			findings.push({
				ruleId: "mobile.ios/usage-description-empty",
				title: "Empty permission purpose string",
				severity: "medium",
				category: "privacy",
				message: `${key} is empty. Users get no explanation for the permission prompt and App Review rejects apps with blank purpose strings.`,
				remediation: `Set ${key} to a specific, user-facing explanation of why the app needs this access.`,
				location: locate(src, key),
				evidence: `${key} = ""`,
				references: [
					"https://developer.apple.com/documentation/uikit/protecting-the-user-s-privacy/requesting-access-to-protected-resources",
					"https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/",
				],
				tags: ["masvs-privacy-1"],
			});
	}

	for (const key of [
		"UIFileSharingEnabled",
		"LSSupportsOpeningDocumentsInPlace",
	])
		if (isTrue(plist[key]))
			findings.push({
				ruleId: "mobile.ios/file-sharing-enabled",
				title: "Documents directory exposed",
				severity: "info",
				category: "privacy",
				message: `${key} is enabled, so the app's Documents directory is visible in the Files app and Finder.`,
				remediation:
					"Make sure nothing sensitive (tokens, databases, caches) is stored in Documents; use Application Support or the Keychain instead.",
				location: locate(src, key),
				evidence: `${key} = true`,
				references: [MASVS_PLATFORM],
				tags: ["masvs-storage-1"],
			});

	const urlTypes = Array.isArray(plist.CFBundleURLTypes)
		? plist.CFBundleURLTypes
		: [];
	for (const type of urlTypes) {
		const schemes = asDict(type)?.CFBundleURLSchemes;
		for (const scheme of Array.isArray(schemes) ? schemes : [])
			if (typeof scheme === "string" && scheme)
				findings.push(
					customSchemeFinding(scheme, locate(src, "CFBundleURLSchemes")),
				);
	}

	return findings;
};

const customSchemeFinding = (
	scheme: string,
	location: FindingInput["location"],
): FindingInput => ({
	ruleId: "mobile.ios/custom-url-scheme",
	title: "Custom URL scheme registered",
	severity: "info",
	category: "security",
	message: `The app registers the "${scheme}://" scheme. Any app can claim the same scheme, so deep links can be hijacked and their parameters are attacker-controlled.`,
	remediation:
		"Prefer Universal Links for authentication and sensitive flows, and validate every parameter received through custom-scheme URLs.",
	location,
	evidence: `${scheme}://`,
	references: [
		"https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app",
		MASVS_PLATFORM,
		"https://cwe.mitre.org/data/definitions/939.html",
	],
	tags: ["masvs-platform-1", "cwe-939"],
});

const checkEntitlements = (src: PlistSource): FindingInput[] =>
	isTrue(src.value["get-task-allow"])
		? [
				{
					ruleId: "mobile.ios/get-task-allow",
					title: "Debuggable build (get-task-allow)",
					severity: "high",
					category: "security",
					message:
						"The get-task-allow entitlement is true: this is a development-signed build that lets debuggers attach and inspect memory at runtime.",
					remediation:
						"Distribute builds signed with an App Store or Ad Hoc distribution profile, which sets get-task-allow to false.",
					location: locate(src, "get-task-allow"),
					evidence: "get-task-allow = true",
					references: [
						"https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_get-task-allow",
						MASVS_RESILIENCE,
						"https://cwe.mitre.org/data/definitions/489.html",
					],
					tags: ["masvs-resilience-4", "cwe-489"],
				},
			]
		: [];

/* ----------------------------------- IPA ----------------------------------- */

const APP_PLIST_RE = /^Payload\/[^/]+\.app\/Info\.plist$/;
const PROVISION_RE = /^Payload\/[^/]+\.app\/embedded\.mobileprovision$/;
const XCENT_RE = /^Payload\/[^/]+\.app\/[^/]*\.(xcent|entitlements)$/;

const auditIpa = (
	file: string,
	entries: Record<string, Uint8Array>,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const [name, bytes] of Object.entries(entries)) {
		const label = `${file}!${name}`;
		const isXml = bytes[0] === 0x3c; // "<"
		const text = isXml ? utf8(bytes) : undefined;
		if (APP_PLIST_RE.test(name)) {
			const value = asDict(parsePlist(bytes));
			if (value)
				findings.push(
					...checkInfoPlist({ file: label, value, text, format: "plist" }),
				);
		} else if (PROVISION_RE.test(name)) {
			const profile = asDict(extractEmbeddedPlist(bytes));
			const ents = asDict(profile?.Entitlements);
			if (ents)
				findings.push(
					...checkEntitlements({ file: label, value: ents, format: "plist" }),
				);
		} else if (XCENT_RE.test(name)) {
			const value = asDict(parsePlist(bytes));
			if (value)
				findings.push(
					...checkEntitlements({ file: label, value, text, format: "plist" }),
				);
		}
	}
	return findings;
};

/* ------------------------------- source tree ------------------------------- */

const readOptional = (ws: Workspace, file: string) =>
	ws.readText(file).pipe(Effect.orElseSucceed(() => undefined));

const plistFromText = (text: string): PlistDict | undefined => {
	try {
		return asDict(parsePlist(new TextEncoder().encode(text)));
	} catch {
		return undefined;
	}
};

const dependencyNames = (file: string, text: string): string[] => {
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

const auditSource = (target: MobileSource) =>
	Effect.gen(function* () {
		const { ws, files } = target;
		const findings: FindingInput[] = [];
		const infoPlists = files.filter((f) => /(^|\/)Info\.plist$/.test(f));
		const entitlements = files.filter((f) => /\.entitlements$/.test(f));
		const expoJson = files.filter((f) => /(^|\/)app\.json$/.test(f));
		const expoConfig = files.filter((f) =>
			/(^|\/)app\.config\.[cm]?[jt]s$/.test(f),
		);

		const declared = new Set<string>();
		let iosFound = infoPlists.length + entitlements.length > 0;

		for (const file of infoPlists) {
			const text = yield* readOptional(ws, file);
			const value = text === undefined ? undefined : plistFromText(text);
			if (!value) continue;
			for (const key of Object.keys(value)) declared.add(key);
			findings.push(...checkInfoPlist({ file, value, text, format: "plist" }));
		}

		for (const file of entitlements) {
			const text = yield* readOptional(ws, file);
			const value = text === undefined ? undefined : plistFromText(text);
			if (value)
				findings.push(
					...checkEntitlements({ file, value, text, format: "plist" }),
				);
		}

		for (const file of expoJson) {
			const text = yield* readOptional(ws, file);
			if (!text) continue;
			let json: Record<string, unknown> | undefined;
			try {
				json = JSON.parse(text) as Record<string, unknown>;
			} catch {
				continue;
			}
			const config = (json.expo ?? json) as Record<string, unknown>;
			const ios = config.ios as Record<string, unknown> | undefined;
			if (!ios) continue;
			iosFound = true;
			const infoPlist = asDict(ios.infoPlist as PlistValue | undefined);
			if (infoPlist)
				findings.push(
					...checkInfoPlist({ file, value: infoPlist, text, format: "json" }),
				);
			const schemes =
				typeof config.scheme === "string"
					? [config.scheme]
					: Array.isArray(config.scheme)
						? config.scheme
						: [];
			for (const scheme of schemes)
				if (typeof scheme === "string" && scheme) {
					const idx = text.indexOf('"scheme"');
					findings.push(
						customSchemeFinding(scheme, {
							file,
							line: idx === -1 ? undefined : lineOf(text, idx),
						}),
					);
				}
		}

		for (const file of expoConfig) {
			const text = yield* readOptional(ws, file);
			if (!text) continue;
			const m = /\bNSAllowsArbitraryLoads["']?\s*:\s*true\b/.exec(text);
			if (!m) continue;
			iosFound = true;
			findings.push({
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
			});
		}

		if (!iosFound)
			return yield* skip(
				"No iOS project files (Info.plist, entitlements or Expo ios config) found",
			);

		// Missing purpose strings only matter for native projects that own an Info.plist.
		if (infoPlists.length > 0) {
			const missing = PERMISSIONS.filter(
				(p) => !p.keys.some((k) => declared.has(k)),
			);
			if (missing.length > 0)
				findings.push(...(yield* findUndeclaredUsage(ws, files, missing)));
		}

		return findings;
	});

const findUndeclaredUsage = (
	ws: Workspace,
	files: ReadonlyArray<string>,
	missing: ReadonlyArray<(typeof PERMISSIONS)[number]>,
) =>
	Effect.gen(function* () {
		const findings: FindingInput[] = [];
		const pending = new Set(missing);
		const report = (
			perm: (typeof PERMISSIONS)[number],
			file: string,
			text: string,
			index: number,
		) => {
			pending.delete(perm);
			findings.push({
				ruleId: "mobile.ios/usage-description-missing",
				title: `${perm.label} purpose string missing`,
				severity: "medium",
				category: "privacy",
				message: `The app appears to use ${perm.label.toLowerCase()} access, but no Info.plist declares ${perm.keys.join(" / ")}. iOS terminates apps that request protected resources without a purpose string.`,
				remediation: `Add ${perm.keys[0]} to Info.plist with a clear explanation of why the app needs ${perm.label.toLowerCase()} access.`,
				location: { file, line: lineOf(text, index) },
				evidence: lineAt(text, index),
				references: [
					"https://developer.apple.com/documentation/uikit/protecting-the-user-s-privacy/requesting-access-to-protected-resources",
					"https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/",
				],
				tags: ["masvs-privacy-1"],
				confidence: "low",
			});
		};

		const manifests = files.filter((f) =>
			/(^|\/)(package\.json|pubspec\.yaml)$/.test(f),
		);
		for (const file of manifests) {
			if (pending.size === 0) break;
			const text = yield* readOptional(ws, file);
			if (!text) continue;
			for (const dep of dependencyNames(file, text)) {
				const perm = [...pending].find((p) => p.deps.test(dep));
				if (!perm) continue;
				const idx = Math.max(0, text.indexOf(dep));
				report(perm, file, text, idx);
			}
		}

		const sources = files
			.filter((f) => /\.(swift|m|mm)$/.test(f))
			.slice(0, 2000);
		for (const file of sources) {
			if (pending.size === 0) break;
			const text = yield* readOptional(ws, file);
			if (!text) continue;
			for (const perm of [...pending]) {
				const m = perm.code.exec(text);
				if (m) report(perm, file, text, m.index);
			}
		}
		return findings;
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
			const entries = target.extract(
				(name, info) =>
					info.originalSize < 20 * 1024 * 1024 &&
					(APP_PLIST_RE.test(name) ||
						PROVISION_RE.test(name) ||
						XCENT_RE.test(name)),
			);
			if (!Object.keys(entries).some((n) => APP_PLIST_RE.test(n)))
				return yield* skip(
					`${target.file} contains no Payload/*.app/Info.plist`,
				);
			return auditIpa(target.file, entries);
		}),
});
