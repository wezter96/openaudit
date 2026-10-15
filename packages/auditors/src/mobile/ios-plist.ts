import { type FindingInput, lineOf } from "@openaudit/core";

import { asDict, isTrue, type PlistDict, type PlistValue } from "./plist";

/**
 * Info.plist and entitlement checks shared by source trees, IPAs and Expo
 * `ios.infoPlist`.
 */

export const ATS_DOCS =
	"https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity";
export const MASVS_NETWORK = "https://mas.owasp.org/MASVS/08-MASVS-NETWORK/";
const MASVS_PLATFORM = "https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/";
const MASVS_RESILIENCE = "https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/";
export const PRIVACY_REFERENCES = [
	"https://developer.apple.com/documentation/uikit/protecting-the-user-s-privacy/requesting-access-to-protected-resources",
	"https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/",
];

/** Workspace path, or `app.ipa!Payload/...` inside an IPA. */
export type FilePath = string;
/** A plist key, such as `NSCameraUsageDescription`. */
export type PlistKey = string;
/** Source text of a plist, JSON or code file. */
export type SourceText = string;

/** A parsed plist-like document plus how to find a key's line in its source. */
export interface PlistSource {
	readonly file: FilePath;
	readonly value: PlistDict;
	/** Source text (XML or JSON) for line lookups; absent for binary plists. */
	readonly text?: SourceText;
	readonly format: "plist" | "json";
}

const lineFor = (src: PlistSource, key: PlistKey): number | undefined => {
	if (!src.text) return undefined;
	const needle = src.format === "json" ? `"${key}"` : `<key>${key}</key>`;
	const idx = src.text.indexOf(needle);
	return idx === -1 ? undefined : lineOf(src.text, idx);
};

const locate = (src: PlistSource, key: PlistKey) => ({
	file: src.file,
	line: lineFor(src, key),
});

/** Permissions whose APIs crash or get rejected without a purpose string. */
export const PERMISSIONS: ReadonlyArray<{
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

export type Permission = (typeof PERMISSIONS)[number];

const USAGE_KEYS = PERMISSIONS.flatMap((p) => p.keys);

const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|::1|[\w-]+\.local)$/i;

const atsFindings = (src: PlistSource, ats: PlistDict): FindingInput[] => {
	const findings: FindingInput[] = [];
	if (isTrue(ats.NSAllowsArbitraryLoads))
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
	if (isTrue(ats.NSAllowsArbitraryLoadsInWebContent))
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
	return findings;
};

const allowsInsecureHttp = (cfg: PlistDict) =>
	isTrue(cfg.NSExceptionAllowsInsecureHTTPLoads) ||
	isTrue(cfg.NSTemporaryExceptionAllowsInsecureHTTPLoads) ||
	isTrue(cfg.NSThirdPartyExceptionAllowsInsecureHTTPLoads);

const minimumTls = (cfg: PlistDict) =>
	cfg.NSExceptionMinimumTLSVersion ??
	cfg.NSTemporaryExceptionMinimumTLSVersion ??
	cfg.NSThirdPartyExceptionMinimumTLSVersion;

const DEPRECATED_TLS = new Set(["TLSv1.0", "TLSv1.1"]);

/** The fields of a finding located at one plist key, in their usual order. */
type KeyIssue = Pick<
	FindingInput,
	| "ruleId"
	| "title"
	| "severity"
	| "category"
	| "message"
	| "remediation"
	| "evidence"
	| "references"
	| "tags"
>;

const keyFinding = (
	src: PlistSource,
	key: PlistKey,
	issue: KeyIssue,
): FindingInput => ({
	ruleId: issue.ruleId,
	title: issue.title,
	severity: issue.severity,
	category: issue.category,
	message: issue.message,
	remediation: issue.remediation,
	location: locate(src, key),
	evidence: issue.evidence,
	references: [...(issue.references ?? [])],
	tags: [...(issue.tags ?? [])],
});

/** The parts of a key finding that do not depend on the key. */
type KeyRule = Pick<
	KeyIssue,
	"ruleId" | "title" | "severity" | "category" | "references" | "tags"
>;

const INSECURE_DOMAIN: KeyRule = {
	ruleId: "mobile.ios/ats-insecure-exception-domain",
	title: "ATS exception allows plain HTTP",
	severity: "medium",
	category: "security",
	references: [
		ATS_DOCS,
		MASVS_NETWORK,
		"https://cwe.mitre.org/data/definitions/319.html",
	],
	tags: ["masvs-network-1", "cwe-319"],
};

const WEAK_TLS: KeyRule = {
	ruleId: "mobile.ios/ats-weak-tls",
	title: "ATS exception allows deprecated TLS",
	severity: "medium",
	category: "security",
	references: [
		ATS_DOCS,
		MASVS_NETWORK,
		"https://cwe.mitre.org/data/definitions/326.html",
	],
	tags: ["masvs-network-1", "cwe-326"],
};

const insecureDomainFinding = (src: PlistSource, domain: PlistKey) =>
	keyFinding(src, domain, {
		...INSECURE_DOMAIN,
		message: `The ATS exception for ${domain} allows insecure HTTP loads, exposing traffic to interception and tampering.`,
		remediation: `Serve ${domain} over HTTPS and remove the insecure-HTTP exception.`,
		evidence: `${domain}: NSExceptionAllowsInsecureHTTPLoads = true`,
	});

const weakTlsFinding = (src: PlistSource, domain: PlistKey, tls: string) =>
	keyFinding(src, domain, {
		...WEAK_TLS,
		message: `The ATS exception for ${domain} accepts ${tls}, which is deprecated and vulnerable.`,
		remediation: `Support TLS 1.2+ on ${domain} and remove the minimum TLS version override.`,
		evidence: `${domain}: MinimumTLSVersion = ${tls}`,
	});

const exceptionDomainFindings = (
	src: PlistSource,
	domain: PlistKey,
	cfg: PlistDict,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	if (allowsInsecureHttp(cfg))
		findings.push(insecureDomainFinding(src, domain));
	const tls = minimumTls(cfg);
	if (typeof tls === "string" && DEPRECATED_TLS.has(tls))
		findings.push(weakTlsFinding(src, domain, tls));
	return findings;
};

const exceptionDomainsFindings = (
	src: PlistSource,
	ats: PlistDict | undefined,
): FindingInput[] =>
	Object.entries(asDict(ats?.NSExceptionDomains) ?? {}).flatMap(
		([domain, raw]) => {
			const cfg = asDict(raw);
			if (!cfg || LOCAL_HOSTS.test(domain)) return [];
			return exceptionDomainFindings(src, domain, cfg);
		},
	);

const EMPTY_USAGE: KeyRule = {
	ruleId: "mobile.ios/usage-description-empty",
	title: "Empty permission purpose string",
	severity: "medium",
	category: "privacy",
	references: PRIVACY_REFERENCES,
	tags: ["masvs-privacy-1"],
};

const emptyUsageFinding = (src: PlistSource, key: PlistKey) =>
	keyFinding(src, key, {
		...EMPTY_USAGE,
		message: `${key} is empty. Users get no explanation for the permission prompt and App Review rejects apps with blank purpose strings.`,
		remediation: `Set ${key} to a specific, user-facing explanation of why the app needs this access.`,
		evidence: `${key} = ""`,
	});

const isBlank = (value: unknown) =>
	typeof value === "string" && value.trim() === "";

const FILE_SHARING_KEYS = [
	"UIFileSharingEnabled",
	"LSSupportsOpeningDocumentsInPlace",
];

const FILE_SHARING: KeyRule = {
	ruleId: "mobile.ios/file-sharing-enabled",
	title: "Documents directory exposed",
	severity: "info",
	category: "privacy",
	references: [MASVS_PLATFORM],
	tags: ["masvs-storage-1"],
};

const fileSharingFinding = (src: PlistSource, key: PlistKey) =>
	keyFinding(src, key, {
		...FILE_SHARING,
		message: `${key} is enabled, so the app's Documents directory is visible in the Files app and Finder.`,
		remediation:
			"Make sure nothing sensitive (tokens, databases, caches) is stored in Documents; use Application Support or the Keychain instead.",
		evidence: `${key} = true`,
	});

const listOf = (value: unknown): unknown[] =>
	Array.isArray(value) ? value : [];

export const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value !== "";

const urlSchemeFindings = (src: PlistSource): FindingInput[] =>
	listOf(src.value.CFBundleURLTypes).flatMap((type) =>
		listOf(asDict(type as PlistValue)?.CFBundleURLSchemes)
			.filter(isNonEmptyString)
			.map((scheme) =>
				customSchemeFinding(scheme, locate(src, "CFBundleURLSchemes")),
			),
	);

/** Checks shared by Info.plist files, IPA plists and Expo `ios.infoPlist`. */
export const checkInfoPlist = (src: PlistSource): FindingInput[] => {
	const plist = src.value;
	const ats = asDict(plist.NSAppTransportSecurity);
	return [
		...(ats ? atsFindings(src, ats) : []),
		...exceptionDomainsFindings(src, ats),
		...USAGE_KEYS.filter((key) => isBlank(plist[key])).map((key) =>
			emptyUsageFinding(src, key),
		),
		...FILE_SHARING_KEYS.filter((key) => isTrue(plist[key])).map((key) =>
			fileSharingFinding(src, key),
		),
		...urlSchemeFindings(src),
	];
};

export const customSchemeFinding = (
	scheme: PlistKey,
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

export const checkEntitlements = (src: PlistSource): FindingInput[] =>
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
