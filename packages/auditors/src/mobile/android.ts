import {
	defineAuditor,
	type FindingInput,
	lineAt,
	lineOf,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	childrenNamed,
	descendants,
	parseAndroidXml,
	parseXmlText,
	renderTag,
	type XmlElement,
} from "./axml";
import { loadMobileTarget, type MobileArtifact } from "./shared";

/** Lowest targetSdk Google Play accepts for new apps and updates (Aug 2025). */
const DEFAULT_MIN_TARGET_SDK = 35;
/** Android 6.0: runtime permissions, modern TLS defaults. */
const MIN_SDK_FLOOR = 23;

const MASVS = "https://mas.owasp.org/MASVS/";

/** Runtime permissions that warrant a privacy review, with a reason. */
const DANGEROUS_PERMISSIONS: Record<string, string> = {
	READ_SMS: "read SMS messages (including OTP codes)",
	SEND_SMS: "send SMS messages (premium-rate fraud vector)",
	RECEIVE_SMS: "receive SMS messages",
	RECEIVE_MMS: "receive MMS messages",
	READ_CALL_LOG: "read the call log",
	WRITE_CALL_LOG: "modify the call log",
	PROCESS_OUTGOING_CALLS: "observe outgoing calls",
	READ_CONTACTS: "read contacts",
	WRITE_CONTACTS: "modify contacts",
	ACCESS_FINE_LOCATION: "precise location",
	ACCESS_BACKGROUND_LOCATION: "location while in the background",
	RECORD_AUDIO: "the microphone",
	CAMERA: "the camera",
	READ_EXTERNAL_STORAGE: "shared storage",
	WRITE_EXTERNAL_STORAGE: "write to shared storage",
	MANAGE_EXTERNAL_STORAGE: "all files on shared storage",
	READ_PHONE_STATE: "phone state and identifiers",
	CALL_PHONE: "place phone calls without user confirmation",
	BODY_SENSORS: "body sensors",
	SYSTEM_ALERT_WINDOW: "draw over other apps (overlay/tapjacking vector)",
	REQUEST_INSTALL_PACKAGES: "install other packages",
	QUERY_ALL_PACKAGES: "enumerate all installed apps",
};

/** Permissions Google Play restricts or that are common abuse vectors. */
const HIGH_RISK_PERMISSIONS = new Set([
	"READ_SMS",
	"SEND_SMS",
	"RECEIVE_SMS",
	"RECEIVE_MMS",
	"READ_CALL_LOG",
	"WRITE_CALL_LOG",
	"PROCESS_OUTGOING_CALLS",
	"SYSTEM_ALERT_WINDOW",
	"REQUEST_INSTALL_PACKAGES",
	"MANAGE_EXTERNAL_STORAGE",
	"QUERY_ALL_PACKAGES",
]);

const COMPONENTS = [
	"activity",
	"activity-alias",
	"service",
	"receiver",
	"provider",
] as const;

const LAUNCH_MODES = [
	"standard",
	"singleTop",
	"singleTask",
	"singleInstance",
	"singleInstancePerTask",
];

interface XmlDoc {
	/** Location used in findings (`app.apk!/AndroidManifest.xml` for artifacts). */
	readonly file: string;
	readonly root: XmlElement;
	/** Source text, when available, for evidence lines. */
	readonly text?: string;
}

interface ManifestDoc extends XmlDoc {
	/** The application's own manifest (as opposed to a library module's). */
	readonly main: boolean;
}

interface SdkLevels {
	readonly min?: { value: number; file: string; line?: number };
	readonly target?: { value: number; file: string; line?: number };
}

interface Inputs {
	readonly manifests: ReadonlyArray<ManifestDoc>;
	readonly networkConfigs: ReadonlyArray<XmlDoc>;
	readonly sdk: SdkLevels;
	readonly undecodable: ReadonlyArray<string>;
}

/* ------------------------------ input loading ----------------------------- */

const NSC_ROOT = "network-security-config";

const fromArtifact = (artifact: MobileArtifact): Inputs => {
	const prefix = artifact.type === "aab" ? "base/" : "";
	const manifestPath =
		artifact.type === "aab"
			? "base/manifest/AndroidManifest.xml"
			: "AndroidManifest.xml";
	// Network security configs live in res/xml*, or anywhere under res/ once
	// resource names are obfuscated; identify them by their root element.
	const xmlRe = new RegExp(`^${prefix}res/(xml[^/]*/[^/]+|[^/]+)\\.xml$`);
	const entries = artifact.extract(
		(name, info) =>
			name === manifestPath ||
			(xmlRe.test(name) && info.originalSize < 256 * 1024),
	);
	const at = (name: string) => `${artifact.file}!/${name}`;
	const manifests: ManifestDoc[] = [];
	const undecodable: string[] = [];
	const manifestBytes = entries[manifestPath];
	if (manifestBytes) {
		const root = parseAndroidXml(manifestBytes);
		if (root?.name === "manifest")
			manifests.push({ file: at(manifestPath), root, main: true });
		else undecodable.push(at(manifestPath));
	}
	const networkConfigs: XmlDoc[] = [];
	for (const [name, bytes] of Object.entries(entries)) {
		if (name === manifestPath) continue;
		const root = parseAndroidXml(bytes);
		if (root?.name === NSC_ROOT) networkConfigs.push({ file: at(name), root });
	}
	const usesSdk = manifests[0]
		? childrenNamed(manifests[0].root, "uses-sdk")[0]
		: undefined;
	const sdkLevel = (attr: string) => {
		const value = Number.parseInt(usesSdk?.attrs[attr] ?? "", 10);
		return Number.isFinite(value) && manifests[0]
			? {
					value,
					file: manifests[0].file,
					...(usesSdk?.line ? { line: usesSdk.line } : {}),
				}
			: undefined;
	};
	const min = sdkLevel("minSdkVersion");
	const target = sdkLevel("targetSdkVersion");
	return {
		manifests,
		networkConfigs,
		sdk: { ...(min ? { min } : {}), ...(target ? { target } : {}) },
		undecodable,
	};
};

/** Debug/test source sets legitimately relax security settings. */
const NON_RELEASE_SOURCE_SET = /(^|\/)src\/(debug|test|androidTest)[^/]*\//;

const isLauncher = (component: XmlElement) =>
	childrenNamed(component, "intent-filter").some(
		(f) =>
			childrenNamed(f, "action").some(
				(a) => a.attrs.name === "android.intent.action.MAIN",
			) &&
			childrenNamed(f, "category").some(
				(c) => c.attrs.name === "android.intent.category.LAUNCHER",
			),
	);

const hasLauncher = (manifest: XmlElement) =>
	childrenNamed(manifest, "application").some((app) =>
		[
			...childrenNamed(app, "activity"),
			...childrenNamed(app, "activity-alias"),
		].some(isLauncher),
	);

const GRADLE_SDK_RE =
	/\b(minSdk|minSdkVersion|targetSdk|targetSdkVersion)\b\s*(?:=|\(|\s)\s*(\d+)/g;

const sdkFromGradle = (
	ws: Workspace,
	files: ReadonlyArray<string>,
): Effect.Effect<SdkLevels> =>
	Effect.gen(function* () {
		const gradle = files.filter((f) => /(^|\/)build\.gradle(\.kts)?$/.test(f));
		let fallback: SdkLevels = {};
		for (const file of gradle) {
			const text = yield* ws
				.readText(file)
				.pipe(Effect.orElseSucceed(() => ""));
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
			const levels = { ...(min ? { min } : {}), ...(target ? { target } : {}) };
			if (!min && !target) continue;
			if (/com\.android\.application/.test(text)) return levels;
			if (!fallback.min && !fallback.target) fallback = levels;
		}
		return fallback;
	});

const fromSource = (
	ws: Workspace,
	files: ReadonlyArray<string>,
): Effect.Effect<Inputs> =>
	Effect.gen(function* () {
		const read = (file: string) =>
			ws.readText(file).pipe(Effect.orElseSucceed(() => undefined));
		const parsed: Array<{ file: string; root: XmlElement; text: string }> = [];
		for (const file of files) {
			if (!/(^|\/)AndroidManifest\.xml$/.test(file)) continue;
			if (NON_RELEASE_SOURCE_SET.test(file)) continue;
			const text = yield* read(file);
			const root = text === undefined ? undefined : parseXmlText(text);
			if (text !== undefined && root?.name === "manifest")
				parsed.push({ file, root, text });
		}
		// Application-level defaults only matter in the app's own manifest.
		const launchers = parsed.filter((m) => hasLauncher(m.root));
		const mainSet = new Set(
			(launchers.length > 0
				? launchers
				: parsed.filter((m) => childrenNamed(m.root, "application").length)
			).map((m) => m.file),
		);
		const manifests = parsed.map((m) => ({ ...m, main: mainSet.has(m.file) }));

		const networkConfigs: XmlDoc[] = [];
		for (const file of files) {
			if (!/(^|\/)res\/xml[^/]*\/[^/]+\.xml$/.test(file)) continue;
			if (NON_RELEASE_SOURCE_SET.test(file)) continue;
			const text = yield* read(file);
			if (text === undefined || !text.includes(NSC_ROOT)) continue;
			const root = parseXmlText(text);
			if (root?.name === NSC_ROOT) networkConfigs.push({ file, root, text });
		}

		const gradleSdk = yield* sdkFromGradle(ws, files);
		const main = manifests.find((m) => m.main);
		const usesSdk = main ? childrenNamed(main.root, "uses-sdk")[0] : undefined;
		const manifestLevel = (attr: string) => {
			const value = Number.parseInt(usesSdk?.attrs[attr] ?? "", 10);
			return main && Number.isFinite(value)
				? {
						value,
						file: main.file,
						...(usesSdk?.line ? { line: usesSdk.line } : {}),
					}
				: undefined;
		};
		// Gradle overrides manifest values during manifest merging.
		const min = gradleSdk.min ?? manifestLevel("minSdkVersion");
		const target = gradleSdk.target ?? manifestLevel("targetSdkVersion");
		return {
			manifests,
			networkConfigs,
			sdk: { ...(min ? { min } : {}), ...(target ? { target } : {}) },
			undecodable: [],
		};
	});

/* --------------------------------- checks --------------------------------- */

const at = (doc: XmlDoc, el: XmlElement) => ({
	file: doc.file,
	...(el.line ? { line: el.line } : {}),
});

/** Source line for text docs, a rendered tag for binary ones. */
const evidenceOf = (doc: XmlDoc, el: XmlElement) => {
	if (doc.text && el.line) {
		const lines = doc.text.split("\n");
		const offset = lines
			.slice(0, el.line - 1)
			.reduce((n, l) => n + l.length + 1, 0);
		return lineAt(doc.text, offset);
	}
	return renderTag(el);
};

const shortName = (name: string | undefined) =>
	name?.replace(/^android\.permission\./, "") ?? "";

const checkApplication = (
	doc: ManifestDoc,
	app: XmlElement,
	sdk: SdkLevels,
	hasNetworkConfig: boolean,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const a = app.attrs;

	if (a.debuggable === "true")
		findings.push({
			ruleId: "mobile.android/debuggable",
			title: "App is debuggable",
			severity: "high",
			category: "security",
			message:
				'android:debuggable="true" lets anyone with USB/ADB access attach a debugger, dump memory and run code as the app.',
			remediation:
				"Remove android:debuggable from the manifest; the build system sets it only for debug builds.",
			location: at(doc, app),
			evidence: evidenceOf(doc, app),
			references: [
				"https://developer.android.com/privacy-and-security/risks/android-debuggable",
				MASVS,
			],
			tags: ["cwe-489", "masvs-resilience"],
		});

	if (doc.main && a.allowBackup !== "false") {
		const hasRules = Boolean(a.fullBackupContent || a.dataExtractionRules);
		findings.push({
			ruleId: "mobile.android/allow-backup",
			title:
				a.allowBackup === "true"
					? "App data backup is enabled"
					: "App data backup is enabled by default",
			severity: hasRules ? "low" : "medium",
			category: "security",
			message: `${a.allowBackup === "true" ? 'android:allowBackup="true"' : "android:allowBackup is not set (defaults to true)"}, so app data (tokens, databases, shared preferences) can be extracted via adb backup or restored to another device${hasRules ? "; backup rules are configured, review that they exclude sensitive files" : ""}.`,
			remediation:
				'Set android:allowBackup="false", or define dataExtractionRules/fullBackupContent that exclude credentials and personal data.',
			location: at(doc, app),
			evidence: evidenceOf(doc, app),
			references: [
				"https://developer.android.com/privacy-and-security/risks/backup-best-practices",
				MASVS,
			],
			tags: ["cwe-530", "masvs-storage"],
			confidence: a.allowBackup === "true" ? "high" : "medium",
		});
	}

	if (a.usesCleartextTraffic === "true")
		findings.push({
			ruleId: "mobile.android/cleartext-traffic",
			title: "Cleartext HTTP traffic allowed",
			severity: "medium",
			category: "security",
			message:
				'android:usesCleartextTraffic="true" allows unencrypted HTTP connections that can be read or modified on the network.',
			remediation:
				"Remove the attribute (default is false from API 28) and use HTTPS; if a legacy host needs HTTP, allow it only for that domain in a network security config.",
			location: at(doc, app),
			evidence: evidenceOf(doc, app),
			references: [
				"https://developer.android.com/privacy-and-security/security-config",
				MASVS,
			],
			tags: ["cwe-319", "masvs-network"],
		});
	else if (
		doc.main &&
		a.usesCleartextTraffic === undefined &&
		!hasNetworkConfig &&
		sdk.target &&
		sdk.target.value < 28
	)
		findings.push({
			ruleId: "mobile.android/cleartext-traffic",
			title: "Cleartext HTTP traffic allowed by default",
			severity: "low",
			category: "security",
			message: `targetSdkVersion ${sdk.target.value} (< 28) permits cleartext HTTP by default and no network security config restricts it.`,
			remediation:
				'Set android:usesCleartextTraffic="false" or add a network security config with cleartextTrafficPermitted="false".',
			location: at(doc, app),
			references: [
				"https://developer.android.com/privacy-and-security/security-config",
			],
			tags: ["cwe-319", "masvs-network"],
			confidence: "medium",
		});

	return findings;
};

const severityFor = (
	type: string,
	component: XmlElement,
): Severity | undefined => {
	if (type === "provider") return "high";
	if (type === "activity" || type === "activity-alias") return "low";
	if (type === "receiver") {
		// Protected system broadcasts can only be sent by the OS.
		const actions = descendants(component, "action").map(
			(x) => x.attrs.name ?? "",
		);
		if (
			actions.length > 0 &&
			actions.every((x) => x.startsWith("android.intent.action."))
		)
			return "low";
	}
	return "medium";
};

const checkComponents = (
	doc: ManifestDoc,
	app: XmlElement,
	appPermission: string | undefined,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const type of COMPONENTS) {
		for (const c of childrenNamed(app, type)) {
			const filters = childrenNamed(c, "intent-filter");
			const name = c.attrs.name ?? c.attrs.targetActivity ?? "(unnamed)";
			if (c.attrs.exported === undefined && filters.length > 0)
				findings.push({
					ruleId: "mobile.android/exported-undeclared",
					title: `${type} with intent-filter does not declare android:exported`,
					severity: "low",
					category: "best-practices",
					message: `${type} ${name} has an intent-filter but no android:exported attribute. It is implicitly exported on Android 11 and below, and apps targeting Android 12+ fail to install.`,
					remediation:
						'Declare android:exported explicitly; use "false" unless other apps must start this component.',
					location: at(doc, c),
					evidence: evidenceOf(doc, c),
					references: [
						"https://developer.android.com/about/versions/12/behavior-changes-12#exported",
					],
					tags: ["cwe-926", "masvs-platform"],
				});

			const exported =
				c.attrs.exported === "true" ||
				(c.attrs.exported === undefined && filters.length > 0);
			if (!exported || isLauncher(c)) continue;
			const protectedBy =
				c.attrs.permission ??
				(type === "provider"
					? (c.attrs.readPermission ?? c.attrs.writePermission)
					: undefined) ??
				(type === "activity-alias" ? undefined : appPermission);
			if (protectedBy) continue;
			const severity = severityFor(type, c) ?? "medium";
			findings.push({
				ruleId: "mobile.android/exported-component",
				title: `Exported ${type} without permission`,
				severity,
				category: "security",
				message: `${type} ${name} is exported and not protected by a permission, so any installed app can ${type === "provider" ? "query or modify its data" : type === "receiver" ? "send it broadcasts" : type === "service" ? "bind to or start it" : "launch it with crafted intents"}.`,
				remediation:
					'Set android:exported="false" if other apps do not need it; otherwise require a signature-level android:permission and validate all intent extras.',
				location: at(doc, c),
				evidence: evidenceOf(doc, c),
				references: [
					"https://developer.android.com/privacy-and-security/risks/android-exported",
					MASVS,
				],
				tags: ["cwe-926", "masvs-platform"],
				confidence: "medium",
			});
		}
	}
	return findings;
};

const checkTaskHijacking = (
	doc: ManifestDoc,
	app: XmlElement,
	sdk: SdkLevels,
): FindingInput[] => {
	// StrandHogg is mitigated for singleTask activities on Android 11+.
	if (sdk.min && sdk.min.value >= 30) return [];
	const appAffinity = app.attrs.taskAffinity;
	const findings: FindingInput[] = [];
	for (const activity of childrenNamed(app, "activity")) {
		const raw = activity.attrs.launchMode;
		const mode = raw && /^\d+$/.test(raw) ? LAUNCH_MODES[Number(raw)] : raw;
		const affinity = activity.attrs.taskAffinity ?? appAffinity;
		const customAffinity = affinity !== undefined && affinity !== "";
		const singleTask =
			(mode === "singleTask" || mode === "singleInstance") && affinity !== "";
		if (!customAffinity && !singleTask) continue;
		findings.push({
			ruleId: "mobile.android/task-hijacking",
			title: "Activity susceptible to task hijacking",
			severity: "low",
			category: "security",
			message: `Activity ${activity.attrs.name ?? "(unnamed)"} ${customAffinity ? `sets taskAffinity="${affinity}"` : `uses launchMode="${mode}"`}, which lets a malicious app place its own activity in the same task (StrandHogg) to phish users.`,
			remediation:
				'Set android:taskAffinity="" on the <application> (or activity) and avoid singleTask/singleInstance unless needed; raise minSdk to 30+ where possible.',
			location: at(doc, activity),
			evidence: evidenceOf(doc, activity),
			references: [
				"https://developer.android.com/privacy-and-security/risks/strandhogg",
				MASVS,
			],
			tags: ["cwe-1021", "masvs-platform"],
			confidence: "low",
		});
	}
	return findings;
};

const checkDeepLinks = (doc: ManifestDoc, app: XmlElement): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const type of ["activity", "activity-alias"]) {
		for (const c of childrenNamed(app, type)) {
			for (const filter of childrenNamed(c, "intent-filter")) {
				const view = childrenNamed(filter, "action").some(
					(a) => a.attrs.name === "android.intent.action.VIEW",
				);
				const browsable = childrenNamed(filter, "category").some(
					(x) => x.attrs.name === "android.intent.category.BROWSABLE",
				);
				if (!view || !browsable) continue;
				const data = childrenNamed(filter, "data");
				const schemes = new Set(
					data.map((d) => d.attrs.scheme).filter((s): s is string => !!s),
				);
				const hosts = data
					.map((d) => d.attrs.host)
					.filter((h): h is string => !!h);
				const web = [...schemes].filter((s) => s === "http" || s === "https");
				const custom = [...schemes].filter(
					(s) => s !== "http" && s !== "https",
				);
				const name = c.attrs.name ?? "(unnamed)";
				if (
					web.length > 0 &&
					hosts.length > 0 &&
					filter.attrs.autoVerify !== "true"
				)
					findings.push({
						ruleId: "mobile.android/app-link-unverified",
						title: "Web deep link without App Links verification",
						severity: "low",
						category: "security",
						message: `${name} handles ${web.join("/")} links for ${hosts.join(", ")} without android:autoVerify="true", so other apps can register the same links and intercept them (including OAuth redirects).`,
						remediation:
							'Add android:autoVerify="true" to the intent-filter and publish /.well-known/assetlinks.json on each host.',
						location: at(doc, filter),
						evidence: evidenceOf(doc, filter),
						references: [
							"https://developer.android.com/training/app-links/verify-android-applinks",
							"https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks",
						],
						tags: ["cwe-939", "masvs-platform"],
					});
				if (custom.length > 0)
					findings.push({
						ruleId: "mobile.android/custom-scheme-deep-link",
						title: "Custom URL scheme deep link",
						severity: "info",
						category: "security",
						message: `${name} handles the custom scheme(s) ${custom.map((s) => `${s}://`).join(", ")}. Any app can claim the same scheme, so links must not carry secrets and handlers must validate all parameters.`,
						remediation:
							"Prefer verified https App Links; validate and authorise every deep-link parameter.",
						location: at(doc, filter),
						evidence: evidenceOf(doc, filter),
						references: [
							"https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks",
						],
						tags: ["cwe-939", "masvs-platform"],
					});
			}
		}
	}
	return findings;
};

const checkPermissions = (doc: ManifestDoc): FindingInput[] =>
	[
		...childrenNamed(doc.root, "uses-permission"),
		...childrenNamed(doc.root, "uses-permission-sdk-23"),
	].flatMap((p): FindingInput[] => {
		const name = shortName(p.attrs.name);
		const reason = DANGEROUS_PERMISSIONS[name];
		if (!reason) return [];
		return [
			{
				ruleId: "mobile.android/dangerous-permission",
				title: `Sensitive permission: ${name}`,
				severity: HIGH_RISK_PERMISSIONS.has(name) ? "low" : "info",
				category: "privacy",
				message: `The app requests ${p.attrs.name}, giving it access to ${reason}. Confirm it is required and disclosed in the privacy policy and Play data-safety form.`,
				remediation:
					"Remove unused permissions (check merged manifests from libraries too) and request sensitive ones only at the point of use.",
				location: at(doc, p),
				evidence: evidenceOf(doc, p),
				references: [
					"https://developer.android.com/guide/topics/permissions/overview",
					"https://support.google.com/googleplay/android-developer/answer/9888170",
				],
				tags: ["masvs-privacy"],
			},
		];
	});

const checkSdk = (sdk: SdkLevels, minTargetSdk: number): FindingInput[] => {
	const findings: FindingInput[] = [];
	if (sdk.min && sdk.min.value < MIN_SDK_FLOOR)
		findings.push({
			ruleId: "mobile.android/min-sdk-low",
			title: `minSdkVersion ${sdk.min.value} is very old`,
			severity: "low",
			category: "security",
			message: `minSdkVersion ${sdk.min.value} lets the app run on Android versions below 6.0 that lack runtime permissions, modern TLS defaults and years of security patches.`,
			remediation: `Raise minSdkVersion to at least ${MIN_SDK_FLOOR}.`,
			location: {
				file: sdk.min.file,
				...(sdk.min.line ? { line: sdk.min.line } : {}),
			},
			evidence: `minSdkVersion ${sdk.min.value}`,
			references: [
				"https://developer.android.com/guide/topics/manifest/uses-sdk-element",
				MASVS,
			],
			tags: ["masvs-code"],
		});
	if (sdk.target && sdk.target.value < minTargetSdk)
		findings.push({
			ruleId: "mobile.android/target-sdk-low",
			title: `targetSdkVersion ${sdk.target.value} is below the Google Play requirement`,
			severity: "medium",
			category: "security",
			message: `targetSdkVersion ${sdk.target.value} opts the app out of platform security behaviours added since then, and Google Play requires API ${minTargetSdk}+ for new apps and updates.`,
			remediation: `Raise targetSdkVersion to ${minTargetSdk} or later and adapt to the behaviour changes.`,
			location: {
				file: sdk.target.file,
				...(sdk.target.line ? { line: sdk.target.line } : {}),
			},
			evidence: `targetSdkVersion ${sdk.target.value}`,
			references: [
				"https://developer.android.com/google/play/requirements/target-sdk",
			],
			tags: ["masvs-code"],
		});
	return findings;
};

const checkNetworkConfig = (doc: XmlDoc): FindingInput[] => {
	const findings: FindingInput[] = [];
	const scopes = [
		...childrenNamed(doc.root, "base-config").map((el) => ({
			el,
			base: true,
		})),
		...descendants(doc.root, "domain-config").map((el) => ({
			el,
			base: false,
		})),
	];
	for (const { el, base } of scopes) {
		const domains = childrenNamed(el, "domain")
			.map((d) => d.text)
			.filter(Boolean);
		const scope = base
			? "all domains"
			: domains.length > 0
				? domains.join(", ")
				: "a domain-config";
		if (el.attrs.cleartextTrafficPermitted === "true")
			findings.push({
				ruleId: "mobile.android/nsc-cleartext-permitted",
				title: base
					? "Network security config permits cleartext for all domains"
					: "Network security config permits cleartext for some domains",
				severity: base ? "medium" : "low",
				category: "security",
				message: `cleartextTrafficPermitted="true" on ${scope} allows unencrypted HTTP that can be read or modified on the network.`,
				remediation:
					'Set cleartextTrafficPermitted="false" and serve the affected hosts over HTTPS.',
				location: at(doc, el),
				evidence: evidenceOf(doc, el),
				references: [
					"https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted",
					MASVS,
				],
				tags: ["cwe-319", "masvs-network"],
			});
		for (const anchors of childrenNamed(el, "trust-anchors")) {
			const user = childrenNamed(anchors, "certificates").find(
				(c) => c.attrs.src === "user",
			);
			if (!user) continue;
			findings.push({
				ruleId: "mobile.android/nsc-user-certificates",
				title: "App trusts user-installed CA certificates",
				severity: "medium",
				category: "security",
				message: `The network security config trusts user-added CAs for ${scope} outside debug-overrides, so a CA installed by the user (or malware/MDM) can intercept the app's TLS traffic.`,
				remediation:
					'Remove <certificates src="user"/> from release configs; put it under <debug-overrides> for local testing.',
				location: at(doc, user),
				evidence: evidenceOf(doc, user),
				references: [
					"https://developer.android.com/privacy-and-security/security-config#TrustingDebugCa",
					MASVS,
				],
				tags: ["cwe-295", "masvs-network"],
			});
		}
	}
	return findings;
};

/** Manifest and network-security checks for Android apps. */
export const android = defineAuditor({
	id: "mobile.android",
	title: "Android app configuration",
	description:
		"Checks AndroidManifest.xml (text or binary, from source trees, APKs and AABs) and network security configs for debuggable builds, backups, cleartext traffic, exported components, sensitive permissions, outdated SDK levels, task hijacking and unverified deep links.",
	categories: ["security", "privacy", "best-practices"],
	targets: ["mobile"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const target = yield* loadMobileTarget(ctx);
			if (target.kind === "artifact" && target.type === "ipa")
				return yield* skip("Target is an iOS app");
			const inputs =
				target.kind === "artifact"
					? fromArtifact(target)
					: yield* fromSource(target.ws, target.files);

			const findings: FindingInput[] = inputs.undecodable.map((file) => ({
				ruleId: "mobile.android/manifest-undecodable",
				title: "Manifest could not be decoded",
				severity: "info" as const,
				category: "security" as const,
				message: `${file} is not valid text, binary (AXML) or protobuf XML, so manifest checks were not run.`,
				remediation:
					"Audit the source tree, or decode the manifest with bundletool/apktool and audit the output.",
				location: { file },
			}));
			if (
				inputs.manifests.length === 0 &&
				inputs.networkConfigs.length === 0 &&
				findings.length === 0
			)
				return yield* skip("No AndroidManifest.xml found");

			const setting = ctx.options.settings?.["mobile.android"]?.minTargetSdk;
			const minTargetSdk =
				typeof setting === "number" ? setting : DEFAULT_MIN_TARGET_SDK;

			for (const doc of inputs.manifests) {
				findings.push(...checkPermissions(doc));
				for (const app of childrenNamed(doc.root, "application")) {
					findings.push(
						...checkApplication(
							doc,
							app,
							inputs.sdk,
							inputs.networkConfigs.length > 0 ||
								app.attrs.networkSecurityConfig !== undefined,
						),
						...checkComponents(doc, app, app.attrs.permission),
						...checkTaskHijacking(doc, app, inputs.sdk),
						...checkDeepLinks(doc, app),
					);
				}
			}
			for (const doc of inputs.networkConfigs)
				findings.push(...checkNetworkConfig(doc));
			findings.push(...checkSdk(inputs.sdk, minTargetSdk));
			return findings;
		}),
});
