import { type FindingInput, lineAt, type Severity } from "@openaudit/core";
import {
	isLauncher,
	type ManifestDoc,
	type SdkLevels,
	type XmlDoc,
} from "./android-inputs";
import { childrenNamed, descendants, renderTag, type XmlElement } from "./axml";

/** Checks on the `<application>` and its components in an Android manifest. */

export const MASVS = "https://mas.owasp.org/MASVS/";

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

type ComponentType = (typeof COMPONENTS)[number];

const LAUNCH_MODES = [
	"standard",
	"singleTop",
	"singleTask",
	"singleInstance",
	"singleInstancePerTask",
];

export const at = (doc: XmlDoc, el: XmlElement) => ({
	file: doc.file,
	...(el.line ? { line: el.line } : {}),
});

/** Source line for text docs, a rendered tag for binary ones. */
export const evidenceOf = (doc: XmlDoc, el: XmlElement) => {
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

/** An `<application>` element with what its checks need to know. */
export interface AppScope {
	readonly doc: ManifestDoc;
	readonly app: XmlElement;
	readonly sdk: SdkLevels;
	readonly hasNetworkConfig: boolean;
}

const debuggableFinding = ({
	doc,
	app,
}: AppScope): FindingInput | undefined => {
	if (app.attrs.debuggable !== "true") return undefined;
	return {
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
	};
};

/** Backup is on unless the app's own manifest turns it off. */
const backupEnabled = (doc: ManifestDoc, a: XmlElement["attrs"]) =>
	doc.main && a.allowBackup !== "false";

const hasBackupRules = (a: XmlElement["attrs"]) =>
	Boolean(a.fullBackupContent || a.dataExtractionRules);

const allowBackupFinding = ({
	doc,
	app,
}: AppScope): FindingInput | undefined => {
	const a = app.attrs;
	if (!backupEnabled(doc, a)) return undefined;
	const hasRules = hasBackupRules(a);
	return {
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
	};
};

/** No attribute or network security config overrides the platform default. */
const cleartextUnset = ({ doc, app, hasNetworkConfig }: AppScope) =>
	doc.main && app.attrs.usesCleartextTraffic === undefined && !hasNetworkConfig;

const cleartextFinding = (scope: AppScope): FindingInput | undefined => {
	const { doc, app, sdk } = scope;
	if (app.attrs.usesCleartextTraffic === "true")
		return {
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
		};
	if (!cleartextUnset(scope)) return undefined;
	if (!sdk.target || sdk.target.value >= 28) return undefined;
	return {
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
	};
};

export const checkApplication = (scope: AppScope): FindingInput[] =>
	[
		debuggableFinding(scope),
		allowBackupFinding(scope),
		cleartextFinding(scope),
	].filter((f): f is FindingInput => f !== undefined);

const COMPONENT_SEVERITY: Partial<Record<ComponentType, Severity>> = {
	provider: "high",
	activity: "low",
	"activity-alias": "low",
};

/** Protected system broadcasts can only be sent by the OS. */
const onlySystemBroadcasts = (component: XmlElement) => {
	const actions = descendants(component, "action").map(
		(x) => x.attrs.name ?? "",
	);
	return (
		actions.length > 0 &&
		actions.every((x) => x.startsWith("android.intent.action."))
	);
};

const severityFor = (
	type: ComponentType,
	component: XmlElement,
): Severity | undefined => {
	const fixed = COMPONENT_SEVERITY[type];
	if (fixed) return fixed;
	if (type === "receiver" && onlySystemBroadcasts(component)) return "low";
	return "medium";
};

const isExported = (c: XmlElement, filters: ReadonlyArray<XmlElement>) =>
	c.attrs.exported === "true" ||
	(c.attrs.exported === undefined && filters.length > 0);

/** The permission guarding a component, inherited from the application. */
const protectingPermission = (
	type: ComponentType,
	c: XmlElement,
	appPermission: string | undefined,
) =>
	c.attrs.permission ??
	(type === "provider"
		? (c.attrs.readPermission ?? c.attrs.writePermission)
		: undefined) ??
	(type === "activity-alias" ? undefined : appPermission);

/** One manifest component and what its findings need. */
interface ComponentScope {
	readonly doc: ManifestDoc;
	readonly type: ComponentType;
	readonly c: XmlElement;
	readonly name: string;
}

const exportedUndeclaredFinding = ({
	doc,
	type,
	c,
	name,
}: ComponentScope): FindingInput => ({
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

const exportedComponentFinding = (
	{ doc, type, c, name }: ComponentScope,
	severity: Severity,
): FindingInput => ({
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

const componentFindings = (
	doc: ManifestDoc,
	type: ComponentType,
	c: XmlElement,
	appPermission: string | undefined,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const filters = childrenNamed(c, "intent-filter");
	const scope: ComponentScope = {
		doc,
		type,
		c,
		name: c.attrs.name ?? c.attrs.targetActivity ?? "(unnamed)",
	};
	if (c.attrs.exported === undefined && filters.length > 0)
		findings.push(exportedUndeclaredFinding(scope));
	if (!isExported(c, filters) || isLauncher(c)) return findings;
	if (protectingPermission(type, c, appPermission)) return findings;
	const severity = severityFor(type, c) ?? "medium";
	findings.push(exportedComponentFinding(scope, severity));
	return findings;
};

export const checkComponents = (
	doc: ManifestDoc,
	app: XmlElement,
	appPermission: string | undefined,
): FindingInput[] =>
	COMPONENTS.flatMap((type) =>
		childrenNamed(app, type).flatMap((c) =>
			componentFindings(doc, type, c, appPermission),
		),
	);

/** A numeric launchMode (binary manifests) as its name. */
const launchModeOf = (raw: string | undefined) =>
	raw && /^\d+$/.test(raw) ? LAUNCH_MODES[Number(raw)] : raw;

const SINGLE_TASK_MODES = new Set(["singleTask", "singleInstance"]);

const hijackFinding = (
	doc: ManifestDoc,
	activity: XmlElement,
	appAffinity: string | undefined,
): FindingInput | undefined => {
	const mode = launchModeOf(activity.attrs.launchMode);
	const affinity = activity.attrs.taskAffinity ?? appAffinity;
	const customAffinity = affinity !== undefined && affinity !== "";
	const singleTask = SINGLE_TASK_MODES.has(mode ?? "") && affinity !== "";
	if (!customAffinity && !singleTask) return undefined;
	return {
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
	};
};

export const checkTaskHijacking = (
	doc: ManifestDoc,
	app: XmlElement,
	sdk: SdkLevels,
): FindingInput[] => {
	// StrandHogg is mitigated for singleTask activities on Android 11+.
	if ((sdk.min?.value ?? 0) >= 30) return [];
	return childrenNamed(app, "activity").flatMap((activity) => {
		const finding = hijackFinding(doc, activity, app.attrs.taskAffinity);
		return finding ? [finding] : [];
	});
};

const isBrowsableView = (filter: XmlElement) =>
	childrenNamed(filter, "action").some(
		(a) => a.attrs.name === "android.intent.action.VIEW",
	) &&
	childrenNamed(filter, "category").some(
		(x) => x.attrs.name === "android.intent.category.BROWSABLE",
	);

const isWebScheme = (s: string) => s === "http" || s === "https";

/** A browsable VIEW intent-filter and the links it claims. */
interface DeepLink {
	readonly doc: ManifestDoc;
	readonly filter: XmlElement;
	readonly name: string;
	readonly web: string[];
	readonly custom: string[];
	readonly hosts: string[];
}

const deepLinkOf = (
	doc: ManifestDoc,
	c: XmlElement,
	filter: XmlElement,
): DeepLink | undefined => {
	if (!isBrowsableView(filter)) return undefined;
	const data = childrenNamed(filter, "data");
	const schemes = [
		...new Set(data.map((d) => d.attrs.scheme).filter((s): s is string => !!s)),
	];
	return {
		doc,
		filter,
		name: c.attrs.name ?? "(unnamed)",
		web: schemes.filter(isWebScheme),
		custom: schemes.filter((s) => !isWebScheme(s)),
		hosts: data.map((d) => d.attrs.host).filter((h): h is string => !!h),
	};
};

const unverified = (link: DeepLink) =>
	link.web.length > 0 &&
	link.hosts.length > 0 &&
	link.filter.attrs.autoVerify !== "true";

const unverifiedAppLinkFinding = ({
	doc,
	filter,
	name,
	web,
	hosts,
}: DeepLink): FindingInput => ({
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

const customSchemeFinding = ({
	doc,
	filter,
	name,
	custom,
}: DeepLink): FindingInput => ({
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

const deepLinkFindings = (link: DeepLink): FindingInput[] => [
	...(unverified(link) ? [unverifiedAppLinkFinding(link)] : []),
	...(link.custom.length > 0 ? [customSchemeFinding(link)] : []),
];

export const checkDeepLinks = (
	doc: ManifestDoc,
	app: XmlElement,
): FindingInput[] =>
	["activity", "activity-alias"]
		.flatMap((type) => childrenNamed(app, type))
		.flatMap((c) =>
			childrenNamed(c, "intent-filter").flatMap((filter) => {
				const link = deepLinkOf(doc, c, filter);
				return link ? deepLinkFindings(link) : [];
			}),
		);

export const checkPermissions = (doc: ManifestDoc): FindingInput[] =>
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
