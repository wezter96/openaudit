import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	fromArtifact,
	fromSource,
	type Inputs,
	type ManifestDoc,
	type SdkLevels,
	type XmlDoc,
} from "./android-inputs";
import {
	at,
	checkApplication,
	checkComponents,
	checkDeepLinks,
	checkPermissions,
	checkTaskHijacking,
	evidenceOf,
	MASVS,
} from "./android-manifest";
import { childrenNamed, descendants, type XmlElement } from "./axml";
import { loadMobileTarget, type MobileTarget } from "./shared";

/** Lowest targetSdk Google Play accepts for new apps and updates (Aug 2025). */
const DEFAULT_MIN_TARGET_SDK = 35;
/** Android 6.0: runtime permissions, modern TLS defaults. */
const MIN_SDK_FLOOR = 23;

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

/** A base-config or domain-config and the domains it applies to. */
interface NscScope {
	readonly el: XmlElement;
	readonly base: boolean;
	readonly scope: string;
}

const scopeLabel = (el: XmlElement, base: boolean) => {
	if (base) return "all domains";
	const domains = childrenNamed(el, "domain")
		.map((d) => d.text)
		.filter(Boolean);
	return domains.length > 0 ? domains.join(", ") : "a domain-config";
};

const nscScopes = (doc: XmlDoc): NscScope[] =>
	[
		...childrenNamed(doc.root, "base-config").map((el) => ({
			el,
			base: true,
		})),
		...descendants(doc.root, "domain-config").map((el) => ({
			el,
			base: false,
		})),
	].map(({ el, base }) => ({ el, base, scope: scopeLabel(el, base) }));

const cleartextPermittedFinding = (
	doc: XmlDoc,
	{ el, base, scope }: NscScope,
): FindingInput | undefined => {
	if (el.attrs.cleartextTrafficPermitted !== "true") return undefined;
	return {
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
	};
};

const userCertificateFindings = (
	doc: XmlDoc,
	{ el, scope }: NscScope,
): FindingInput[] =>
	childrenNamed(el, "trust-anchors").flatMap((anchors): FindingInput[] => {
		const user = childrenNamed(anchors, "certificates").find(
			(c) => c.attrs.src === "user",
		);
		if (!user) return [];
		return [
			{
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
			},
		];
	});

const checkNetworkConfig = (doc: XmlDoc): FindingInput[] =>
	nscScopes(doc).flatMap((scope) => {
		const cleartext = cleartextPermittedFinding(doc, scope);
		return [
			...(cleartext ? [cleartext] : []),
			...userCertificateFindings(doc, scope),
		];
	});

const undecodableFinding = (file: string): FindingInput => ({
	ruleId: "mobile.android/manifest-undecodable",
	title: "Manifest could not be decoded",
	severity: "info" as const,
	category: "security" as const,
	message: `${file} is not valid text, binary (AXML) or protobuf XML, so manifest checks were not run.`,
	remediation:
		"Audit the source tree, or decode the manifest with bundletool/apktool and audit the output.",
	location: { file },
});

const loadInputs = (target: MobileTarget): Effect.Effect<Inputs> =>
	target.kind === "artifact"
		? Effect.succeed(fromArtifact(target))
		: fromSource(target.ws, target.files);

const nothingToAudit = (inputs: Inputs) =>
	inputs.manifests.length +
		inputs.networkConfigs.length +
		inputs.undecodable.length ===
	0;

const minTargetSdkOf = (ctx: AuditContext): number => {
	const setting = ctx.options.settings?.["mobile.android"]?.minTargetSdk;
	return typeof setting === "number" ? setting : DEFAULT_MIN_TARGET_SDK;
};

const applicationFindings = (
	doc: ManifestDoc,
	app: XmlElement,
	inputs: Inputs,
): FindingInput[] => [
	...checkApplication({
		doc,
		app,
		sdk: inputs.sdk,
		hasNetworkConfig:
			inputs.networkConfigs.length > 0 ||
			app.attrs.networkSecurityConfig !== undefined,
	}),
	...checkComponents(doc, app, app.attrs.permission),
	...checkTaskHijacking(doc, app, inputs.sdk),
	...checkDeepLinks(doc, app),
];

const manifestFindings = (doc: ManifestDoc, inputs: Inputs): FindingInput[] => [
	...checkPermissions(doc),
	...childrenNamed(doc.root, "application").flatMap((app) =>
		applicationFindings(doc, app, inputs),
	),
];

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
			const inputs = yield* loadInputs(target);
			if (nothingToAudit(inputs))
				return yield* skip("No AndroidManifest.xml found");
			return [
				...inputs.undecodable.map(undecodableFinding),
				...inputs.manifests.flatMap((doc) => manifestFindings(doc, inputs)),
				...inputs.networkConfigs.flatMap(checkNetworkConfig),
				...checkSdk(inputs.sdk, minTargetSdkOf(ctx)),
			];
		}),
});
