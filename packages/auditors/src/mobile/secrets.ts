import {
	type Category,
	defineAuditor,
	type FindingInput,
	lineOf,
	redact,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { loadMobileTarget } from "./shared";

const MASVS_STORAGE = "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/";
const CWE_798 = "https://cwe.mitre.org/data/definitions/798.html";
const MAX_ENTRY_BYTES = 20 * 1024 * 1024;

interface SecretRule {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	/** Global regex; group 1 is the secret. */
	readonly re: RegExp;
	readonly what: string;
	readonly remediation: string;
}

const ROTATE =
	"Treat the credential as compromised: rotate it, remove it from the app and route the call through your backend.";

const RULES: ReadonlyArray<SecretRule> = [
	{
		id: "aws-access-key",
		title: "AWS access key embedded in app",
		severity: "high",
		re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g,
		what: "an AWS access key ID",
		remediation: `${ROTATE} Use Cognito identity pools or pre-signed URLs for client access.`,
	},
	{
		id: "aws-secret-key",
		title: "AWS secret key embedded in app",
		severity: "critical",
		re: /aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
		what: "an AWS secret access key",
		remediation: ROTATE,
	},
	{
		id: "stripe-live-secret",
		title: "Stripe live secret key embedded in app",
		severity: "critical",
		re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b/g,
		what: "a Stripe live secret/restricted key",
		remediation: `${ROTATE} Apps must only contain publishable (pk_live_) keys.`,
	},
	{
		id: "private-key",
		title: "Private key embedded in app",
		severity: "critical",
		re: /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----/g,
		what: "a PEM private key",
		remediation:
			"Remove the private key from the app and revoke it. Keys used on-device should be generated in the Keychain/Keystore, never shipped.",
	},
	{
		id: "github-token",
		title: "GitHub token embedded in app",
		severity: "high",
		re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/g,
		what: "a GitHub token",
		remediation: ROTATE,
	},
	{
		id: "slack-token",
		title: "Slack token embedded in app",
		severity: "high",
		re: /\b(xox[abprs]-[0-9A-Za-z-]{10,})\b/g,
		what: "a Slack token",
		remediation: ROTATE,
	},
	{
		id: "sendgrid-key",
		title: "SendGrid API key embedded in app",
		severity: "high",
		re: /\b(SG\.[\w-]{22}\.[\w-]{43})\b/g,
		what: "a SendGrid API key",
		remediation: ROTATE,
	},
	{
		id: "google-oauth-secret",
		title: "Google OAuth client secret embedded in app",
		severity: "high",
		re: /\b(GOCSPX-[\w-]{28})\b/g,
		what: "a Google OAuth client secret",
		remediation:
			"Mobile apps are public clients: use PKCE without a client secret and rotate this secret.",
	},
];

const GOOGLE_KEY_RE = /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g;
const FIREBASE_DB_RE =
	/\b(https:\/\/[a-z0-9-]+\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app))\b/g;
const HTTP_RE = /\bhttp:\/\/([a-z0-9.-]+)(?::\d+)?[^\s"'<>\\)]*/gi;

/** Assignment-like patterns in JS/JSON, Android string resources, plists and properties. */
const GENERIC_RES: ReadonlyArray<RegExp> = [
	/\b([\w.-]*(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)[\w.-]*)["']?\s*[:=]\s*["']([^"'\s]{16,200})["']/gi,
	/<string\s+name="([^"]*(?:api_?key|apikey|secret|token)[^"]*)"[^>]*>([^<\s]{16,200})<\/string>/gi,
	/<key>([^<]*(?:api_?key|apikey|secret|token)[^<]*)<\/key>\s*<string>([^<\s]{16,200})<\/string>/gi,
	/^[ \t]*([\w.-]*(?:api[_-]?key|apikey|secret|token)[\w.-]*)[ \t]*=[ \t]*(\S{16,200})[ \t]*$/gim,
];

const PLACEHOLDER =
	/your|example|sample|dummy|changeme|placeholder|xxxx|\*\*\*|<|\$\{|\$\(|%s|process\.env|BuildConfig|getString|todo/i;

const IGNORED_HOSTS =
	/^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.0\.2\.2|(?:[\w-]+\.)*(?:example\.(?:com|org|net)|w3\.org|android\.com|apple\.com|adobe\.com|xml\.org|xmlpull\.org|purl\.org|json-schema\.org|apache\.org|sun\.com|openxmlformats\.org|microsoft\.com|schemas\.xmlsoap\.org)|[\w-]+\.(?:local|test|example|invalid))$/i;

/** Shannon entropy in bits per character. */
export const entropy = (s: string): number => {
	const counts = new Map<string, number>();
	for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
	let h = 0;
	for (const n of counts.values()) {
		const p = n / s.length;
		h -= p * Math.log2(p);
	}
	return h;
};

const FIREBASE_CONFIG_RE =
	/(^|[/!])(google-services\.json|GoogleService-Info\.plist)$/;

export interface ScanOptions {
	/** Binary blob (dex, arsc, Mach-O): only high-signal token patterns, no lines. */
	readonly binary?: boolean;
}

/** Scans one file's content for hardcoded secrets. Exported for tests. */
export const scanForSecrets = (
	text: string,
	file: string,
	options: ScanOptions = {},
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	const where = (index: number) =>
		options.binary ? { file } : { file, line: lineOf(text, index) };
	const push = (
		key: string,
		f: Omit<FindingInput, "category" | "location"> & {
			readonly index: number;
			readonly category?: Category;
		},
	) => {
		if (seen.has(key)) return;
		seen.add(key);
		const { index, category, ...rest } = f;
		findings.push({
			...rest,
			category: category ?? "security",
			location: where(index),
		});
	};

	for (const rule of RULES) {
		for (const m of text.matchAll(rule.re)) {
			const secret = m[1] ?? m[0];
			push(secret, {
				ruleId: `mobile.secrets/${rule.id}`,
				title: rule.title,
				severity: rule.severity,
				message: `The app ships ${rule.what}. Anyone can unpack the app and extract it.`,
				remediation: rule.remediation,
				evidence: rule.id === "private-key" ? m[0] : redact(secret),
				references: [MASVS_STORAGE, CWE_798],
				tags: ["masvs-storage-1", "cwe-798", "secret"],
				confidence: "high",
				index: m.index ?? 0,
			});
		}
	}

	const firebaseConfig = FIREBASE_CONFIG_RE.test(file);
	for (const m of text.matchAll(GOOGLE_KEY_RE)) {
		const key = m[1] ?? m[0];
		push(key, {
			ruleId: "mobile.secrets/google-api-key",
			title: "Google API key in app",
			severity: firebaseConfig ? "info" : "low",
			message:
				"A Google API key is embedded in the app. Such keys are extractable, so they are only safe when restricted.",
			remediation:
				"In Google Cloud Console restrict the key to your Android package/SHA-1 or iOS bundle id and to only the APIs the app needs.",
			evidence: redact(key, 8),
			references: [
				"https://cloud.google.com/docs/authentication/api-keys#securing",
				MASVS_STORAGE,
			],
			tags: ["masvs-storage-1", "cwe-798", "secret"],
			confidence: "high",
			index: m.index ?? 0,
		});
	}

	for (const m of text.matchAll(FIREBASE_DB_RE)) {
		const url = m[1] ?? m[0];
		push(url, {
			ruleId: "mobile.secrets/firebase-database-url",
			title: "Firebase Realtime Database URL",
			severity: "info",
			message: `The app talks to the Firebase Realtime Database ${url}. Misconfigured security rules commonly expose the whole database to anyone with this URL.`,
			remediation:
				"Verify the database rules deny unauthenticated reads/writes (try `curl <url>/.json`) and scope access per user.",
			evidence: url,
			references: [
				"https://firebase.google.com/docs/database/security",
				"https://mas.owasp.org/MASVS/08-MASVS-NETWORK/",
			],
			tags: ["firebase", "cwe-284"],
			confidence: "high",
			index: m.index ?? 0,
		});
	}

	if (options.binary) return findings;

	for (const re of GENERIC_RES) {
		for (const m of text.matchAll(re)) {
			const name = m[1] ?? "";
			const value = (m[2] ?? "").replace(/^["']|["']$/g, "");
			if (
				value.length < 16 ||
				seen.has(value) ||
				PLACEHOLDER.test(value) ||
				/^AIza|^https?:/.test(value) ||
				entropy(value) < 3.5
			)
				continue;
			push(value, {
				ruleId: "mobile.secrets/generic-secret",
				title: "Possible hardcoded secret",
				severity: "medium",
				message: `"${name}" is assigned a high-entropy literal that looks like a credential. Values shipped in the app are readable by anyone.`,
				remediation:
					"Move the secret to your backend (or fetch short-lived tokens at runtime) and rotate it if it is real.",
				evidence: `${name} = ${redact(value)}`,
				references: [MASVS_STORAGE, CWE_798],
				tags: ["masvs-storage-1", "cwe-798", "secret"],
				confidence: "low",
				index: m.index ?? 0,
			});
		}
	}

	let httpCount = 0;
	for (const m of text.matchAll(HTTP_RE)) {
		const host = (m[1] ?? "").toLowerCase().replace(/\.$/, "");
		if (
			!host.includes(".") ||
			IGNORED_HOSTS.test(host) ||
			/^(192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(host) ||
			seen.has(`http:${host}`)
		)
			continue;
		if (++httpCount > 10) break;
		push(`http:${host}`, {
			ruleId: "mobile.secrets/cleartext-endpoint",
			title: "Cleartext HTTP endpoint",
			severity: "low",
			category: "security",
			message: `The app references http://${host}. Traffic to it can be read and modified by anyone on the network path.`,
			remediation: "Use https:// for every endpoint the app contacts.",
			evidence: m[0].slice(0, 120),
			references: [
				"https://mas.owasp.org/MASVS/08-MASVS-NETWORK/",
				"https://cwe.mitre.org/data/definitions/319.html",
			],
			tags: ["masvs-network-1", "cwe-319"],
			confidence: "medium",
			index: m.index ?? 0,
		});
	}

	return findings;
};

/* --------------------------------- targets --------------------------------- */

const MEDIA_RE =
	/\.(png|jpe?g|gif|webp|svg|ico|ttf|otf|woff2?|mp3|mp4|m4a|aac|wav|ogg|mov|pdf|car|nib|storyboardc|riv|so\.dbg)$/i;

/** APK/AAB entries worth scanning; `binary` entries get the token-only scan. */
const androidEntry = (name: string): "text" | "binary" | undefined => {
	const n = name.replace(/^base\//, "");
	if (/^(dex\/)?classes\d*\.dex$/.test(n)) return "binary";
	if (/^resources\.(arsc|pb)$/.test(n)) return "binary";
	if (/^lib\/[^/]+\/libapp\.so$/.test(n)) return "binary";
	if (MEDIA_RE.test(n)) return undefined;
	if (/^(assets|res\/raw|root)\//.test(n)) return "text";
	if (/^[^/]+\.(json|properties)$/.test(n)) return "text";
	return undefined;
};

const IOS_TEXT_RE =
	/\.(plist|json|js|jsbundle|xml|txt|strings|env|cfg|conf|ya?ml)$/i;

const iosEntry = (name: string): "text" | "binary" | undefined => {
	const app = /^Payload\/([^/]+)\.app\/(.+)$/.exec(name);
	if (!app) return undefined;
	const [, bundle, rest = ""] = app;
	if (rest === bundle) return "binary"; // main Mach-O executable
	if (rest === "Frameworks/App.framework/App") return "binary"; // Flutter AOT snapshot
	if (MEDIA_RE.test(rest)) return undefined;
	if (/(^|\/)flutter_assets\//.test(rest)) return "text";
	if (IOS_TEXT_RE.test(rest)) return "text";
	return undefined;
};

/** Mobile config files scanned in source trees; general code is left to code.* auditors. */
const SOURCE_RE =
	/(^|\/)(google-services\.json|GoogleService-Info\.plist|Info\.plist|AndroidManifest\.xml|app\.json|app\.config\.[cm]?[jt]s|eas\.json|pubspec\.yaml|gradle\.properties|local\.properties|[^/]+\.xcconfig)$|(^|\/)res\/values[^/]*\/[^/]+\.xml$/;

const decode = (bytes: Uint8Array, kind: "text" | "binary") =>
	new TextDecoder(kind === "binary" ? "latin1" : "utf-8").decode(bytes);

/** Hardcoded credentials and insecure endpoints in mobile apps and their config. */
export const mobileSecrets = defineAuditor({
	id: "mobile.secrets",
	title: "Mobile app secrets",
	description:
		"Scans APK/AAB/IPA contents (dex, JS bundles, assets, plists, resources) and mobile config files for hardcoded API keys, tokens and private keys, Firebase database URLs and cleartext HTTP endpoints.",
	categories: ["security"],
	targets: ["mobile"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const target = yield* loadMobileTarget(ctx);
			const findings: FindingInput[] = [];

			if (target.kind === "artifact") {
				const classify = target.type === "ipa" ? iosEntry : androidEntry;
				const entries = target.extract(
					(name, info) =>
						info.originalSize <= MAX_ENTRY_BYTES &&
						classify(name) !== undefined,
				);
				for (const [name, bytes] of Object.entries(entries)) {
					const kind = classify(name);
					if (!kind) continue;
					findings.push(
						...scanForSecrets(decode(bytes, kind), `${target.file}!${name}`, {
							binary: kind === "binary",
						}),
					);
				}
				return findings;
			}

			const files = target.files.filter((f) => SOURCE_RE.test(f));
			if (files.length === 0)
				return yield* skip("No mobile configuration files found");
			for (const file of files) {
				const text = yield* target.ws
					.readText(file)
					.pipe(Effect.orElseSucceed(() => undefined));
				if (text !== undefined) findings.push(...scanForSecrets(text, file));
			}
			return findings;
		}),
});
