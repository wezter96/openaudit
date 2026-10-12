import {
	defineAuditor,
	type FindingInput,
	redact,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	baseName,
	cweUrl,
	fullLineAt,
	isFixturePath,
	isLockfile,
	isTestPath,
	lineLocator,
	owaspUrl,
	readTextFiles,
	type SourceFile,
	scrubLine,
	shannonEntropy,
	truncate,
} from "./util";

interface SecretRule {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	/** Global regex; capture group `secret` (or the whole match) is the secret. */
	readonly pattern: RegExp;
	readonly remediation: string;
	readonly confidence?: "high" | "medium" | "low";
	/** Minimum Shannon entropy of the secret, to drop low-entropy lookalikes. */
	readonly minEntropy?: number;
}

const ROTATE =
	"Revoke and rotate the credential now, then purge it from history (git filter-repo / BFG) and load it from a secret manager or environment variable.";

/** Provider-specific patterns. Ordered: more specific first. */
export const SECRET_RULES: ReadonlyArray<SecretRule> = [
	{
		id: "private-key",
		title: "Private key committed",
		severity: "critical",
		pattern:
			/-----BEGIN (?<secret>(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?)-----(?=(?:\\[nr]|\s)+(?:[\w-]+: [^\n]*(?:\\n|\n))*(?:\\n|\s)*[A-Za-z0-9+/=]{40,})/g,
		remediation: `${ROTATE} Store keys outside the repository.`,
	},
	{
		id: "aws-access-key-id",
		title: "AWS access key ID",
		severity: "critical",
		pattern: /\b(?<secret>(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/g,
		remediation: `${ROTATE} Prefer IAM roles or short-lived credentials over static keys.`,
	},
	{
		id: "aws-secret-access-key",
		title: "AWS secret access key",
		severity: "critical",
		pattern:
			/aws_?(?:secret|sec)_?(?:access)?_?key["']?\s*[:=]\s*["']?(?<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
		remediation: ROTATE,
		minEntropy: 3.5,
	},
	{
		id: "github-token",
		title: "GitHub token",
		severity: "critical",
		pattern:
			/\b(?<secret>gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,
		remediation: ROTATE,
	},
	{
		id: "gitlab-token",
		title: "GitLab token",
		severity: "critical",
		pattern: /\b(?<secret>gl(?:pat|dt|rt|ptt|cbt)-[A-Za-z0-9_-]{20,})\b/g,
		remediation: ROTATE,
	},
	{
		id: "slack-token",
		title: "Slack token",
		severity: "high",
		pattern: /\b(?<secret>xox[abposr]-[A-Za-z0-9-]{10,})\b/g,
		remediation: ROTATE,
	},
	{
		id: "slack-webhook",
		title: "Slack incoming webhook URL",
		severity: "high",
		pattern:
			/(?<secret>https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+)/g,
		remediation: `Regenerate the webhook in Slack and load the URL from configuration. ${ROTATE}`,
	},
	{
		id: "stripe-live-key",
		title: "Stripe live secret key",
		severity: "critical",
		pattern: /\b(?<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g,
		remediation: `Roll the key in the Stripe dashboard. ${ROTATE}`,
	},
	{
		id: "anthropic-api-key",
		title: "Anthropic API key",
		severity: "critical",
		pattern: /\b(?<secret>sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})/g,
		remediation: ROTATE,
	},
	{
		id: "openai-api-key",
		title: "OpenAI API key",
		severity: "critical",
		pattern:
			/\b(?<secret>sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})/g,
		remediation: ROTATE,
	},
	{
		id: "google-api-key",
		title: "Google API key",
		severity: "high",
		pattern: /\b(?<secret>AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g,
		remediation: `Restrict the key (HTTP referrer / API restrictions) or rotate it if it grants access to paid or private APIs. ${ROTATE}`,
		confidence: "medium",
	},
	{
		id: "twilio-api-key",
		title: "Twilio API key",
		severity: "high",
		pattern: /\b(?<secret>SK[0-9a-f]{32})\b/g,
		remediation: ROTATE,
		confidence: "medium",
		minEntropy: 3,
	},
	{
		id: "sendgrid-api-key",
		title: "SendGrid API key",
		severity: "critical",
		pattern:
			/\b(?<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/g,
		remediation: ROTATE,
	},
	{
		id: "npm-token",
		title: "npm access token",
		severity: "critical",
		pattern:
			/\b(?<secret>npm_[A-Za-z0-9]{36})\b|_authToken\s*=\s*(?<auth>[A-Za-z0-9_-]{20,})/g,
		remediation: `${ROTATE} Use \`\${NPM_TOKEN}\` in .npmrc instead of a literal token.`,
	},
	{
		id: "jwt",
		title: "JSON Web Token committed",
		severity: "medium",
		pattern:
			/\b(?<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g,
		remediation:
			"Remove the token. If it is long-lived or grants access, revoke it (rotate the signing key if needed).",
		confidence: "medium",
	},
	{
		id: "database-url-password",
		title: "Database connection string with password",
		severity: "high",
		pattern:
			/\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|cockroachdb):\/\/[^:/\s"'`@]+:(?<secret>[^@\s"'`/]{3,})@[^\s"'`]+/g,
		remediation: `Load the connection string from an environment variable or secret manager. ${ROTATE}`,
	},
];

const SECRET_KEY_NAME =
	/(?:password|passwd|passphrase|pwd|secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|signing[_-]?key|encryption[_-]?key|bearer)/i;

/** `key = "value"` style assignments in code and config. */
const GENERIC_ASSIGNMENT =
	/(?<key>[A-Za-z_][\w.-]{0,60})["']?\s*(?::=|=>|==?|:)\s*(?<q>["'`])(?<secret>[^"'`\s]{8,200})\k<q>/g;

const PLACEHOLDER =
	/^(?:x+|\*+|\.+|-+|0+|1234.*|abc.*|changeme|change[_-]?me.*|replace[_-]?me.*|your[_-].*|my[_-].*|<.*>|\$\{.*\}|\{\{.*\}\}|%\(?.*|\$[A-Z_]+|example.*|test.*|dummy.*|fake.*|sample.*|placeholder.*|password.*|secret.*|null|none|undefined|todo|redacted.*|insert.*|enter.*|process\.env.*|env\(.*|os\.environ.*)$/i;

/** True for obviously fake values used in docs and examples. */
export const isPlaceholder = (value: string): boolean =>
	PLACEHOLDER.test(value) ||
	/example|xxxx|your[_-]|\.\.\.|\$\{|\{\{|fake|dummy|sample|placeholder|redacted|secret|changeme|abcdefgh|01234567|12345678/i.test(
		value,
	);

/** `.env`, `.env.production`, `prod.env`… but not `.env.example` & co. */
const ENV_FILE = /(^|\/)(\.env(\.[\w.-]+)?|[\w-]+\.env)$/;
const ENV_TEMPLATE = /(example|sample|template|dist|defaults?|schema|tpl)/i;

/** Lines with these markers are intentionally ignored. */
const ALLOW_MARKER =
	/openaudit-ignore|gitleaks:allow|pragma: allowlist secret|nosec|NOSONAR/;

const REFERENCES = [
	cweUrl(798),
	owaspUrl("a07"),
	"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
];
const TAGS = ["cwe-798", "owasp-a07", "secrets"];

/** Max chars of context shown before the secret. */
const EVIDENCE_PREFIX = 40;

/**
 * Evidence is a short scrubbed prefix plus the redacted secret: never the
 * rest of the line, which may hold further credentials.
 */
export const secretEvidence = (
	text: string,
	index: number,
	secret: string,
): string => {
	const lineStart = text.lastIndexOf("\n", index - 1) + 1;
	// Scrub the whole prefix before cutting so no partial secret survives.
	const prefix = scrubLine(text.slice(lineStart, index)).trimStart();
	const clipped =
		prefix.length > EVIDENCE_PREFIX
			? `…${prefix.slice(-EVIDENCE_PREFIX)}`
			: prefix;
	return truncate(`${clipped}${redact(secret)}`);
};

/** Scans one file. Exported for unit tests. */
export const scanSecrets = (file: SourceFile): FindingInput[] => {
	const { path, text } = file;
	const findings: FindingInput[] = [];
	const lineOf = lineLocator(text);
	const flaggedLines = new Set<number>();
	const inTests = isTestPath(path);
	const push = (
		rule: Pick<SecretRule, "id" | "title" | "severity" | "remediation">,
		index: number,
		evidence: string,
		message: string,
		confidence: "high" | "medium" | "low" = "high",
	) => {
		const lineText = fullLineAt(text, index);
		if (ALLOW_MARKER.test(lineText)) return;
		const line = lineOf(index);
		flaggedLines.add(line);
		findings.push({
			ruleId: `code.secrets/${rule.id}`,
			title: rule.title,
			severity: rule.severity,
			category: "security",
			message,
			location: { file: path, line },
			evidence,
			remediation: rule.remediation,
			references: REFERENCES,
			confidence: inTests ? "low" : confidence,
			tags: TAGS,
		});
	};

	for (const rule of SECRET_RULES) {
		for (const m of text.matchAll(rule.pattern)) {
			const secret = m.groups?.secret ?? m.groups?.auth ?? m[0];
			if (rule.id !== "private-key" && isPlaceholder(secret)) continue;
			if (rule.minEntropy && shannonEntropy(secret) < rule.minEntropy) continue;
			if (rule.id === "database-url-password" && /^\$|^:|^%/.test(secret))
				continue;
			const index = (m.index ?? 0) + Math.max(0, m[0].indexOf(secret));
			if (flaggedLines.has(lineOf(index))) continue;
			push(
				rule,
				index,
				// Only the PEM header, never key material.
				rule.id === "private-key"
					? `-----BEGIN ${secret}-----****`
					: secretEvidence(text, index, secret),
				`${rule.title} found in ${path}. Anyone with read access to the repository (or its history) can use it.`,
				rule.confidence,
			);
		}
	}

	const isEnv = ENV_FILE.test(path) && !ENV_TEMPLATE.test(baseName(path));
	if (isEnv) scanEnvAssignments(text, lineOf, flaggedLines, push);

	for (const m of text.matchAll(GENERIC_ASSIGNMENT)) {
		const key = m.groups?.key ?? "";
		const secret = m.groups?.secret ?? "";
		if (
			!SECRET_KEY_NAME.test(key) ||
			/(?:_|-|^)(?:url|path|file|name|id|type|field|label|header|length|min|max|policy|regex|pattern|hash)$/i.test(
				key,
			)
		)
			continue;
		if (isPlaceholder(secret) || shannonEntropy(secret) < 3.5) continue;
		// Identifiers, URLs without credentials, and i18n keys are not secrets.
		if (
			/^[a-z]+(?:[._-][a-z]+)+$|^https?:\/\/|^[A-Z_]+$|^[a-z]+[A-Z][A-Za-z]+$/.test(
				secret,
			)
		)
			continue;
		const index = (m.index ?? 0) + m[0].lastIndexOf(secret);
		if (flaggedLines.has(lineOf(index))) continue;
		push(
			{
				id: "generic-secret",
				title: "Hardcoded secret",
				severity: "high",
				remediation: ROTATE,
			},
			index,
			secretEvidence(text, index, secret),
			`\`${key}\` is assigned a high-entropy literal that looks like a credential.`,
			"medium",
		);
	}

	return findings;
};

const scanEnvAssignments = (
	text: string,
	lineOf: (index: number) => number,
	flaggedLines: Set<number>,
	push: (
		rule: Pick<SecretRule, "id" | "title" | "severity" | "remediation">,
		index: number,
		evidence: string,
		message: string,
		confidence?: "high" | "medium" | "low",
	) => void,
) => {
	const re =
		/^[ \t]*(?:export[ \t]+)?(?<key>[A-Za-z_][\w.]*)[ \t]*=[ \t]*["']?(?<secret>[^"'\s#]{8,})/gm;
	for (const m of text.matchAll(re)) {
		const key = m.groups?.key ?? "";
		const secret = m.groups?.secret ?? "";
		if (!SECRET_KEY_NAME.test(key)) continue;
		if (isPlaceholder(secret) || shannonEntropy(secret) < 3) continue;
		const index = (m.index ?? 0) + m[0].lastIndexOf(secret);
		if (flaggedLines.has(lineOf(index))) continue;
		push(
			{
				id: "generic-secret",
				title: "Hardcoded secret",
				severity: "high",
				remediation: ROTATE,
			},
			index,
			secretEvidence(text, index, secret),
			`\`${key}\` in a committed environment file holds what looks like a real credential.`,
			"medium",
		);
	}
};

/** Committed `.env` files that contain at least one real assignment. */
const envFileFinding = (file: SourceFile): FindingInput | undefined => {
	if (!ENV_FILE.test(file.path) || ENV_TEMPLATE.test(baseName(file.path)))
		return undefined;
	const assignment = /^[ \t]*(?:export[ \t]+)?[A-Za-z_][\w.]*[ \t]*=[ \t]*\S/m;
	if (!assignment.test(file.text)) return undefined;
	return {
		ruleId: "code.secrets/env-file-committed",
		title: "Environment file committed",
		severity: "medium",
		category: "security",
		message: `${file.path} is tracked in the repository. Environment files usually hold credentials and per-environment configuration.`,
		location: { file: file.path, line: 1 },
		remediation:
			"Remove the file from version control, add it to .gitignore, rotate any credentials it contained, and commit a `.env.example` with placeholder values instead.",
		references: [cweUrl(538), "https://12factor.net/config"],
		confidence: "high",
		tags: ["cwe-538", "owasp-a05", "secrets"],
	};
};

const shouldScan = (path: string): boolean =>
	!isLockfile(path) &&
	!isFixturePath(path) &&
	!/\.(svg|map|snap|lock|sum|min\.js|min\.css)$/i.test(path) &&
	!/(^|\/)(CHANGELOG|LICENSE|NOTICE)(\.\w+)?$/i.test(path);

export const secrets = defineAuditor({
	id: "code.secrets",
	title: "Secrets in source",
	description:
		"Detects committed credentials (cloud keys, tokens, private keys, connection strings, high-entropy passwords) and tracked .env files.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, shouldScan);
			const findings: FindingInput[] = [];
			for (const file of files) {
				const env = envFileFinding(file);
				if (env) findings.push(env);
				findings.push(...scanSecrets(file));
			}
			return findings;
		}),
});
