import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	type Category,
	defineAuditor,
	type ExecResult,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord, kebab, scrubLine, truncate } from "../codebase/util";
import { arr, num, str } from "../tool";

const ID = "cloud.prowler";
const MAX_FINDINGS = 1000;
const MAX_TAGS = 20;
const PROVIDERS = ["aws", "azure", "gcp", "kubernetes"] as const;
type Provider = (typeof PROVIDERS)[number];

/* -------------------------------------------------------------------------- */
/*                                  Settings                                  */
/* -------------------------------------------------------------------------- */

/*
 * Every value below ends up as a CLI argument, so each must match a strict
 * pattern that cannot start with `-` (no option injection) or contain
 * whitespace/shell syntax. Nothing is run through a shell regardless.
 */
const PROFILE = /^[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,127}$/;
const REGION = /^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$/;
const CHECK = /^[a-z0-9][a-z0-9_]{0,127}$/;
const SERVICE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const COMPLIANCE = /^[a-z0-9][a-z0-9_.]{0,63}$/;
const GCP_PROJECT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const KUBE_CONTEXT = /^[A-Za-z0-9][A-Za-z0-9_.@:/-]{0,127}$/;
const AZURE_AUTH = {
	cli: "--az-cli-auth",
	"sp-env": "--sp-env-auth",
	"managed-identity": "--managed-identity-auth",
} as const;

export interface ProwlerSettings {
	readonly profile?: string;
	readonly regions: ReadonlyArray<string>;
	readonly checks: ReadonlyArray<string>;
	readonly services: ReadonlyArray<string>;
	readonly compliance?: string;
	readonly azureAuth: keyof typeof AZURE_AUTH;
	readonly projectIds: ReadonlyArray<string>;
	readonly context?: string;
}

type RawSettings = Record<string, unknown> | undefined;
type SettingKey = keyof ProwlerSettings;
type AzureAuth = keyof typeof AZURE_AUTH;
type DirPath = string;
type CliFlag = `--${string}`;

const list = (v: unknown): unknown[] =>
	typeof v === "string" ? [v] : Array.isArray(v) ? v : [];

const matches = (v: unknown, re: RegExp): v is string =>
	typeof v === "string" && re.test(v);

/** One optional setting; throws when it is set but does not match `re`. */
const one = (
	raw: RawSettings,
	key: SettingKey,
	re: RegExp,
): string | undefined => {
	const v = raw?.[key];
	if (v === undefined || v === null) return undefined;
	if (!matches(v, re))
		throw new Error(`settings["${ID}"].${key} has an invalid value`);
	return v;
};

/** A string or list setting (at most 50 entries); every entry must match `re`. */
const many = (raw: RawSettings, key: SettingKey, re: RegExp): string[] => {
	const items = list(raw?.[key]);
	if (items.length > 50)
		throw new Error(`settings["${ID}"].${key} has too many entries (max 50)`);
	return items.map((v) => {
		if (!matches(v, re))
			throw new Error(`settings["${ID}"].${key} has an invalid entry`);
		return v;
	});
};

const azureAuthOf = (raw: RawSettings): AzureAuth => {
	const auth = raw?.azureAuth ?? "cli";
	if (typeof auth !== "string" || !Object.hasOwn(AZURE_AUTH, auth))
		throw new Error(
			`settings["${ID}"].azureAuth must be one of ${Object.keys(AZURE_AUTH).join(", ")}`,
		);
	return auth as AzureAuth;
};

/** Validates settings against the allowlist patterns; throws on a bad value. */
export const readProwlerSettings = (raw: RawSettings): ProwlerSettings => {
	const azureAuth = azureAuthOf(raw);
	return {
		profile: one(raw, "profile", PROFILE),
		regions: many(raw, "regions", REGION),
		checks: many(raw, "checks", CHECK),
		services: many(raw, "services", SERVICE),
		compliance: one(raw, "compliance", COMPLIANCE),
		azureAuth,
		projectIds: many(raw, "projectIds", GCP_PROJECT),
		context: one(raw, "context", KUBE_CONTEXT),
	};
};

/** `flag value` when the value is set. */
const flagValue = (flag: CliFlag, value: string | undefined): string[] =>
	value ? [flag, value] : [];

/** `flag v1 v2 ...` when there are values. */
const flagValues = (flag: CliFlag, values: ReadonlyArray<string>): string[] =>
	values.length > 0 ? [flag, ...values] : [];

const PROVIDER_ARGS: Record<Provider, (s: ProwlerSettings) => string[]> = {
	aws: (s) => [
		...flagValue("--profile", s.profile),
		...flagValues("--filter-region", s.regions),
	],
	azure: (s) => [AZURE_AUTH[s.azureAuth]],
	gcp: (s) => flagValues("--project-ids", s.projectIds),
	kubernetes: (s) => flagValue("--context", s.context),
};

/**
 * Prowler CLI arguments (after the binary). Credentials are never passed:
 * Prowler reads them from the ambient environment (AWS_*, AZURE_*,
 * GOOGLE_APPLICATION_CREDENTIALS, KUBECONFIG, ...).
 */
export const prowlerArgs = (
	provider: Provider,
	s: ProwlerSettings,
	outDir: DirPath,
): string[] => [
	provider,
	"--output-formats",
	"json-ocsf",
	"--output-directory",
	outDir,
	"--output-filename",
	"openaudit",
	"--no-banner",
	"--status",
	"FAIL",
	"--log-level",
	"ERROR",
	...PROVIDER_ARGS[provider](s),
	...flagValues("--checks", s.checks),
	...flagValues("--services", s.services),
	...flagValue("--compliance", s.compliance),
];

/* -------------------------------------------------------------------------- */
/*                                   Parsing                                  */
/* -------------------------------------------------------------------------- */

const SEVERITY: Record<string, Severity> = {
	critical: "critical",
	fatal: "critical",
	high: "high",
	medium: "medium",
	low: "low",
	informational: "info",
	unknown: "info",
};
// OCSF severity_id: 0 unknown, 1 informational, 2 low, 3 medium, 4 high, 5 critical, 6 fatal.
const SEVERITY_ID: ReadonlyArray<Severity> = [
	"info",
	"info",
	"low",
	"medium",
	"high",
	"critical",
	"critical",
];

const severityOf = (f: Record<string, unknown>): Severity => {
	const label = str(f.severity)?.toLowerCase();
	if (label && SEVERITY[label]) return SEVERITY[label];
	const id = num(f.severity_id);
	return (id !== undefined && SEVERITY_ID[id]) || "medium";
};

const complianceTag = (framework: string) =>
	framework
		.toLowerCase()
		.replace(/[^a-z0-9.]+/g, "-")
		.replace(/^-+|-+$/g, "");

type Json = Record<string, unknown>;

const record = (v: unknown): Json => (isRecord(v) ? v : {});

const isHttpUrl = (r: unknown): r is string =>
	typeof r === "string" && /^https?:\/\//.test(r);

/** A FAIL result that is not muted ("Suppressed"). */
const isReportedFailure = (item: Json) =>
	str(item.status_code)?.toUpperCase() === "FAIL" &&
	str(item.status)?.toLowerCase() !== "suppressed";

/** The risk, plus the region when there is one. */
const messageOf = (item: Json, info: Json, resource: Json): string => {
	const risk = str(item.risk_details) ?? str(info.desc);
	const region = str(resource.region) ?? str(record(item.cloud).region);
	return [risk, region ? `Region: ${region}.` : ""].filter(Boolean).join(" ");
};

const referencesOf = (remediation: Json, unmapped: Json): string[] => {
	const refs = [
		...arr(remediation.references).filter(isHttpUrl),
		...[str(unmapped.related_url)].filter((r): r is string => !!r),
	];
	return [...new Set(refs)].slice(0, 6);
};

/** `prowler`, the cloud provider and the compliance frameworks. */
const tagsOf = (item: Json, unmapped: Json): string[] => {
	const provider = str(record(item.cloud).provider);
	const compliance = isRecord(unmapped.compliance)
		? Object.keys(unmapped.compliance)
		: [];
	return [
		"prowler",
		...(provider ? [provider.toLowerCase()] : []),
		...compliance.map(complianceTag).filter(Boolean),
	].slice(0, MAX_TAGS);
};

/** The check id, from the metadata or else the finding uid. */
const checkOf = (meta: Json, info: Json) =>
	str(meta.event_code) ?? str(info.uid)?.split("-")[2];

const prowlerFinding = (
	item: Json,
	category: Category,
): FindingInput | undefined => {
	const meta = record(item.metadata);
	const info = record(item.finding_info);
	const check = checkOf(meta, info);
	const title = str(info.title);
	if (!check || !title) return undefined;
	const resource = record(arr(item.resources)[0]);
	const remediation = record(item.remediation);
	const unmapped = record(item.unmapped);
	const status = str(item.status_detail) ?? str(item.message);
	return {
		ruleId: `${ID}/${kebab(check)}`,
		title: truncate(title, 200),
		severity: severityOf(item),
		category,
		message: truncate(messageOf(item, info, resource) || title, 400),
		location: {
			url: str(resource.uid) ?? str(resource.name),
			selector: str(resource.type),
		},
		evidence: status ? truncate(scrubLine(status), 240) : undefined,
		remediation:
			truncate(str(remediation.desc) ?? "", 500) ||
			"See the Prowler check documentation.",
		references: referencesOf(remediation, unmapped),
		confidence: "high",
		tags: tagsOf(item, unmapped),
	};
};

/**
 * Maps Prowler `json-ocsf` output (an array of OCSF Detection Findings) to
 * findings. Only `status_code: "FAIL"` results are reported; PASS, MANUAL and
 * muted ("Suppressed") ones are dropped.
 *
 * Location: the resource's native id (ARN, Azure resource id, GCP resource
 * name, `namespace/name` for Kubernetes) goes in `location.url`, since cloud
 * resource ids are URI-like and there is no file; the resource type goes in
 * `location.selector` so reporters show `arn:aws:s3:::bucket AwsS3Bucket`.
 */
export const parseProwlerReport = (
	json: unknown,
	options: { readonly compliance?: boolean } = {},
): FindingInput[] => {
	const category = options.compliance ? "compliance" : "security";
	return arr(json)
		.filter(isRecord)
		.filter(isReportedFailure)
		.flatMap((item) => prowlerFinding(item, category) ?? [])
		.slice(0, MAX_FINDINGS);
};

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

const providerOf = (ctx: AuditContext): Provider | undefined =>
	PROVIDERS.find((p) => p === ctx.target.cloud);

/** Exit codes that still mean a finished scan. */
const PROWLER_OK_CODES = new Set([0, 3]);

interface ProwlerScan {
	readonly bin: string;
	readonly provider: Provider;
	readonly settings: ProwlerSettings;
	readonly dir: DirPath;
}

const settingsOf = (ctx: AuditContext) =>
	Effect.try({
		try: () => readProwlerSettings(ctx.options.settings?.[ID]),
		catch: (cause) =>
			new AuditorError({
				message: cause instanceof Error ? cause.message : String(cause),
			}),
	});

/** The report Prowler wrote into `dir`, if any. */
const reportFileIn = (dir: DirPath) =>
	Effect.promise(() => readdir(dir).catch(() => [] as string[])).pipe(
		Effect.map(
			(files) =>
				files.find((f) => f.endsWith(".ocsf.json")) ??
				files.find((f) => f.endsWith(".json")),
		),
	);

const scanFailure = (res: ExecResult, file: string | undefined) =>
	new AuditorError({
		message: `prowler exited with code ${res.code}${file ? "" : " and wrote no report"}: ${truncate(scrubLine((res.stderr || res.stdout).trim()), 300)}`,
	});

const readReport = (path: string) =>
	Effect.promise(() => readFile(path, "utf8")).pipe(
		Effect.flatMap((body) =>
			Effect.try({
				try: () => parseOcsf(body),
				catch: (cause) =>
					new AuditorError({
						message: "prowler produced an invalid JSON-OCSF report",
						cause,
					}),
			}),
		),
	);

const scan = (ctx: AuditContext, s: ProwlerScan) =>
	Effect.gen(function* () {
		const res = yield* ctx.exec.run(
			[s.bin, ...prowlerArgs(s.provider, s.settings, s.dir)],
			{ cwd: s.dir, timeoutMs: 60 * 60_000 },
		);
		const file = yield* reportFileIn(s.dir);
		// Prowler exits 3 when it found failures; anything else with no report is an error.
		if (!file || !PROWLER_OK_CODES.has(res.code))
			return yield* Effect.fail(scanFailure(res, file));
		const json = yield* readReport(join(s.dir, file));
		return parseProwlerReport(json, {
			compliance: s.settings.compliance !== undefined,
		});
	});

export const prowler = defineAuditor({
	id: ID,
	title: "Prowler cloud security posture",
	description:
		'Runs Prowler (v4+) against a live cloud account or cluster (target cloud:aws, cloud:azure, cloud:gcp, cloud:kubernetes) and reports its FAIL checks with compliance-framework tags (cis-…, soc2, …). Credentials come from your ambient environment (AWS_PROFILE/AWS_*, az login, GOOGLE_APPLICATION_CREDENTIALS, KUBECONFIG) and are never read or reported. Only read/list API calls are made, but a full scan can take many minutes and many API calls, so it is opt-in. Optional settings["cloud.prowler"]: profile (aws), regions (aws), checks, services, compliance (e.g. cis_2.0_aws), azureAuth (cli | sp-env | managed-identity), projectIds (gcp), context (kubernetes); each is validated against a strict pattern.',
	categories: ["security", "compliance"],
	targets: ["cloud"],
	engine: "external",
	tool: "prowler",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const provider = providerOf(ctx);
			if (!provider)
				return yield* skip(
					"Target is not a cloud account. Use cloud:aws, cloud:azure, cloud:gcp or cloud:kubernetes.",
				);
			const bin = yield* requireTool(
				ctx,
				"prowler",
				"Install: pipx install prowler (https://docs.prowler.com/projects/prowler-open-source/en/latest/#installation).",
			);
			const settings = yield* settingsOf(ctx);
			const dir = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-prowler-")),
			);
			return yield* scan(ctx, { bin, provider, settings, dir }).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			);
		}),
});

/** A JSON array, or (older releases) one JSON object per line. */
const parseOcsf = (body: string): unknown => {
	const text = body.trim();
	if (!text) return [];
	if (text.startsWith("[")) return JSON.parse(text);
	return text
		.split("\n")
		.filter(Boolean)
		.map((l) => JSON.parse(l));
};
