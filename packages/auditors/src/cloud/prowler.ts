import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
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

const list = (v: unknown): unknown[] =>
	typeof v === "string" ? [v] : Array.isArray(v) ? v : [];

/** Validates settings against the allowlist patterns; throws on a bad value. */
export const readProwlerSettings = (
	raw: Record<string, unknown> | undefined,
): ProwlerSettings => {
	const one = (key: string, re: RegExp): string | undefined => {
		const v = raw?.[key];
		if (v === undefined || v === null) return undefined;
		if (typeof v !== "string" || !re.test(v))
			throw new Error(`settings["${ID}"].${key} has an invalid value`);
		return v;
	};
	const many = (key: string, re: RegExp): string[] => {
		const items = list(raw?.[key]);
		if (items.length > 50)
			throw new Error(`settings["${ID}"].${key} has too many entries (max 50)`);
		return items.map((v) => {
			if (typeof v !== "string" || !re.test(v))
				throw new Error(`settings["${ID}"].${key} has an invalid entry`);
			return v;
		});
	};
	const auth = raw?.azureAuth ?? "cli";
	if (typeof auth !== "string" || !Object.hasOwn(AZURE_AUTH, auth))
		throw new Error(
			`settings["${ID}"].azureAuth must be one of ${Object.keys(AZURE_AUTH).join(", ")}`,
		);
	return {
		profile: one("profile", PROFILE),
		regions: many("regions", REGION),
		checks: many("checks", CHECK),
		services: many("services", SERVICE),
		compliance: one("compliance", COMPLIANCE),
		azureAuth: auth as keyof typeof AZURE_AUTH,
		projectIds: many("projectIds", GCP_PROJECT),
		context: one("context", KUBE_CONTEXT),
	};
};

/**
 * Prowler CLI arguments (after the binary). Credentials are never passed:
 * Prowler reads them from the ambient environment (AWS_*, AZURE_*,
 * GOOGLE_APPLICATION_CREDENTIALS, KUBECONFIG, ...).
 */
export const prowlerArgs = (
	provider: Provider,
	s: ProwlerSettings,
	outDir: string,
): string[] => {
	const args: string[] = [
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
	];
	if (provider === "aws") {
		if (s.profile) args.push("--profile", s.profile);
		if (s.regions.length > 0) args.push("--filter-region", ...s.regions);
	}
	if (provider === "azure") args.push(AZURE_AUTH[s.azureAuth]);
	if (provider === "gcp" && s.projectIds.length > 0)
		args.push("--project-ids", ...s.projectIds);
	if (provider === "kubernetes" && s.context) args.push("--context", s.context);
	if (s.checks.length > 0) args.push("--checks", ...s.checks);
	if (s.services.length > 0) args.push("--services", ...s.services);
	if (s.compliance) args.push("--compliance", s.compliance);
	return args;
};

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
	const findings: FindingInput[] = [];
	for (const item of arr(json)) {
		if (!isRecord(item)) continue;
		if (str(item.status_code)?.toUpperCase() !== "FAIL") continue;
		if (str(item.status)?.toLowerCase() === "suppressed") continue;
		const meta = isRecord(item.metadata) ? item.metadata : {};
		const info = isRecord(item.finding_info) ? item.finding_info : {};
		const check = str(meta.event_code) ?? str(info.uid)?.split("-")[2];
		const title = str(info.title);
		if (!check || !title) continue;
		const resource = isRecord(arr(item.resources)[0])
			? (arr(item.resources)[0] as Record<string, unknown>)
			: {};
		const cloud = isRecord(item.cloud) ? item.cloud : {};
		const provider = str(cloud.provider);
		const region = str(resource.region) ?? str(cloud.region);
		const remediation = isRecord(item.remediation) ? item.remediation : {};
		const unmapped = isRecord(item.unmapped) ? item.unmapped : {};
		const compliance = isRecord(unmapped.compliance)
			? Object.keys(unmapped.compliance)
			: [];
		const status = str(item.status_detail) ?? str(item.message);
		const risk = str(item.risk_details) ?? str(info.desc);
		const refs = [
			...arr(remediation.references).filter(
				(r): r is string => typeof r === "string" && /^https?:\/\//.test(r),
			),
			...[str(unmapped.related_url)].filter((r): r is string => !!r),
		];
		const uid = str(resource.uid) ?? str(resource.name);
		findings.push({
			ruleId: `${ID}/${kebab(check)}`,
			title: truncate(title, 200),
			severity: severityOf(item),
			category: options.compliance ? "compliance" : "security",
			message: truncate(
				[risk, region ? `Region: ${region}.` : ""].filter(Boolean).join(" ") ||
					title,
				400,
			),
			location: { url: uid, selector: str(resource.type) },
			evidence: status ? truncate(scrubLine(status), 240) : undefined,
			remediation:
				truncate(str(remediation.desc) ?? "", 500) ||
				"See the Prowler check documentation.",
			references: [...new Set(refs)].slice(0, 6),
			confidence: "high",
			tags: [
				"prowler",
				...(provider ? [provider.toLowerCase()] : []),
				...compliance.map(complianceTag).filter(Boolean),
			].slice(0, MAX_TAGS),
		});
		if (findings.length >= MAX_FINDINGS) break;
	}
	return findings;
};

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

const providerOf = (ctx: AuditContext): Provider | undefined =>
	PROVIDERS.find((p) => p === ctx.target.cloud);

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
			const settings = yield* Effect.try({
				try: () => readProwlerSettings(ctx.options.settings?.[ID]),
				catch: (cause) =>
					new AuditorError({
						message: cause instanceof Error ? cause.message : String(cause),
					}),
			});
			const dir = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-prowler-")),
			);
			return yield* Effect.gen(function* () {
				const res = yield* ctx.exec.run(
					[bin, ...prowlerArgs(provider, settings, dir)],
					{ cwd: dir, timeoutMs: 60 * 60_000 },
				);
				const files = yield* Effect.promise(() =>
					readdir(dir).catch(() => [] as string[]),
				);
				const file =
					files.find((f) => f.endsWith(".ocsf.json")) ??
					files.find((f) => f.endsWith(".json"));
				// Prowler exits 3 when it found failures; anything else with no report is an error.
				if (!file || (res.code !== 0 && res.code !== 3))
					return yield* Effect.fail(
						new AuditorError({
							message: `prowler exited with code ${res.code}${file ? "" : " and wrote no report"}: ${truncate(scrubLine((res.stderr || res.stdout).trim()), 300)}`,
						}),
					);
				const body = yield* Effect.promise(() =>
					readFile(join(dir, file), "utf8"),
				);
				const json = yield* Effect.try({
					try: () => parseOcsf(body),
					catch: (cause) =>
						new AuditorError({
							message: "prowler produced an invalid JSON-OCSF report",
							cause,
						}),
				});
				return parseProwlerReport(json, {
					compliance: settings.compliance !== undefined,
				});
			}).pipe(
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
