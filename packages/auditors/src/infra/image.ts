import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type ExecResult,
	type FindingInput,
	redact,
	type Severity,
	type SkipAudit,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	asArray,
	asRecord,
	isPlaceholderValue,
	SECRET_NAME_RE,
} from "./shared";

const CIS_DOCKER = "https://www.cisecurity.org/benchmark/docker";
const STALE_DAYS = 180;
const MB = 1024 * 1024;
const TRIVY_INSTALL = "https://trivy.dev/latest/getting-started/installation/";

/** An image reference such as `nginx:1.27`. */
type ImageName = string;
/** Raw JSON printed by trivy or docker. */
type JsonOutput = string;
/** Milliseconds since the epoch. */
type EpochMillis = number;

/** The parts of an image's config that the auditor inspects. */
export interface ImageConfig {
	readonly user: string | undefined;
	readonly exposedPorts: ReadonlyArray<string>;
	readonly env: ReadonlyArray<string>;
	/** ISO timestamp of image creation. */
	readonly created: string | undefined;
	/** Uncompressed size in bytes. */
	readonly size: number | undefined;
}

const toConfig = (
	config: Record<string, unknown> | undefined,
	created: unknown,
	size: unknown,
): ImageConfig => ({
	user: typeof config?.User === "string" ? config.User : undefined,
	exposedPorts: Object.keys(asRecord(config?.ExposedPorts) ?? {}),
	env: asArray(config?.Env).map(String),
	created: typeof created === "string" ? created : undefined,
	size: typeof size === "number" ? size : undefined,
});

/** Parses `docker image inspect` output (a JSON array). */
export const parseDockerInspect = (
	stdout: JsonOutput,
): ImageConfig | undefined => {
	try {
		const first = asRecord(asArray(JSON.parse(stdout))[0]);
		if (!first) return undefined;
		return toConfig(asRecord(first.Config), first.Created, first.Size);
	} catch {
		return undefined;
	}
};

type ConfigRule = (
	image: ImageName,
	cfg: ImageConfig,
	now: EpochMillis,
) => FindingInput[];

const isRootUser = (user: string) =>
	user === "" || /^(root|0)(:(root|0))?$/.test(user);

const rootUserFindings: ConfigRule = (image, cfg) => {
	const user = (cfg.user ?? "").trim();
	if (!isRootUser(user)) return [];
	return [
		{
			ruleId: "container.image/runs-as-root",
			title: "Image runs as root",
			severity: "medium",
			category: "security",
			message: `\`${image}\` has ${user ? `\`User: ${user}\`` : "no configured user"}, so its processes run as root by default.`,
			remediation:
				"Set a non-root `USER` in the Dockerfile, or run with `--user` / `runAsNonRoot` in your orchestrator.",
			location: { file: image },
			evidence: `User: ${user || "(empty)"}`,
			references: [
				CIS_DOCKER,
				"https://docs.docker.com/reference/dockerfile/#user",
			],
			tags: ["cis-docker-4.1", "cwe-250"],
		},
	];
};

const portFindings: ConfigRule = (image, cfg) => {
	const findings: FindingInput[] = [];
	if (cfg.exposedPorts.some((p) => /^22(\/tcp)?$/.test(p)))
		findings.push({
			ruleId: "container.image/ssh-exposed",
			title: "SSH port exposed",
			severity: "medium",
			category: "security",
			message: `\`${image}\` exposes port 22, suggesting an SSH daemon inside the container.`,
			remediation: "Remove sshd from the image; use `docker exec` for access.",
			location: { file: image },
			evidence: "ExposedPorts: 22/tcp",
			references: [CIS_DOCKER],
			tags: ["cis-docker-5.6"],
		});
	if (cfg.exposedPorts.length > 0)
		findings.push({
			ruleId: "container.image/exposed-ports",
			title: "Exposed ports",
			severity: "info",
			category: "security",
			message: `\`${image}\` exposes ${cfg.exposedPorts.join(", ")}. Confirm each is intended to be reachable.`,
			remediation:
				"Remove `EXPOSE` entries for ports that should stay internal.",
			location: { file: image },
			evidence: cfg.exposedPorts.join(", "),
		});
	return findings;
};

/** Splits a `KEY=value` env entry; a bare `KEY` has an empty value. */
const splitEnv = (entry: string) => {
	const eq = entry.indexOf("=");
	return eq === -1
		? { key: entry, value: "" }
		: { key: entry.slice(0, eq), value: entry.slice(eq + 1) };
};

const isLiteralSecret = ({ key, value }: { key: string; value: string }) =>
	SECRET_NAME_RE.test(key) && !isPlaceholderValue(value);

const envSecretFindings: ConfigRule = (image, cfg) =>
	cfg.env
		.map(splitEnv)
		.filter(isLiteralSecret)
		.map(({ key, value }) => ({
			ruleId: "container.image/secret-in-env",
			title: "Secret baked into image environment",
			severity: "high",
			category: "security",
			message: `\`${key}\` is set in the image config; anyone who can pull \`${image}\` can read it.`,
			remediation:
				"Rebuild without the value, rotate the credential and inject secrets at runtime.",
			location: { file: image },
			evidence: `${key}=${redact(value)}`,
			references: ["https://docs.docker.com/build/building/secrets/"],
			tags: ["cis-docker-4.10", "cwe-798"],
		}));

/** Build time in ms, or undefined when missing, invalid or an epoch stamp. */
const buildTime = (cfg: ImageConfig): EpochMillis | undefined => {
	const created = cfg.created ? Date.parse(cfg.created) : Number.NaN;
	if (!Number.isFinite(created)) return undefined;
	// Reproducible builds (ko, nix, distroless) stamp the epoch; age is meaningless there.
	return new Date(created).getUTCFullYear() > 2000 ? created : undefined;
};

const staleFindings: ConfigRule = (image, cfg, now) => {
	const created = buildTime(cfg);
	if (created === undefined) return [];
	const days = Math.floor((now - created) / 86_400_000);
	return days > STALE_DAYS
		? [
				{
					ruleId: "container.image/stale",
					title: "Image is old",
					severity: "low",
					category: "supply-chain",
					message: `\`${image}\` was built ${days} days ago and likely misses OS and dependency security patches.`,
					remediation:
						"Rebuild regularly (e.g. weekly) on an updated base image and redeploy.",
					location: { file: image },
					evidence: `Created: ${cfg.created}`,
					references: [
						"https://docs.docker.com/build/building/best-practices/#rebuild-your-images-often",
					],
				},
			]
		: [];
};

const isLarge = (size: number | undefined): size is number =>
	size !== undefined && size > 500 * MB;

const sizeFindings: ConfigRule = (image, cfg) => {
	const size = cfg.size;
	if (!isLarge(size)) return [];
	return [
		{
			ruleId: "container.image/large",
			title: "Large image",
			severity: size > 1024 * MB ? "low" : "info",
			category: "performance",
			message: `\`${image}\` is ${Math.round(size / MB)} MB, slowing pulls and cold starts and enlarging the attack surface.`,
			remediation:
				"Use a slim/distroless base, multi-stage builds and remove build tools and caches.",
			location: { file: image },
			evidence: `Size: ${Math.round(size / MB)} MB`,
			references: ["https://docs.docker.com/build/building/multi-stage/"],
		},
	];
};

/** Config checks, in reporting order. */
const CONFIG_RULES: ReadonlyArray<ConfigRule> = [
	rootUserFindings,
	portFindings,
	envSecretFindings,
	staleFindings,
	sizeFindings,
];

/** Findings derived from image configuration (user, ports, env, age, size). */
export const configFindings = (
	image: ImageName,
	cfg: ImageConfig,
	now: EpochMillis = Date.now(),
): FindingInput[] => CONFIG_RULES.flatMap((rule) => rule(image, cfg, now));

const TRIVY_SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MEDIUM: "medium",
	LOW: "low",
};

export interface TrivyResult {
	readonly findings: FindingInput[];
	readonly config: ImageConfig | undefined;
}

type JsonRecord = Record<string, unknown>;

const osEolFindings = (
	image: ImageName,
	metadata: JsonRecord | undefined,
): FindingInput[] => {
	const os = asRecord(metadata?.OS);
	if (os?.EOSL !== true) return [];
	return [
		{
			ruleId: "container.image/os-eol",
			title: "Base OS is end-of-life",
			severity: "high",
			category: "supply-chain",
			message: `\`${image}\` is based on ${os.Family ?? "an OS"} ${os.Name ?? ""}, which no longer receives security updates.`,
			remediation: "Rebuild on a supported base image release.",
			location: { file: image },
			evidence: `${os.Family ?? ""} ${os.Name ?? ""}`.trim(),
			references: ["https://endoflife.date/"],
			tags: ["cwe-1104"],
		},
	];
};

const optionalString = (v: unknown): string | undefined =>
	typeof v === "string" ? v : undefined;

const vulnerabilityFinding = (
	target: ImageName,
	vuln: JsonRecord,
): FindingInput => {
	const id = String(vuln.VulnerabilityID ?? "UNKNOWN");
	const pkg = String(vuln.PkgName ?? "package");
	const version = String(vuln.InstalledVersion ?? "");
	const fixed = optionalString(vuln.FixedVersion);
	const url = optionalString(vuln.PrimaryURL);
	return {
		ruleId: "container.image/vulnerability",
		title: `${id} in ${pkg}`,
		severity: TRIVY_SEVERITY[String(vuln.Severity)] ?? "info",
		category: "supply-chain",
		message: `${pkg}@${version} is affected by ${id}${vuln.Title ? `: ${vuln.Title}` : ""}.`,
		remediation: fixed
			? `Upgrade ${pkg} to ${fixed} (or rebuild on a patched base image).`
			: "No fixed version yet; assess exploitability, mitigate, or switch to an unaffected base image.",
		location: { file: target },
		evidence: `${id} ${pkg}@${version}`,
		references: url ? [url] : [],
		tags: [
			id.toLowerCase(),
			...asArray(vuln.CweIDs).map((c) => String(c).toLowerCase()),
		],
	};
};

const secretFinding = (target: ImageName, secret: JsonRecord): FindingInput => {
	const match = String(secret.Match ?? "").trim();
	return {
		ruleId: "container.image/secret",
		title: `Secret in image: ${secret.Title ?? secret.RuleID ?? "credential"}`,
		severity: TRIVY_SEVERITY[String(secret.Severity)] ?? "high",
		category: "security",
		message: `A ${secret.Category ? `${secret.Category} ` : ""}secret (${secret.RuleID ?? "unknown rule"}) is embedded in ${target}.`,
		remediation:
			"Remove the file from the image (and every layer — rebuild), then rotate the credential.",
		location: {
			file: target,
			line: typeof secret.StartLine === "number" ? secret.StartLine : undefined,
		},
		evidence: match.length > 120 ? `${match.slice(0, 120)}…` : match,
		references: ["https://trivy.dev/latest/docs/scanner/secret/"],
		tags: ["cwe-798"],
	};
};

/** The records in a JSON array, skipping anything that is not an object. */
const records = (v: unknown): JsonRecord[] =>
	asArray(v).flatMap((item) => {
		const record = asRecord(item);
		return record ? [record] : [];
	});

/** Vulnerabilities, then secrets, of one trivy result. */
const resultFindings = (image: ImageName, r: unknown): FindingInput[] => {
	const result = asRecord(r);
	const target = String(result?.Target ?? image);
	return [
		...records(result?.Vulnerabilities).map((v) =>
			vulnerabilityFinding(target, v),
		),
		...records(result?.Secrets).map((s) => secretFinding(target, s)),
	];
};

const trivyConfig = (
	metadata: JsonRecord | undefined,
): ImageConfig | undefined => {
	const imageConfig = asRecord(metadata?.ImageConfig);
	if (!imageConfig) return undefined;
	return toConfig(
		asRecord(imageConfig.config),
		imageConfig.created,
		metadata?.Size,
	);
};

/** Parses `trivy image --format json` output. Exported for tests. */
export const parseTrivyOutput = (
	image: ImageName,
	stdout: JsonOutput,
): TrivyResult => {
	const root = asRecord(JSON.parse(stdout));
	const metadata = asRecord(root?.Metadata);
	return {
		findings: [
			...osEolFindings(image, metadata),
			...asArray(root?.Results).flatMap((r) => resultFindings(image, r)),
		],
		config: trivyConfig(metadata),
	};
};

/** Set for remote (HTTP) clients: never read the local daemon or paths. */
const isRegistryOnly = (ctx: AuditContext) =>
	ctx.options.settings?.["container.image"]?.registryOnly === true;

const trivyCommand = (ctx: AuditContext, trivy: string, ref: ImageName) => [
	trivy,
	"image",
	"--format",
	"json",
	"--quiet",
	"--scanners",
	"vuln,secret",
	...(isRegistryOnly(ctx) ? ["--image-src", "remote"] : []),
	...(ctx.options.offline ? ["--skip-db-update", "--offline-scan"] : []),
	ref,
];

/** Trivy's findings, or the tail of its stderr when the scan failed. */
type TrivyScan =
	| { readonly findings: FindingInput[] }
	| { readonly error: string };

const scanWithTrivy = (
	ctx: AuditContext,
	trivy: string,
	ref: ImageName,
): Effect.Effect<TrivyScan, AuditorError> =>
	Effect.gen(function* () {
		const res = yield* ctx.exec.run(trivyCommand(ctx, trivy, ref), {
			timeoutMs: 280_000,
		});
		if (res.code !== 0 || !res.stdout.trim())
			return {
				error: res.stderr.trim().split("\n").slice(-3).join(" "),
			};
		const parsed = yield* Effect.try({
			try: () => parseTrivyOutput(ref, res.stdout),
			catch: (cause) =>
				new AuditorError({ message: "Could not parse trivy output", cause }),
		});
		return {
			findings: [
				...parsed.findings,
				...(parsed.config ? configFindings(ref, parsed.config) : []),
			],
		};
	});

/** Fails with trivy's error when it ran and failed, otherwise skips with `reason`. */
const failOrSkip = (
	trivyError: string | undefined,
	reason: string,
): Effect.Effect<never, AuditorError | SkipAudit> =>
	trivyError
		? Effect.fail(new AuditorError({ message: `trivy failed: ${trivyError}` }))
		: skip(reason);

const isMissingLocally = (res: ExecResult) =>
	res.code !== 0 && /no such image/i.test(res.stderr);

/** `docker image inspect`, pulling the image first when it is not local. */
const inspectImage = (ctx: AuditContext, docker: string, ref: ImageName) =>
	Effect.gen(function* () {
		const inspect = () =>
			ctx.exec.run([docker, "image", "inspect", ref], { timeoutMs: 30_000 });
		const res = yield* inspect();
		if (!isMissingLocally(res) || ctx.options.offline) return res;
		yield* ctx.log(`Pulling ${ref} for inspection`);
		const pull = yield* ctx.exec.run([docker, "pull", "--quiet", ref], {
			timeoutMs: 240_000,
		});
		return pull.code === 0 ? yield* inspect() : res;
	});

const scanSkippedFinding = (ref: ImageName) =>
	({
		ruleId: "container.image/vulnerability-scan-skipped",
		title: "Vulnerability scan not run",
		severity: "info",
		category: "supply-chain",
		message:
			"Trivy is not installed, so only the image configuration was checked.",
		remediation: `Install Trivy to scan OS and language packages: ${TRIVY_INSTALL}`,
		location: { file: ref },
	}) satisfies FindingInput;

interface DockerFallback {
	readonly ctx: AuditContext;
	readonly ref: ImageName;
	readonly trivy: string | undefined;
	readonly trivyError: string | undefined;
}

/** Checks the image config through `docker image inspect` when trivy is missing or failed. */
const inspectWithDocker = ({
	ctx,
	ref,
	trivy,
	trivyError,
}: DockerFallback): Effect.Effect<FindingInput[], AuditorError | SkipAudit> =>
	Effect.gen(function* () {
		if (isRegistryOnly(ctx))
			return yield* failOrSkip(
				trivyError,
				"Remote image scans need Trivy; the local docker daemon is not used for remote clients.",
			);
		const docker = yield* ctx.exec.which("docker");
		if (!docker)
			return yield* failOrSkip(
				trivyError,
				`Neither trivy nor docker found on PATH. Install Trivy: ${TRIVY_INSTALL}`,
			);
		const res = yield* inspectImage(ctx, docker, ref);
		if (res.code !== 0) {
			const reason = res.stderr.trim().split("\n")[0] ?? "unknown error";
			return yield* skip(
				`docker image inspect failed (${reason})${trivyError ? `; trivy failed: ${trivyError}` : ""}`,
			);
		}
		const config = parseDockerInspect(res.stdout);
		if (!config)
			return yield* new AuditorError({
				message: "Could not parse docker image inspect output",
			});
		return [
			...configFindings(ref, config),
			...(trivy ? [] : [scanSkippedFinding(ref)]),
		];
	});

/** Scans an `image:<ref>` target with Trivy, falling back to `docker image inspect`. */
export const image = defineAuditor({
	id: "container.image",
	title: "Container image scan",
	description:
		"Scans an image (image:<ref>) for vulnerable packages and secrets with Trivy, and checks its config (user, ports, env secrets, age, size); falls back to `docker image inspect` without Trivy.",
	categories: ["security", "supply-chain"],
	targets: ["container"],
	engine: "external",
	tool: "trivy",
	run: (ctx) =>
		Effect.gen(function* () {
			const ref = ctx.target.image;
			if (ctx.target.type !== "image" || !ref)
				return yield* skip("Only runs for image:<ref> targets");
			const trivy = yield* ctx.exec.which("trivy");
			const scan = trivy ? yield* scanWithTrivy(ctx, trivy, ref) : undefined;
			if (scan && "findings" in scan) return scan.findings;
			return yield* inspectWithDocker({
				ctx,
				ref,
				trivy,
				trivyError: scan?.error,
			});
		}),
});
