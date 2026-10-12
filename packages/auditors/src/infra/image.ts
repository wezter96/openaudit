import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	redact,
	type Severity,
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
export const parseDockerInspect = (stdout: string): ImageConfig | undefined => {
	try {
		const first = asRecord(asArray(JSON.parse(stdout))[0]);
		if (!first) return undefined;
		return toConfig(asRecord(first.Config), first.Created, first.Size);
	} catch {
		return undefined;
	}
};

/** Findings derived from image configuration (user, ports, env, age, size). */
export const configFindings = (
	image: string,
	cfg: ImageConfig,
	now: number = Date.now(),
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const location = { file: image };
	const user = (cfg.user ?? "").trim();
	if (user === "" || /^(root|0)(:(root|0))?$/.test(user))
		findings.push({
			ruleId: "container.image/runs-as-root",
			title: "Image runs as root",
			severity: "medium",
			category: "security",
			message: `\`${image}\` has ${user ? `\`User: ${user}\`` : "no configured user"}, so its processes run as root by default.`,
			remediation:
				"Set a non-root `USER` in the Dockerfile, or run with `--user` / `runAsNonRoot` in your orchestrator.",
			location,
			evidence: `User: ${user || "(empty)"}`,
			references: [
				CIS_DOCKER,
				"https://docs.docker.com/reference/dockerfile/#user",
			],
			tags: ["cis-docker-4.1", "cwe-250"],
		});

	if (cfg.exposedPorts.some((p) => /^22(\/tcp)?$/.test(p)))
		findings.push({
			ruleId: "container.image/ssh-exposed",
			title: "SSH port exposed",
			severity: "medium",
			category: "security",
			message: `\`${image}\` exposes port 22, suggesting an SSH daemon inside the container.`,
			remediation: "Remove sshd from the image; use `docker exec` for access.",
			location,
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
			location,
			evidence: cfg.exposedPorts.join(", "),
		});

	for (const entry of cfg.env) {
		const eq = entry.indexOf("=");
		const key = eq === -1 ? entry : entry.slice(0, eq);
		const value = eq === -1 ? "" : entry.slice(eq + 1);
		if (SECRET_NAME_RE.test(key) && !isPlaceholderValue(value))
			findings.push({
				ruleId: "container.image/secret-in-env",
				title: "Secret baked into image environment",
				severity: "high",
				category: "security",
				message: `\`${key}\` is set in the image config; anyone who can pull \`${image}\` can read it.`,
				remediation:
					"Rebuild without the value, rotate the credential and inject secrets at runtime.",
				location,
				evidence: `${key}=${redact(value)}`,
				references: ["https://docs.docker.com/build/building/secrets/"],
				tags: ["cis-docker-4.10", "cwe-798"],
			});
	}

	const created = cfg.created ? Date.parse(cfg.created) : Number.NaN;
	// Reproducible builds (ko, nix, distroless) stamp the epoch; age is meaningless there.
	if (Number.isFinite(created) && new Date(created).getUTCFullYear() > 2000) {
		const days = Math.floor((now - created) / 86_400_000);
		if (days > STALE_DAYS)
			findings.push({
				ruleId: "container.image/stale",
				title: "Image is old",
				severity: "low",
				category: "supply-chain",
				message: `\`${image}\` was built ${days} days ago and likely misses OS and dependency security patches.`,
				remediation:
					"Rebuild regularly (e.g. weekly) on an updated base image and redeploy.",
				location,
				evidence: `Created: ${cfg.created}`,
				references: [
					"https://docs.docker.com/build/building/best-practices/#rebuild-your-images-often",
				],
			});
	}

	if (cfg.size !== undefined && cfg.size > 500 * MB)
		findings.push({
			ruleId: "container.image/large",
			title: "Large image",
			severity: cfg.size > 1024 * MB ? "low" : "info",
			category: "performance",
			message: `\`${image}\` is ${Math.round(cfg.size / MB)} MB, slowing pulls and cold starts and enlarging the attack surface.`,
			remediation:
				"Use a slim/distroless base, multi-stage builds and remove build tools and caches.",
			location,
			evidence: `Size: ${Math.round(cfg.size / MB)} MB`,
			references: ["https://docs.docker.com/build/building/multi-stage/"],
		});

	return findings;
};

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

/** Parses `trivy image --format json` output. Exported for tests. */
export const parseTrivyOutput = (
	image: string,
	stdout: string,
): TrivyResult => {
	const root = asRecord(JSON.parse(stdout));
	const findings: FindingInput[] = [];
	const metadata = asRecord(root?.Metadata);
	const os = asRecord(metadata?.OS);
	if (os?.EOSL === true)
		findings.push({
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
		});

	for (const r of asArray(root?.Results)) {
		const result = asRecord(r);
		const target = String(result?.Target ?? image);
		for (const v of asArray(result?.Vulnerabilities)) {
			const vuln = asRecord(v);
			if (!vuln) continue;
			const id = String(vuln.VulnerabilityID ?? "UNKNOWN");
			const pkg = String(vuln.PkgName ?? "package");
			const version = String(vuln.InstalledVersion ?? "");
			const fixed =
				typeof vuln.FixedVersion === "string" ? vuln.FixedVersion : undefined;
			const url =
				typeof vuln.PrimaryURL === "string" ? vuln.PrimaryURL : undefined;
			findings.push({
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
			});
		}
		for (const s of asArray(result?.Secrets)) {
			const secret = asRecord(s);
			if (!secret) continue;
			const match = String(secret.Match ?? "").trim();
			findings.push({
				ruleId: "container.image/secret",
				title: `Secret in image: ${secret.Title ?? secret.RuleID ?? "credential"}`,
				severity: TRIVY_SEVERITY[String(secret.Severity)] ?? "high",
				category: "security",
				message: `A ${secret.Category ? `${secret.Category} ` : ""}secret (${secret.RuleID ?? "unknown rule"}) is embedded in ${target}.`,
				remediation:
					"Remove the file from the image (and every layer — rebuild), then rotate the credential.",
				location: {
					file: target,
					line:
						typeof secret.StartLine === "number" ? secret.StartLine : undefined,
				},
				evidence: match.length > 120 ? `${match.slice(0, 120)}…` : match,
				references: ["https://trivy.dev/latest/docs/scanner/secret/"],
				tags: ["cwe-798"],
			});
		}
	}

	const imageConfig = asRecord(metadata?.ImageConfig);
	const config = imageConfig
		? toConfig(
				asRecord(imageConfig.config),
				imageConfig.created,
				metadata?.Size,
			)
		: undefined;
	return { findings, config };
};

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
			let trivyError: string | undefined;
			if (trivy) {
				const res = yield* ctx.exec.run(
					[
						trivy,
						"image",
						"--format",
						"json",
						"--quiet",
						"--scanners",
						"vuln,secret",
						...(ctx.options.offline
							? ["--skip-db-update", "--offline-scan"]
							: []),
						ref,
					],
					{ timeoutMs: 280_000 },
				);
				if (res.code === 0 && res.stdout.trim()) {
					const parsed = yield* Effect.try({
						try: () => parseTrivyOutput(ref, res.stdout),
						catch: (cause) =>
							new AuditorError({
								message: "Could not parse trivy output",
								cause,
							}),
					});
					return [
						...parsed.findings,
						...(parsed.config ? configFindings(ref, parsed.config) : []),
					];
				}
				trivyError = res.stderr.trim().split("\n").slice(-3).join(" ");
			}

			const docker = yield* ctx.exec.which("docker");
			if (!docker)
				return yield* trivyError
					? Effect.fail(
							new AuditorError({ message: `trivy failed: ${trivyError}` }),
						)
					: skip(
							"Neither trivy nor docker found on PATH. Install Trivy: https://trivy.dev/latest/getting-started/installation/",
						);

			const inspect = () =>
				ctx.exec.run([docker, "image", "inspect", ref], { timeoutMs: 30_000 });
			let res = yield* inspect();
			if (
				res.code !== 0 &&
				/no such image/i.test(res.stderr) &&
				!ctx.options.offline
			) {
				yield* ctx.log(`Pulling ${ref} for inspection`);
				const pull = yield* ctx.exec.run([docker, "pull", "--quiet", ref], {
					timeoutMs: 240_000,
				});
				if (pull.code === 0) res = yield* inspect();
			}
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
				...(trivy
					? []
					: [
							{
								ruleId: "container.image/vulnerability-scan-skipped",
								title: "Vulnerability scan not run",
								severity: "info",
								category: "supply-chain",
								message:
									"Trivy is not installed, so only the image configuration was checked.",
								remediation:
									"Install Trivy to scan OS and language packages: https://trivy.dev/latest/getting-started/installation/",
								location: { file: ref },
							} satisfies FindingInput,
						]),
			];
		}),
});
