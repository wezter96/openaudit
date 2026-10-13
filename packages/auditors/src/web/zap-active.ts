import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	requireUrl,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isLoopback } from "./page";
import { truncate } from "./util";
import {
	DOCKER_HOST,
	forContainer,
	parseZapReport,
	ZAP_IMAGE,
	type ZapReport,
} from "./zap";

const ID = "web.zap-active";
const DEFAULT_MINUTES = 10;
const MAX_MINUTES = 120;

interface ZapActiveSettings {
	readonly allowHosts: ReadonlyArray<string>;
	readonly maxMinutes: number;
}

/** Lower-cased host names the user allow-listed; anything but strings is dropped. */
export const readZapActiveSettings = (ctx: AuditContext): ZapActiveSettings => {
	const s = ctx.options.settings?.[ID];
	const hosts = Array.isArray(s?.allowHosts) ? s.allowHosts : [];
	const mins = s?.maxMinutes;
	return {
		allowHosts: hosts
			.filter((h): h is string => typeof h === "string")
			.map((h) => h.trim().toLowerCase())
			.filter(Boolean),
		maxMinutes:
			typeof mins === "number" &&
			Number.isInteger(mins) &&
			mins >= 1 &&
			mins <= MAX_MINUTES
				? mins
				: DEFAULT_MINUTES,
	};
};

/** Exact host-name match (no wildcards, no suffixes, no ports). */
export const isHostAllowed = (
	hostname: string,
	allowHosts: ReadonlyArray<string>,
): boolean => allowHosts.includes(hostname.toLowerCase());

/** ZAP full scan: spider plus the ACTIVE scanner, which sends attack payloads. */
export const zapActive = defineAuditor({
	id: ID,
	title: "OWASP ZAP active scan",
	description:
		'Runs the OWASP ZAP full scan (zap-full-scan.py: spider, then the ACTIVE scanner) from the pinned Docker image or a local install. The active scanner sends attack payloads (injection strings, fuzzing, forced browsing) and can create or alter data, so it only runs against a host listed in settings["web.zap-active"].allowHosts (exact host name) and that setting is only honoured from a trusted config (`--config <path>`), never from a config found inside the target. settings["web.zap-active"].maxMinutes (default 10) bounds the spider and the active scan. Localhost targets are reached through host.docker.internal. Authenticated scans are not supported. Never point it at production or at systems you do not own.',
	categories: ["security"],
	targets: ["url", "webapp"],
	engine: "external",
	tool: "docker",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const url = yield* requireUrl(ctx);
			const parsed = yield* Effect.try({
				try: () => new URL(url),
				catch: () => new AuditorError({ message: `Invalid URL: ${url}` }),
			});
			const { allowHosts, maxMinutes } = readZapActiveSettings(ctx);
			if (!isHostAllowed(parsed.hostname, allowHosts))
				return yield* skip(
					`The ZAP active scan sends attack payloads and is only allowed against hosts you list explicitly. Add "${parsed.hostname}" to ` +
						`options.settings["${ID}"].allowHosts in a config file passed with --config <path>, only for systems you are authorised to attack. ` +
						"Settings in a config found inside the target are ignored.",
				);
			if (ctx.options.headers && Object.keys(ctx.options.headers).length > 0)
				yield* ctx.log(
					`${ID}: custom headers are not forwarded (authenticated scans are not supported)`,
				);
			const local = yield* ctx.exec.which("zap-full-scan.py");
			const docker = local ? undefined : yield* ctx.exec.which("docker");
			if (!local && !docker)
				return yield* skip(
					"Neither zap-full-scan.py nor docker found on PATH. Install Docker (https://docs.docker.com/get-docker/) and the scan pulls " +
						`${ZAP_IMAGE}, or install ZAP's zap-full-scan.py.`,
				);
			if (docker) {
				const info = yield* ctx.exec
					.run([docker, "info"], { timeoutMs: 20_000 })
					.pipe(
						Effect.orElseSucceed(() => ({ code: 1, stdout: "", stderr: "" })),
					);
				if (info.code !== 0)
					return yield* skip(
						"Docker daemon is not running (`docker info` failed)",
					);
			}
			const loopback = isLoopback(url);
			const target = docker && loopback ? forContainer(url) : url;
			const dir = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-zap-active-")),
			);
			return yield* Effect.gen(function* () {
				// The container's zap user must be able to write the report.
				yield* Effect.promise(() => chmod(dir, 0o777));
				const scan = [
					"-t",
					target,
					"-J",
					"report.json",
					"-m",
					String(maxMinutes),
					"-z",
					`-config scanner.maxScanDurationInMins=${maxMinutes}`,
					"-I",
				];
				const cmd = local
					? [local, ...scan]
					: [
							docker as string,
							"run",
							"--rm",
							"-v",
							`${dir}:/zap/wrk/:rw`,
							...(loopback ? [`--add-host=${DOCKER_HOST}:host-gateway`] : []),
							ZAP_IMAGE,
							"zap-full-scan.py",
							...scan,
						];
				yield* ctx.log(
					`${ID}: actively scanning ${parsed.hostname} for up to ${maxMinutes} min`,
				);
				// Hard cap: spider + active scan + ZAP start-up and passive scan.
				const res = yield* ctx.exec.run(cmd, {
					cwd: dir,
					timeoutMs: (2 * maxMinutes + 10) * 60_000,
				});
				const body = yield* Effect.promise(() =>
					readFile(join(dir, "report.json"), "utf8").catch(() => ""),
				);
				// 0 = pass, 1 = failures, 2 = warnings; 3 and others = scan error.
				if (!body.trim() || res.code > 2)
					return yield* Effect.fail(
						new AuditorError({
							message: `zap-full-scan.py exited with code ${res.code} and no report: ${truncate((res.stderr || res.stdout).trim(), 300)}`,
						}),
					);
				const report = yield* Effect.try({
					try: () => JSON.parse(body) as ZapReport,
					catch: (cause) =>
						new AuditorError({
							message: "ZAP produced an invalid JSON report",
							cause,
						}),
				});
				return parseZapReport(
					report,
					docker && loopback
						? { from: DOCKER_HOST, to: parsed.hostname }
						: undefined,
					ID,
				);
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			);
		}),
});
