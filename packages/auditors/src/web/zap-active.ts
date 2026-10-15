import {
	type AuditContext,
	defineAuditor,
	requireUrl,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { parseUrl } from "./util";
import { runZapScan, ZAP_AUDITOR } from "./zap";

const ID = "web.zap-active";
const DEFAULT_MINUTES = 10;
const MAX_MINUTES = 120;

interface ZapActiveSettings {
	readonly allowHosts: ReadonlyArray<string>;
	readonly maxMinutes: number;
}

/** Lower-cased host names the user allow-listed; anything but strings is dropped. */
const hostList = (hosts: unknown): ReadonlyArray<string> =>
	(Array.isArray(hosts) ? hosts : [])
		.filter((h): h is string => typeof h === "string")
		.map((h) => h.trim().toLowerCase())
		.filter(Boolean);

const isWholeNumber = (n: unknown): n is number =>
	typeof n === "number" && Number.isInteger(n);

const inMinuteRange = (n: number) => n >= 1 && n <= MAX_MINUTES;

const minutesOrDefault = (mins: unknown): number =>
	isWholeNumber(mins) && inMinuteRange(mins) ? mins : DEFAULT_MINUTES;

export const readZapActiveSettings = (ctx: AuditContext): ZapActiveSettings => {
	const s = ctx.options.settings?.[ID];
	return {
		allowHosts: hostList(s?.allowHosts),
		maxMinutes: minutesOrDefault(s?.maxMinutes),
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
	...ZAP_AUDITOR,
	run: (ctx) =>
		Effect.gen(function* () {
			const url = yield* requireUrl(ctx);
			const parsed = yield* parseUrl(url);
			const { allowHosts, maxMinutes } = readZapActiveSettings(ctx);
			if (!isHostAllowed(parsed.hostname, allowHosts))
				return yield* skip(
					`The ZAP active scan sends attack payloads and is only allowed against hosts you list explicitly. Add "${parsed.hostname}" to ` +
						`options.settings["${ID}"].allowHosts in a config file passed with --config <path>, only for systems you are authorised to attack. ` +
						"Settings in a config found inside the target are ignored.",
				);
			return yield* runZapScan(ctx, {
				id: ID,
				script: "zap-full-scan.py",
				url,
				hostname: parsed.hostname,
				tmpPrefix: "openaudit-zap-active-",
				args: (target) => [
					"-t",
					target,
					"-J",
					"report.json",
					"-m",
					String(maxMinutes),
					"-z",
					`-config scanner.maxScanDurationInMins=${maxMinutes}`,
					"-I",
				],
				// Hard cap: spider + active scan + ZAP start-up and passive scan.
				timeoutMs: (2 * maxMinutes + 10) * 60_000,
				announce: `${ID}: actively scanning ${parsed.hostname} for up to ${maxMinutes} min`,
			});
		}),
});
