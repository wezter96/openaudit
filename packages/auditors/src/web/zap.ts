import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditContext,
	type Auditor,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { cweTags } from "../tool";
import { isLoopback } from "./page";
import { parseUrl, truncate } from "./util";

/** Pinned stable ZAP image; bump deliberately. */
export const ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:2.17.0";
export const DOCKER_HOST = "host.docker.internal";

interface ZapInstance {
	readonly uri?: string;
	readonly method?: string;
	readonly param?: string;
	readonly attack?: string;
	readonly evidence?: string;
	readonly otherinfo?: string;
}

interface ZapAlert {
	readonly pluginid?: string;
	readonly alertRef?: string;
	readonly name?: string;
	readonly alert?: string;
	readonly riskcode?: string;
	readonly confidence?: string;
	readonly desc?: string;
	readonly solution?: string;
	readonly reference?: string;
	readonly cweid?: string;
	readonly wascid?: string;
	readonly count?: string;
	readonly instances?: ReadonlyArray<ZapInstance>;
}

export interface ZapReport {
	readonly site?: ReadonlyArray<{ readonly alerts?: ReadonlyArray<ZapAlert> }>;
}

/** Risk 0-3 → info/low/medium/high (ZAP has no critical level). */
const RISK: Record<string, Severity> = {
	"0": "info",
	"1": "low",
	"2": "medium",
	"3": "high",
};
const CONFIDENCE: Record<string, "high" | "medium" | "low"> = {
	"1": "low",
	"2": "medium",
	"3": "high",
	"4": "high",
};
const MAX_INSTANCES = 20;

const kebab = (s: string) =>
	s
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");

/** ZAP descriptions are small HTML fragments (<p>…</p>). */
const text = (html = "") =>
	html
		.replace(/<\/p>\s*<p>/gi, "\n")
		.replace(/<[^>]+>/g, "")
		.replace(/&lt;/g, "<")
		.replace(/&gt;/g, ">")
		.replace(/&quot;/g, '"')
		.replace(/&amp;/g, "&")
		.trim();

/**
 * Maps a ZAP traditional JSON report to findings, one per alert and unique
 * instance URL (capped). `rewrite` maps the Docker host alias back to the
 * host the user asked for.
 */
export const parseZapReport = (
	report: ZapReport,
	rewrite?: { readonly from: string; readonly to: string },
	/** Rule id prefix; the active scan reports under its own auditor id. */
	auditorId = "web.zap-baseline",
): FindingInput[] => {
	const back = (u?: string) =>
		u && rewrite ? u.split(rewrite.from).join(rewrite.to) : u;
	const findings: FindingInput[] = [];
	for (const site of report.site ?? []) {
		for (const alert of site.alerts ?? []) {
			const severity = RISK[alert.riskcode ?? ""];
			const name = alert.name ?? alert.alert;
			// confidence 0 is a ZAP-confirmed false positive.
			if (!severity || !name || alert.confidence === "0" || !alert.pluginid)
				continue;
			const plain = text(alert.desc).split("\n")[0] ?? name;
			const refs = [
				...new Set(
					(text(alert.reference).match(/https?:\/\/[^\s<>"]+/g) ?? []).map(
						(r) => r.replace(/[.,)]+$/, ""),
					),
				),
				`https://www.zaproxy.org/docs/alerts/${alert.pluginid}/`,
			];
			const tags = [
				...cweTags(Number(alert.cweid) > 0 ? [`CWE-${alert.cweid}`] : []),
				...(Number(alert.wascid) > 0 ? [`wasc-${alert.wascid}`] : []),
			];
			const seen = new Set<string>();
			const instances = (alert.instances ?? []).filter((i) => {
				const key = `${i.method} ${i.uri} ${i.param}`;
				if (seen.has(key)) return false;
				seen.add(key);
				return true;
			});
			for (const inst of instances.slice(0, MAX_INSTANCES)) {
				const evidence = [
					inst.param ? `param: ${inst.param}` : "",
					inst.evidence
						? truncate(inst.evidence.replace(/\s+/g, " "), 160)
						: "",
				]
					.filter(Boolean)
					.join(" · ");
				findings.push({
					ruleId: `${auditorId}/${alert.pluginid}-${kebab(name)}`,
					title: name,
					severity,
					category: "security",
					message: `${truncate(plain, 300)}${instances.length > 1 ? ` (${instances.length} URLs affected)` : ""}`,
					location: { url: back(inst.uri) },
					evidence: evidence || undefined,
					remediation:
						truncate(text(alert.solution).replace(/\n/g, " "), 400) ||
						"See the ZAP alert documentation.",
					references: refs,
					confidence: CONFIDENCE[alert.confidence ?? ""],
					tags,
				});
			}
		}
	}
	return findings;
};

/** `http://localhost:3000/x` → `http://host.docker.internal:3000/x` for the container. */
export const forContainer = (url: string): string => {
	const u = new URL(url);
	u.hostname = DOCKER_HOST;
	return u.toString();
};

/** Auditor fields shared by the ZAP scans: opt-in, and run through Docker. */
export const ZAP_AUDITOR = {
	categories: ["security"],
	targets: ["url", "webapp"],
	engine: "external",
	tool: "docker",
	defaultEnabled: false,
} satisfies Partial<Auditor>;

interface ZapScan {
	/** Auditor id: the rule id prefix and log prefix. */
	readonly id: string;
	/** ZAP packaged scan script, e.g. `zap-baseline.py`. */
	readonly script: string;
	readonly url: string;
	readonly hostname: string;
	readonly tmpPrefix: string;
	/** Script arguments for the URL ZAP should scan. */
	readonly args: (target: string) => ReadonlyArray<string>;
	readonly timeoutMs: number;
	/** Logged just before the scan starts. */
	readonly announce?: string;
}

/**
 * Runs a ZAP packaged scan from a local install or the pinned Docker image and
 * parses its JSON report. Skips when neither is available.
 */
export const runZapScan = (ctx: AuditContext, scan: ZapScan) =>
	Effect.gen(function* () {
		if (ctx.options.headers && Object.keys(ctx.options.headers).length > 0)
			yield* ctx.log(
				`${scan.id}: custom headers are not forwarded (authenticated scans are not supported)`,
			);
		const local = yield* ctx.exec.which(scan.script);
		const docker = local ? undefined : yield* ctx.exec.which("docker");
		if (!local && !docker)
			return yield* skip(
				`Neither ${scan.script} nor docker found on PATH. Install Docker (https://docs.docker.com/get-docker/) and the scan pulls ` +
					`${ZAP_IMAGE}, or install ZAP's ${scan.script}.`,
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
		const loopback = isLoopback(scan.url);
		const target = docker && loopback ? forContainer(scan.url) : scan.url;
		const dir = yield* Effect.promise(() =>
			mkdtemp(join(tmpdir(), scan.tmpPrefix)),
		);
		return yield* Effect.gen(function* () {
			// The container's zap user must be able to write the report.
			yield* Effect.promise(() => chmod(dir, 0o777));
			const args = scan.args(target);
			const cmd = local
				? [local, ...args]
				: [
						docker as string,
						"run",
						"--rm",
						"-v",
						`${dir}:/zap/wrk/:rw`,
						...(loopback ? [`--add-host=${DOCKER_HOST}:host-gateway`] : []),
						ZAP_IMAGE,
						scan.script,
						...args,
					];
			if (scan.announce) yield* ctx.log(scan.announce);
			const res = yield* ctx.exec.run(cmd, {
				cwd: dir,
				timeoutMs: scan.timeoutMs,
			});
			const body = yield* Effect.promise(() =>
				readFile(join(dir, "report.json"), "utf8").catch(() => ""),
			);
			// 0 = pass, 1 = failures, 2 = warnings; 3 and others = scan error.
			if (!body.trim() || res.code > 2)
				return yield* Effect.fail(
					new AuditorError({
						message: `${scan.script} exited with code ${res.code} and no report: ${truncate((res.stderr || res.stdout).trim(), 300)}`,
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
					? { from: DOCKER_HOST, to: scan.hostname }
					: undefined,
				scan.id,
			);
		}).pipe(
			Effect.ensuring(
				Effect.promise(() => rm(dir, { recursive: true, force: true })),
			),
		);
	});

/** OWASP ZAP baseline scan: spider plus passive rules only, never the active scan. */
export const zapBaseline = defineAuditor({
	id: "web.zap-baseline",
	title: "OWASP ZAP baseline",
	description:
		"Runs the OWASP ZAP baseline scan (zap-baseline.py: spider for about a minute, then passive rules only; no attacks and no active scan) from a local install or the pinned Docker image. Sends GET requests while spidering, more than the default URL auditors, so it is opt-in. Localhost targets are reached through host.docker.internal. Authenticated scans are not supported.",
	...ZAP_AUDITOR,
	run: (ctx) =>
		Effect.gen(function* () {
			const url = yield* requireUrl(ctx);
			const parsed = yield* parseUrl(url);
			return yield* runZapScan(ctx, {
				id: "web.zap-baseline",
				script: "zap-baseline.py",
				url,
				hostname: parsed.hostname,
				tmpPrefix: "openaudit-zap-",
				args: (target) => ["-t", target, "-J", "report.json", "-m", "1", "-I"],
				timeoutMs: 20 * 60_000,
			});
		}),
});
