import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
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
import { truncate } from "./util";

/** Pinned stable ZAP image; bump deliberately. */
export const ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:2.17.0";
const DOCKER_HOST = "host.docker.internal";

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
					ruleId: `web.zap-baseline/${alert.pluginid}-${kebab(name)}`,
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
const forContainer = (url: string): string => {
	const u = new URL(url);
	u.hostname = DOCKER_HOST;
	return u.toString();
};

/** OWASP ZAP baseline scan: spider plus passive rules only, never the active scan. */
export const zapBaseline = defineAuditor({
	id: "web.zap-baseline",
	title: "OWASP ZAP baseline",
	description:
		"Runs the OWASP ZAP baseline scan (zap-baseline.py: spider for about a minute, then passive rules only; no attacks and no active scan) from a local install or the pinned Docker image. Sends GET requests while spidering, more than the default URL auditors, so it is opt-in. Localhost targets are reached through host.docker.internal. Authenticated scans are not supported.",
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
			if (ctx.options.headers && Object.keys(ctx.options.headers).length > 0)
				yield* ctx.log(
					"web.zap-baseline: custom headers are not forwarded (authenticated scans are not supported)",
				);
			const local = yield* ctx.exec.which("zap-baseline.py");
			const docker = local ? undefined : yield* ctx.exec.which("docker");
			if (!local && !docker)
				return yield* skip(
					"Neither zap-baseline.py nor docker found on PATH. Install Docker (https://docs.docker.com/get-docker/) and the scan pulls " +
						`${ZAP_IMAGE}, or install ZAP's zap-baseline.py.`,
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
				mkdtemp(join(tmpdir(), "openaudit-zap-")),
			);
			return yield* Effect.gen(function* () {
				// The container's zap user must be able to write the report.
				yield* Effect.promise(() => chmod(dir, 0o777));
				const scan = ["-t", target, "-J", "report.json", "-m", "1", "-I"];
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
							"zap-baseline.py",
							...scan,
						];
				const res = yield* ctx.exec.run(cmd, {
					cwd: dir,
					timeoutMs: 20 * 60_000,
				});
				const body = yield* Effect.promise(() =>
					readFile(join(dir, "report.json"), "utf8").catch(() => ""),
				);
				// 0 = pass, 1 = failures, 2 = warnings; 3 and others = scan error.
				if (!body.trim() || res.code > 2)
					return yield* Effect.fail(
						new AuditorError({
							message: `zap-baseline.py exited with code ${res.code} and no report: ${truncate((res.stderr || res.stdout).trim(), 300)}`,
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
				);
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			);
		}),
});
