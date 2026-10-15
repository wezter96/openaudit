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

interface Rewrite {
	readonly from: string;
	readonly to: string;
}

/** Maps the Docker host alias in a URL back to the host the user asked for. */
const rewriter =
	(rewrite?: Rewrite) =>
	(u?: string): string | undefined =>
		u && rewrite ? u.split(rewrite.from).join(rewrite.to) : u;

const referencesOf = (alert: ZapAlert, pluginid: string) => [
	...new Set(
		(text(alert.reference).match(/https?:\/\/[^\s<>"]+/g) ?? []).map((r) =>
			r.replace(/[.,)]+$/, ""),
		),
	),
	`https://www.zaproxy.org/docs/alerts/${pluginid}/`,
];

const tagsOf = (alert: ZapAlert) => [
	...cweTags(Number(alert.cweid) > 0 ? [`CWE-${alert.cweid}`] : []),
	...(Number(alert.wascid) > 0 ? [`wasc-${alert.wascid}`] : []),
];

/** Instances with a distinct method, URL and parameter. */
const uniqueInstances = (instances: ReadonlyArray<ZapInstance>) => {
	const seen = new Set<string>();
	return instances.filter((i) => {
		const key = `${i.method} ${i.uri} ${i.param}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
};

const instanceEvidence = (inst: ZapInstance) =>
	[
		inst.param ? `param: ${inst.param}` : "",
		inst.evidence ? truncate(inst.evidence.replace(/\s+/g, " "), 160) : "",
	]
		.filter(Boolean)
		.join(" · ");

/** One finding per unique instance URL of an alert (capped). */
const alertFindings = (
	alert: ZapAlert,
	back: ReturnType<typeof rewriter>,
	auditorId: string,
): FindingInput[] => {
	const severity = RISK[alert.riskcode ?? ""];
	const name = alert.name ?? alert.alert;
	if (!severity || !name) return [];
	// confidence 0 is a ZAP-confirmed false positive.
	if (alert.confidence === "0" || !alert.pluginid) return [];
	const plain = text(alert.desc).split("\n")[0] ?? name;
	const references = referencesOf(alert, alert.pluginid);
	const tags = tagsOf(alert);
	const instances = uniqueInstances(alert.instances ?? []);
	const message = `${truncate(plain, 300)}${instances.length > 1 ? ` (${instances.length} URLs affected)` : ""}`;
	const remediation =
		truncate(text(alert.solution).replace(/\n/g, " "), 400) ||
		"See the ZAP alert documentation.";
	return instances.slice(0, MAX_INSTANCES).map((inst) => ({
		ruleId: `${auditorId}/${alert.pluginid}-${kebab(name)}`,
		title: name,
		severity,
		category: "security",
		message,
		location: { url: back(inst.uri) },
		evidence: instanceEvidence(inst) || undefined,
		remediation,
		references,
		confidence: CONFIDENCE[alert.confidence ?? ""],
		tags,
	}));
};

/**
 * Maps a ZAP traditional JSON report to findings, one per alert and unique
 * instance URL (capped). `rewrite` maps the Docker host alias back to the
 * host the user asked for.
 */
export const parseZapReport = (
	report: ZapReport,
	rewrite?: Rewrite,
	/** Rule id prefix; the active scan reports under its own auditor id. */
	auditorId = "web.zap-baseline",
): FindingInput[] => {
	const back = rewriter(rewrite);
	return (report.site ?? []).flatMap((site) =>
		(site.alerts ?? []).flatMap((alert) =>
			alertFindings(alert, back, auditorId),
		),
	);
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

interface ExecResult {
	readonly code: number;
	readonly stdout: string;
	readonly stderr: string;
}

/** How the scan runs: a local ZAP script, or Docker with a scratch dir mounted. */
interface ZapRun {
	readonly local?: string;
	readonly docker?: string;
	readonly loopback: boolean;
	readonly dir: string;
	/** A loopback target reached from the container through the Docker host alias. */
	readonly viaDockerHost: boolean;
}

const hasCustomHeaders = (ctx: AuditContext) =>
	Object.keys(ctx.options.headers ?? {}).length > 0;

const requireDockerDaemon = (ctx: AuditContext, docker: string) =>
	Effect.gen(function* () {
		const info = yield* ctx.exec
			.run([docker, "info"], { timeoutMs: 20_000 })
			.pipe(Effect.orElseSucceed(() => ({ code: 1, stdout: "", stderr: "" })));
		if (info.code !== 0)
			return yield* skip("Docker daemon is not running (`docker info` failed)");
	});

/** A local ZAP script, else a running Docker daemon; skips when neither is usable. */
const findRunner = (ctx: AuditContext, scan: ZapScan) =>
	Effect.gen(function* () {
		const local = yield* ctx.exec.which(scan.script);
		const docker = local ? undefined : yield* ctx.exec.which("docker");
		if (!local && !docker)
			return yield* skip(
				`Neither ${scan.script} nor docker found on PATH. Install Docker (https://docs.docker.com/get-docker/) and the scan pulls ` +
					`${ZAP_IMAGE}, or install ZAP's ${scan.script}.`,
			);
		if (docker) yield* requireDockerDaemon(ctx, docker);
		return { local, docker };
	});

const zapCommand = (scan: ZapScan, run: ZapRun, args: ReadonlyArray<string>) =>
	run.local
		? [run.local, ...args]
		: [
				run.docker as string,
				"run",
				"--rm",
				"-v",
				`${run.dir}:/zap/wrk/:rw`,
				...(run.loopback ? [`--add-host=${DOCKER_HOST}:host-gateway`] : []),
				ZAP_IMAGE,
				scan.script,
				...args,
			];

const readReport = (dir: string, script: string, res: ExecResult) =>
	Effect.gen(function* () {
		const body = yield* Effect.promise(() =>
			readFile(join(dir, "report.json"), "utf8").catch(() => ""),
		);
		// 0 = pass, 1 = failures, 2 = warnings; 3 and others = scan error.
		if (!body.trim() || res.code > 2)
			return yield* Effect.fail(
				new AuditorError({
					message: `${script} exited with code ${res.code} and no report: ${truncate((res.stderr || res.stdout).trim(), 300)}`,
				}),
			);
		return yield* Effect.try({
			try: () => JSON.parse(body) as ZapReport,
			catch: (cause) =>
				new AuditorError({
					message: "ZAP produced an invalid JSON report",
					cause,
				}),
		});
	});

const scanIn = (ctx: AuditContext, scan: ZapScan, run: ZapRun) =>
	Effect.gen(function* () {
		// The container's zap user must be able to write the report.
		yield* Effect.promise(() => chmod(run.dir, 0o777));
		const target = run.viaDockerHost ? forContainer(scan.url) : scan.url;
		const cmd = zapCommand(scan, run, scan.args(target));
		if (scan.announce) yield* ctx.log(scan.announce);
		const res = yield* ctx.exec.run(cmd, {
			cwd: run.dir,
			timeoutMs: scan.timeoutMs,
		});
		const report = yield* readReport(run.dir, scan.script, res);
		return parseZapReport(
			report,
			run.viaDockerHost ? { from: DOCKER_HOST, to: scan.hostname } : undefined,
			scan.id,
		);
	});

/**
 * Runs a ZAP packaged scan from a local install or the pinned Docker image and
 * parses its JSON report. Skips when neither is available.
 */
export const runZapScan = (ctx: AuditContext, scan: ZapScan) =>
	Effect.gen(function* () {
		if (hasCustomHeaders(ctx))
			yield* ctx.log(
				`${scan.id}: custom headers are not forwarded (authenticated scans are not supported)`,
			);
		const { local, docker } = yield* findRunner(ctx, scan);
		const loopback = isLoopback(scan.url);
		const viaDockerHost = Boolean(docker) && loopback;
		const dir = yield* Effect.promise(() =>
			mkdtemp(join(tmpdir(), scan.tmpPrefix)),
		);
		return yield* scanIn(ctx, scan, {
			local,
			docker,
			loopback,
			dir,
			viaDockerHost,
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
