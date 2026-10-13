import {
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, str } from "../../tool";
import { type OsvVuln, osvSeverity } from "../dependencies";
import { isRecord } from "../util";
import {
	baseOf,
	dirOf,
	findFiles,
	joinRel,
	lower,
	osvUrl,
	run,
	vulnFinding,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                 govulncheck                                */
/* -------------------------------------------------------------------------- */

/** Splits a stream of concatenated JSON objects (govulncheck's output). */
export const splitJsonStream = (text: string): unknown[] => {
	const out: unknown[] = [];
	let level = 0;
	let start = -1;
	let inString = false;
	let escaped = false;
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (inString) {
			if (escaped) escaped = false;
			else if (c === "\\") escaped = true;
			else if (c === '"') inString = false;
		} else if (level > 0 && c === '"') {
			inString = true;
		} else if (c === "{") {
			if (level === 0) start = i;
			level++;
		} else if (c === "}" && level > 0) {
			level--;
			if (level === 0 && start >= 0) {
				try {
					out.push(JSON.parse(text.slice(start, i + 1)));
				} catch {
					// Truncated or corrupt message: skip it.
				}
				start = -1;
			}
		}
	}
	return out;
};

type GoLevel = "module" | "package" | "symbol";
const GO_LEVELS: ReadonlyArray<GoLevel> = ["module", "package", "symbol"];

interface GoFinding {
	readonly level: GoLevel;
	readonly osv: string;
	readonly fixed?: string;
	readonly module: string;
	readonly version?: string;
	readonly pkg?: string;
	readonly fn?: string;
	/** Where the main module reaches the vulnerable symbol. */
	readonly caller?: { file?: string; line?: number; fn?: string };
}

const goFinding = (raw: Record<string, unknown>): GoFinding | undefined => {
	const osv = str(raw.osv);
	const trace = arr(raw.trace).filter(isRecord);
	const top = trace[0];
	if (!osv || !top) return undefined;
	const level: GoLevel = str(top.function)
		? "symbol"
		: str(top.package)
			? "package"
			: "module";
	// The last frame is the entry point in the user's own module.
	const entry = [...trace].reverse().find((f) => isRecord(f.position));
	const pos = isRecord(entry?.position) ? entry.position : undefined;
	return {
		level,
		osv,
		fixed: str(raw.fixed_version),
		module: str(top.module) ?? "unknown",
		version: str(top.version),
		pkg: str(top.package),
		fn: str(top.function)
			? `${str(top.receiver) ? `${str(top.receiver)}.` : ""}${str(top.function)}`
			: undefined,
		caller: pos
			? {
					file: str(pos.filename),
					line: num(pos.line),
					fn: str(entry?.function),
				}
			: undefined,
	};
};

/**
 * Parses `govulncheck -format json` (a stream of `config`/`osv`/`finding`
 * messages). Symbol-level findings (the vulnerable function is reachable) are
 * high-confidence; module/package-level ones are imported-but-not-called, so
 * they are reported one severity step lower with low confidence.
 */
export const parseGovulncheckReport = (
	stdout: string,
	_root: string,
	moduleDir = "",
): FindingInput[] => {
	const osvs = new Map<string, OsvVuln>();
	const best = new Map<string, GoFinding>();
	for (const msg of splitJsonStream(stdout)) {
		if (!isRecord(msg)) continue;
		if (isRecord(msg.osv) && typeof msg.osv.id === "string") {
			osvs.set(msg.osv.id, msg.osv as unknown as OsvVuln);
		} else if (isRecord(msg.finding)) {
			const f = goFinding(msg.finding);
			if (!f) continue;
			const key = `${f.osv}|${f.module}`;
			const prev = best.get(key);
			if (!prev || GO_LEVELS.indexOf(f.level) > GO_LEVELS.indexOf(prev.level))
				best.set(key, f);
		}
	}
	const goMod = joinRel(moduleDir, "go.mod");
	return [...best.values()].map((f) => {
		const vuln = osvs.get(f.osv);
		const reachable = f.level === "symbol";
		const base = vuln ? osvSeverity(vuln) : "medium";
		const callerFile =
			f.caller?.file && reachable
				? joinRel(moduleDir, f.caller.file)
				: undefined;
		const stdlib = f.module === "stdlib";
		const where = f.pkg ?? f.module;
		const note = reachable
			? `Your code calls ${f.pkg}.${f.fn}${f.caller?.fn ? ` (from ${f.caller.fn})` : ""}, so the vulnerable code is reachable.`
			: f.level === "package"
				? `${where} is imported but the vulnerable function is not called by your code.`
				: `${f.module} is required but its vulnerable packages are not imported or called by your code.`;
		const fixed = f.fixed?.replace(/^v/, "");
		const finding = vulnFinding({
			auditor: "code.govulncheck",
			name: f.module,
			version: f.version,
			ecosystem: "Go",
			id: f.osv,
			aliases: vuln?.aliases,
			summary: vuln?.summary ?? f.osv,
			severity: reachable ? base : lower(base),
			fixed: fixed ? [f.fixed ?? fixed] : [],
			fixHint: stdlib
				? "Upgrade the Go toolchain to a release containing the fix."
				: undefined,
			file: callerFile ?? goMod,
			line: callerFile ? f.caller?.line : undefined,
			references: [
				`https://pkg.go.dev/vuln/${f.osv}`,
				...(vuln?.aliases ?? [])
					.filter((a) => a.startsWith("GHSA-"))
					.map(osvUrl),
			],
			confidence: reachable ? "high" : "low",
			note,
			tags: [reachable ? "reachable" : "not-called"],
		});
		return finding;
	});
};

export const govulncheck = defineAuditor({
	id: "code.govulncheck",
	title: "govulncheck (Go vulnerabilities)",
	description:
		"Runs govulncheck over each Go module. Findings whose vulnerable function is actually called are high-confidence; imported-but-not-called ones are low-confidence and one severity lower. govulncheck loads packages with the Go toolchain (no code is executed, cgo is disabled, toolchain downloads are blocked), so it is opt-in.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "govulncheck",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const mods = yield* findFiles(ctx, (p) => baseOf(p) === "go.mod");
			if (!mods.length) return yield* skip("No go.mod found");
			const bin = yield* requireTool(
				ctx,
				"govulncheck",
				"Install: go install golang.org/x/vuln/cmd/govulncheck@latest.",
			);
			const findings: FindingInput[] = [];
			for (const mod of mods) {
				const dir = dirOf(mod);
				// Exit 0 even with findings in JSON mode; 3 = vulnerabilities (text mode).
				const res = yield* run(ctx, [bin, "-format", "json", "./..."], {
					cwd: ws.absolute(dir || "."),
					okCodes: [0, 3],
					env: { GOTOOLCHAIN: "local", CGO_ENABLED: "0" },
				});
				findings.push(...parseGovulncheckReport(res.stdout, ws.root, dir));
			}
			return findings;
		}),
});
