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
import type { AdvisoryId, FilePath, FileText, RootPath } from "./report";
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

interface StreamState {
	level: number;
	start: number;
	inString: boolean;
	escaped: boolean;
}

/** Steps over one character inside a JSON string. */
const stepString = (s: StreamState, c: string | undefined): void => {
	if (s.escaped) s.escaped = false;
	else if (c === "\\") s.escaped = true;
	else if (c === '"') s.inString = false;
};

/** Steps over one character outside strings; true when it closes a top-level object. */
const closesObject = (
	s: StreamState,
	c: string | undefined,
	i: number,
): boolean => {
	if (s.level > 0 && c === '"') {
		s.inString = true;
		return false;
	}
	if (c === "{") {
		if (s.level === 0) s.start = i;
		s.level++;
		return false;
	}
	if (c !== "}" || s.level === 0) return false;
	s.level--;
	return s.level === 0 && s.start >= 0;
};

const pushParsed = (out: unknown[], chunk: string): void => {
	try {
		out.push(JSON.parse(chunk));
	} catch {
		// Truncated or corrupt message: skip it.
	}
};

/** Splits a stream of concatenated JSON objects (govulncheck's output). */
export const splitJsonStream = (text: FileText): unknown[] => {
	const out: unknown[] = [];
	const s: StreamState = {
		level: 0,
		start: -1,
		inString: false,
		escaped: false,
	};
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (s.inString) stepString(s, c);
		else if (closesObject(s, c, i)) {
			pushParsed(out, text.slice(s.start, i + 1));
			s.start = -1;
		}
	}
	return out;
};

type GoLevel = "module" | "package" | "symbol";
const GO_LEVELS: ReadonlyArray<GoLevel> = ["module", "package", "symbol"];

interface GoCaller {
	readonly file?: string;
	readonly line?: number;
	readonly fn?: string;
}

interface GoFinding {
	readonly level: GoLevel;
	readonly osv: string;
	readonly fixed?: string;
	readonly module: string;
	readonly version?: string;
	readonly pkg?: string;
	readonly fn?: string;
	/** Where the main module reaches the vulnerable symbol. */
	readonly caller?: GoCaller;
}

type GoFrame = Record<string, unknown>;

const goLevelOf = (top: GoFrame): GoLevel => {
	if (str(top.function)) return "symbol";
	return str(top.package) ? "package" : "module";
};

const goFunctionName = (top: GoFrame): string | undefined =>
	str(top.function)
		? `${str(top.receiver) ? `${str(top.receiver)}.` : ""}${str(top.function)}`
		: undefined;

/** The last frame with a position is the entry point in the user's own module. */
const goCaller = (trace: ReadonlyArray<GoFrame>): GoCaller | undefined => {
	const entry = [...trace].reverse().find((f) => isRecord(f.position));
	if (!entry || !isRecord(entry.position)) return undefined;
	const pos = entry.position;
	return {
		file: str(pos.filename),
		line: num(pos.line),
		fn: str(entry.function),
	};
};

const goFinding = (raw: Record<string, unknown>): GoFinding | undefined => {
	const osv = str(raw.osv);
	const trace = arr(raw.trace).filter(isRecord);
	const top = trace[0];
	if (!osv || !top) return undefined;
	return {
		level: goLevelOf(top),
		osv,
		fixed: str(raw.fixed_version),
		module: str(top.module) ?? "unknown",
		version: str(top.version),
		pkg: str(top.package),
		fn: goFunctionName(top),
		caller: goCaller(trace),
	};
};

/** Keeps the most specific finding per advisory and module. */
const keepBest = (best: Map<string, GoFinding>, f: GoFinding): void => {
	const key = `${f.osv}|${f.module}`;
	const prev = best.get(key);
	if (!prev || GO_LEVELS.indexOf(f.level) > GO_LEVELS.indexOf(prev.level))
		best.set(key, f);
};

const keepFinding = (
	best: Map<string, GoFinding>,
	raw: Record<string, unknown>,
): void => {
	const f = goFinding(raw);
	if (f) keepBest(best, f);
};

/** Records one govulncheck message: an OSV entry or a finding. */
const readGoMessage = (
	msg: unknown,
	osvs: Map<string, OsvVuln>,
	best: Map<string, GoFinding>,
): void => {
	if (!isRecord(msg)) return;
	if (isRecord(msg.osv) && typeof msg.osv.id === "string")
		osvs.set(msg.osv.id, msg.osv as unknown as OsvVuln);
	else if (isRecord(msg.finding)) keepFinding(best, msg.finding);
};

const readGoStream = (stdout: FileText) => {
	const osvs = new Map<string, OsvVuln>();
	const best = new Map<string, GoFinding>();
	for (const msg of splitJsonStream(stdout)) readGoMessage(msg, osvs, best);
	return { osvs, findings: [...best.values()] };
};

const goNote = (f: GoFinding): string => {
	if (f.level === "symbol")
		return `Your code calls ${f.pkg}.${f.fn}${f.caller?.fn ? ` (from ${f.caller.fn})` : ""}, so the vulnerable code is reachable.`;
	if (f.level === "package")
		return `${f.pkg ?? f.module} is imported but the vulnerable function is not called by your code.`;
	return `${f.module} is required but its vulnerable packages are not imported or called by your code.`;
};

const goCallerFile = (f: GoFinding, moduleDir: FilePath) =>
	f.caller?.file && f.level === "symbol"
		? joinRel(moduleDir, f.caller.file)
		: undefined;

/** Reachable findings point at the calling line; the rest at go.mod. */
const goLocation = (f: GoFinding, moduleDir: FilePath) => {
	const callerFile = goCallerFile(f, moduleDir);
	return callerFile
		? { file: callerFile, line: f.caller?.line }
		: { file: joinRel(moduleDir, "go.mod"), line: undefined };
};

/** Imported-but-not-called findings are one severity step lower, with low confidence. */
const goReach = (f: GoFinding, vuln: OsvVuln | undefined) => {
	const base = vuln ? osvSeverity(vuln) : "medium";
	return f.level === "symbol"
		? { severity: base, confidence: "high" as const, tags: ["reachable"] }
		: {
				severity: lower(base),
				confidence: "low" as const,
				tags: ["not-called"],
			};
};

const goReferences = (id: AdvisoryId, vuln: OsvVuln | undefined) => [
	`https://pkg.go.dev/vuln/${id}`,
	...(vuln?.aliases ?? []).filter((a) => a.startsWith("GHSA-")).map(osvUrl),
];

const goVulnFinding = (
	f: GoFinding,
	vuln: OsvVuln | undefined,
	moduleDir: FilePath,
): FindingInput => {
	const fixed = f.fixed?.replace(/^v/, "");
	return vulnFinding({
		auditor: "code.govulncheck",
		name: f.module,
		version: f.version,
		ecosystem: "Go",
		id: f.osv,
		aliases: vuln?.aliases,
		summary: vuln?.summary ?? f.osv,
		fixed: fixed ? [f.fixed ?? fixed] : [],
		fixHint:
			f.module === "stdlib"
				? "Upgrade the Go toolchain to a release containing the fix."
				: undefined,
		...goLocation(f, moduleDir),
		...goReach(f, vuln),
		references: goReferences(f.osv, vuln),
		note: goNote(f),
	});
};

/**
 * Parses `govulncheck -format json` (a stream of `config`/`osv`/`finding`
 * messages). Symbol-level findings (the vulnerable function is reachable) are
 * high-confidence; module/package-level ones are imported-but-not-called, so
 * they are reported one severity step lower with low confidence.
 */
export const parseGovulncheckReport = (
	stdout: FileText,
	_root: RootPath,
	moduleDir: FilePath = "",
): FindingInput[] => {
	const { osvs, findings } = readGoStream(stdout);
	return findings.map((f) => goVulnFinding(f, osvs.get(f.osv), moduleDir));
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
