import { isAbsolute, relative } from "node:path";
import {
	type AuditContext,
	type AuditorError,
	type FindingInput,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { runCommand, withTempDir as withScratchDir } from "../../tool";

/* -------------------------------------------------------------------------- */
/*                                   Shared                                   */
/* -------------------------------------------------------------------------- */

const MAX_ROOTS = 5;
export const NPM_REGISTRY = "https://registry.npmjs.org/";

const STEPS: ReadonlyArray<Severity> = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
];
/** `steps` levels less severe (floored at info). */
export const lower = (sev: Severity, steps = 1): Severity =>
	STEPS[Math.min(STEPS.indexOf(sev) + steps, STEPS.length - 1)] ?? "info";

export const dirOf = (path: string) =>
	path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
export const joinRel = (dir: string, file: string) =>
	dir ? `${dir}/${file}` : file;
export const baseOf = (path: string) => path.slice(path.lastIndexOf("/") + 1);
const depth = (path: string) => path.split("/").length;

/** Workspace files matching `test`, shallowest first, capped. */
export const findFiles = (
	ctx: AuditContext,
	test: (path: string) => boolean,
	max = MAX_ROOTS,
) =>
	Effect.gen(function* () {
		const ws = yield* requireWorkspace(ctx);
		const files = yield* ws.files;
		return files
			.filter(test)
			.sort((a, b) => depth(a) - depth(b) || a.localeCompare(b))
			.slice(0, max);
	});

/** Runs `fn` with a scratch directory that is always removed afterwards. */
export const withTempDir = <A, E>(
	fn: (dir: string) => Effect.Effect<A, E>,
): Effect.Effect<A, E | AuditorError> => withScratchDir("openaudit-sc-", fn);

/** Runs a tool; fails with its output unless the exit code is in `okCodes`. */
export const run = runCommand;

export const advisoryTags = (ids: ReadonlyArray<string>) =>
	ids.filter((a) => /^(CVE|GHSA)-/i.test(a)).map((a) => a.toLowerCase());

/** `<4.17.21` / `>=1.0.0 <1.2.3` → `4.17.21` / `1.2.3`; `<=` has no fix. */
export const fixedFromRange = (
	range: string | undefined,
): string | undefined => {
	const m = range ? /<\s*(\d[^\s|]*)\s*$/.exec(range.trim()) : null;
	return m?.[1];
};
/** Patched ranges such as `>=1.2.3` → `1.2.3`. */
export const fixedFromPatched = (
	patched: string | undefined,
): string | undefined => {
	const m = patched ? /^>=\s*(\d\S*)/.exec(patched.trim()) : null;
	return m?.[1];
};
export const ghsaOf = (url: string | undefined) =>
	url ? /GHSA(?:-[a-z0-9]{4}){3}/i.exec(url)?.[0] : undefined;

interface VulnInput {
	readonly auditor: string;
	readonly name: string;
	readonly version?: string;
	readonly ecosystem?: string;
	readonly id: string;
	readonly aliases?: ReadonlyArray<string>;
	readonly summary: string;
	readonly severity: Severity;
	readonly fixed: ReadonlyArray<string>;
	/** Used instead of the "no fix" sentence when `fixed` is empty. */
	readonly fixHint?: string;
	readonly file?: string;
	readonly line?: number;
	readonly references: ReadonlyArray<string>;
	readonly confidence?: FindingInput["confidence"];
	readonly note?: string;
	readonly tags?: ReadonlyArray<string>;
}

/** One finding in the shape of `code.osv-scanner`'s vulnerable-dependency. */
export const vulnFinding = (v: VulnInput): FindingInput => {
	const aliases = [...new Set(v.aliases ?? [])].filter((a) => a !== v.id);
	const at = v.version ? `${v.name}@${v.version}` : v.name;
	return {
		ruleId: `${v.auditor}/vulnerable-dependency`,
		title: `${at}: ${v.summary}`,
		severity: v.severity,
		category: "supply-chain",
		message: `${v.name}${v.version ? ` ${v.version}` : ""}${v.ecosystem ? ` (${v.ecosystem})` : ""} is affected by ${v.id}${aliases.length ? ` (${aliases.slice(0, 3).join(", ")})` : ""}.${v.note ? ` ${v.note}` : ""}`,
		location: { file: v.file, line: v.line },
		evidence: `${at} ${v.id}`,
		remediation: v.fixed.length
			? `Upgrade ${v.name} to ${[...new Set(v.fixed)].join(" or ")} or later.`
			: (v.fixHint ??
				`No fixed version is published for ${v.name}; consider replacing it or mitigating per the advisory.`),
		references: [...new Set(v.references)],
		confidence: v.confidence ?? "high",
		tags: [
			...new Set([
				"owasp-a06",
				...advisoryTags([v.id, ...aliases]),
				...(v.tags ?? []),
			]),
		],
	};
};

export const osvUrl = (id: string) => `https://osv.dev/vulnerability/${id}`;

/** Path as reported by scanners that root their output at `/`. */
export const scanPath = (root: string, file: string | undefined) => {
	if (!file) return undefined;
	if (isAbsolute(file) && file.startsWith(root))
		return relative(root, file).split("\\").join("/");
	return file.replace(/^\.?\/+/, "");
};
