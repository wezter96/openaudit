import {
	type FindingInput,
	type Severity,
	severityRank,
} from "@openaudit/core";

import { baseName, cweUrl, owaspUrl, truncate } from "../util";
import type { Setting } from "./config";
import {
	LOCKFILES_ID,
	type LockedPackage,
	MAX_FINDINGS_PER_RULE,
	type Problem,
} from "./shared";
import { KNOWN_GIT_HOSTS } from "./sources";

export const LOCKFILE_LINT = "https://github.com/lirantal/lockfile-lint";

export const NPM_LOCKFILE =
	"https://docs.npmjs.com/cli/configuring-npm/package-lock-json";

export const NPM_SCRIPTS = "https://docs.npmjs.com/cli/using-npm/scripts";

export const NPM_IGNORE_SCRIPTS =
	"https://docs.npmjs.com/cli/using-npm/config#ignore-scripts";

export const NPM_REGISTRY = "https://docs.npmjs.com/cli/using-npm/registry";

export const PNPM_BUILDS = "https://pnpm.io/settings#onlybuiltdependencies";

export const BUN_LIFECYCLE = "https://bun.sh/docs/install/lifecycle";

export const SOCKET_INSTALL_SCRIPTS =
	"https://socket.dev/npm/issue/installScripts";

export const PIP_INSTALL = "https://pip.pypa.io/en/stable/cli/pip_install/";

export const PIP_CONFUSION = "https://github.com/pypa/pip/issues/8606";

export const COMPOSER_CONFIG =
	"https://getcomposer.org/doc/06-config.md#secure-http";

export const COMPOSER_REPOS = "https://getcomposer.org/doc/05-repositories.md";

export const rule = (name: string) => `${LOCKFILES_ID}/${name}`;

export const base = {
	category: "supply-chain",
	confidence: "high",
} as const;

export const label = (p: LockedPackage) =>
	p.version ? `${p.name}@${p.version}` : p.name;

/** Names, at most `max`, joined for a message. */
export const listNames = (names: ReadonlyArray<string>, max = 10) =>
	`${names.slice(0, max).join(", ")}${names.length > max ? `, … (${names.length - max} more)` : ""}`;

export const unique = (xs: ReadonlyArray<string>) => [...new Set(xs)];

export const insecureFinding = (
	file: string,
	line: number | undefined,
	what: string,
	evidence: string,
	severity: Severity = "high",
): FindingInput => ({
	...base,
	ruleId: rule("insecure-protocol"),
	title: truncate(`${what} is fetched over an unencrypted connection`, 120),
	severity,
	message: truncate(
		`${what} is downloaded over ${evidence.toLowerCase().includes("git://") ? "the unencrypted git:// protocol" : "plain HTTP"}, so anyone on the network path can substitute the code that gets installed.`,
		500,
	),
	location: { file, line },
	evidence: truncate(evidence),
	remediation:
		"Use https:// (or git+https:// / git+ssh://) URLs for registries and dependencies, then regenerate the lockfile.",
	references: [LOCKFILE_LINT, cweUrl(319), cweUrl(494), owaspUrl("a08")],
	tags: ["cwe-319", "cwe-494", "owasp-a08"],
});

export const pathFinding = (
	file: string,
	line: number | undefined,
	name: string,
	evidence: string,
): FindingInput => ({
	...base,
	ruleId: rule("path-outside-workspace"),
	title: truncate(
		`${name} is installed from a path outside the repository`,
		120,
	),
	severity: "medium",
	message: truncate(
		`${name} resolves to a local path that leaves the repository. Installs then depend on whatever happens to be at that path on the machine, which a clean checkout cannot reproduce or review.`,
		500,
	),
	location: { file, line },
	evidence: truncate(evidence),
	remediation:
		"Move the package into the repository (as a workspace) or publish it to a registry, and depend on it from there.",
	references: [LOCKFILE_LINT, cweUrl(829)],
	tags: ["cwe-829"],
});

export const gitFinding = (
	file: string,
	line: number | undefined,
	name: string,
	evidence: string,
	pinned: boolean,
	how: string,
	host: string,
): FindingInput => {
	const knownHost = KNOWN_GIT_HOSTS.has(host);
	return {
		...base,
		ruleId: rule("git-dependency"),
		title: truncate(
			`${name} is installed from a git host instead of a registry`,
			120,
		),
		severity: pinned && knownHost ? "low" : "medium",
		message: truncate(
			`${name} is installed from ${how}. It bypasses the registry's integrity metadata, advisories and malware scanning${pinned ? "." : ", and the lockfile does not pin its content to a commit or hash, so the same lockfile can install different code tomorrow."}${knownHost ? "" : ` ${host || "The host"} is not one of the well-known git hosts (GitHub, GitLab, Bitbucket).`}`,
			600,
		),
		location: { file, line },
		evidence: truncate(evidence),
		remediation: pinned
			? "Prefer a published registry version. If the git dependency is needed, keep it pinned to a full commit SHA on a host you trust and review updates."
			: "Pin the dependency to a full commit SHA (or publish it to a registry) and regenerate the lockfile.",
		references: [LOCKFILE_LINT, cweUrl(829), ...(pinned ? [] : [cweUrl(1357)])],
		tags: ["cwe-829", ...(pinned ? [] : ["cwe-1357"])],
	};
};

/** A lockfile that was not checked at all (too large or unparseable). */
export const uncheckedFinding = (
	ruleName: "truncated" | "unparseable-lockfile",
	file: string,
	message: string,
): FindingInput => ({
	...base,
	ruleId: rule(ruleName),
	title: `${baseName(file)} was not checked`,
	// A lockfile the package manager may read but openaudit cannot is a
	// place to hide entries; an oversized one is more likely just large.
	severity: ruleName === "unparseable-lockfile" ? "medium" : "low",
	message: `${message} Its entries were not checked, but the package manager may still install from it.`,
	location: { file },
	evidence: file,
	remediation:
		"Regenerate the lockfile with the package manager and check it with lockfile-lint.",
	references: [LOCKFILE_LINT],
	tags: ["lockfile"],
});

/** A lockfile that was read, but not all of it. */
export const partlyCheckedFinding = (
	file: string,
	problem: Problem,
): FindingInput => ({
	...uncheckedFinding("unparseable-lockfile", file, ""),
	title: `${baseName(file)} was only partly checked`,
	severity: problem.severity,
	message: `${problem.reason} The rest of ${file} was checked.`,
	evidence: `${file}: ${problem.what}`,
});

/** A package-manager config (or manifest) that was not checked. */
export const unparsedConfigFinding = (
	file: string,
	reason: string,
): FindingInput => ({
	...base,
	ruleId: rule("unparseable-config"),
	title: `${baseName(file)} was not checked`,
	severity: "low",
	message: `${file} ${reason}, so the registries and install settings in it were not checked. A package manager that reads it differently may still apply them.`,
	location: { file },
	evidence: file,
	remediation:
		"Fix the file so it parses, or remove it if the package manager does not use it.",
	references: [NPM_REGISTRY, LOCKFILE_LINT],
	tags: ["lockfile"],
});

/**
 * Keeps the first `MAX_FINDINGS_PER_RULE` findings of each rule per file and
 * folds the rest into one finding of that rule at their highest severity.
 */
export const capPerRule = (
	findings: ReadonlyArray<FindingInput>,
): FindingInput[] => {
	const byRule = new Map<string, FindingInput[]>();
	for (const f of findings) {
		const key = `${f.ruleId}|${f.location?.file ?? ""}`;
		const group = byRule.get(key);
		if (group) group.push(f);
		else byRule.set(key, [f]);
	}
	const out: FindingInput[] = [];
	for (const group of byRule.values()) {
		out.push(...group.slice(0, MAX_FINDINGS_PER_RULE));
		const rest = group.slice(MAX_FINDINGS_PER_RULE);
		const first = rest[0];
		if (!first) continue;
		const severity = rest.reduce<Severity>(
			(s, f) => (severityRank(f.severity) < severityRank(s) ? f.severity : s),
			first.severity,
		);
		const items = rest.map((f) => f.evidence ?? f.title);
		out.push({
			...first,
			title: truncate(
				`${rest.length} more ${first.ruleId.split("/")[1]} findings in ${baseName(first.location?.file ?? "")}`,
				120,
			),
			severity,
			message: truncate(
				`Only the first ${MAX_FINDINGS_PER_RULE} findings of this rule are listed one by one. ${rest.length} more entries have the same problem: ${listNames(items)}.`,
				1000,
			),
			evidence: truncate(`${rest.length} more: ${items.join(", ")}`),
		});
	}
	return out;
};

export const tlsFinding = (s: Setting, who: string): FindingInput => ({
	...base,
	ruleId: rule("tls-verification-disabled"),
	title: `TLS certificate checks are disabled for ${who}`,
	severity: "medium",
	message: truncate(
		`${s.file} turns off certificate verification for ${who}, so a machine-in-the-middle can serve modified packages over a connection that still looks encrypted.`,
		500,
	),
	location: { file: s.file, line: s.line },
	evidence: truncate(s.evidence),
	remediation:
		"Remove the setting. For a private registry with an internal CA, trust that CA instead (npm cafile, NODE_EXTRA_CA_CERTS, pip --cert).",
	references: [cweUrl(295), LOCKFILE_LINT],
	tags: ["cwe-295"],
});
