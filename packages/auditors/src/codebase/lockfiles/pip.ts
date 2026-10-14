import type { FindingInput } from "@openaudit/core";

import { baseName, cweUrl, owaspUrl, type SourceFile, truncate } from "../util";
import {
	base,
	capPerRule,
	gitFinding,
	insecureFinding,
	PIP_CONFUSION,
	PIP_INSTALL,
	pathFinding,
	rule,
	tlsFinding,
} from "./findings";
import { dirOf, stripBom, unquote } from "./shared";
import {
	displayHost,
	displayUrl,
	escapesRoot,
	hostOf,
	isInsecureUrl,
	maskTokens,
	onPypi,
	resolveInRepo,
} from "./sources";

/*                               Python, Composer                             */

/** Long options pip accepts in requirements files (optparse also takes unique prefixes). */
const PIP_LONG_OPTIONS = [
	"--index-url",
	"--extra-index-url",
	"--no-index",
	"--find-links",
	"--trusted-host",
	"--requirement",
	"--constraint",
	"--editable",
	"--no-binary",
	"--only-binary",
	"--prefer-binary",
	"--require-hashes",
	"--pre",
	"--use-feature",
	"--global-option",
	"--config-settings",
	"--hash",
];

const PIP_SHORT_OPTIONS: Readonly<Record<string, string>> = {
	"-i": "--index-url",
	"-f": "--find-links",
	"-r": "--requirement",
	"-c": "--constraint",
	"-e": "--editable",
};

/** Options whose value is a source or file. */
const PIP_VALUE_OPTIONS = new Set([
	"--index-url",
	"--extra-index-url",
	"--find-links",
	"--trusted-host",
	"--requirement",
	"--constraint",
	"--editable",
	"--no-binary",
	"--only-binary",
	"--use-feature",
	"--global-option",
	"--config-settings",
	"--hash",
]);

/** optparse's long-option matching: exact, else a unique prefix. */
const pipLongOption = (name: string): string | undefined => {
	if (PIP_LONG_OPTIONS.includes(name)) return name;
	const matches = PIP_LONG_OPTIONS.filter((o) => o.startsWith(name));
	return matches.length === 1 ? matches[0] : undefined;
};

/** Logical lines of a requirements file (`\` continuations joined), with start lines. */
const logicalLines = (text: string): Array<readonly [string, number]> => {
	const out: Array<readonly [string, number]> = [];
	let buffer = "";
	let start = 0;
	text.split(/\r\n|\r|\n/).forEach((line, i) => {
		if (!buffer) start = i + 1;
		if (line.endsWith("\\")) {
			buffer += `${line.slice(0, -1)} `;
			return;
		}
		out.push([buffer + line, start]);
		buffer = "";
	});
	if (buffer) out.push([buffer, start]);
	return out;
};

const pipSourceFinding = (
	file: string,
	line: number,
	what: string,
	url: string,
	why: string,
): FindingInput => {
	const shown = displayUrl(url);
	const parsed = hostOf(url);
	const host = parsed ? displayHost(url, parsed) : "an unknown host";
	return {
		...base,
		ruleId: rule("unexpected-host"),
		title: truncate(`${what} is downloaded from ${host}`, 120),
		severity: "medium",
		message: truncate(
			`${file} makes pip download ${what} from ${shown}, ${why}. It bypasses the package index, so the index's provenance and any --require-hashes pinning of index packages do not cover it.`,
			600,
		),
		location: { file, line },
		evidence: truncate(`${what}: ${shown}`),
		remediation:
			"Publish the package to PyPI or your private index and require it by version, or pin the download with --hash.",
		references: [PIP_INSTALL, cweUrl(829), owaspUrl("a08")],
		tags: ["cwe-829", "owasp-a08"],
	};
};

/** A VCS, URL or path requirement (`name @ url`, a bare URL, `-e url`). */
const pipDirectReference = (
	file: SourceFile,
	line: number,
	name: string,
	url: string,
): FindingInput | undefined => {
	const lower = url.toLowerCase();
	const what = name || "a direct reference";
	const evidence = `${what}: ${displayUrl(url)}`;
	if (isInsecureUrl(url))
		return insecureFinding(file.path, line, what, evidence);
	const vcs = /^(git|hg|svn|bzr)\+/.exec(lower);
	if (vcs) {
		const bare = url.slice(vcs[0].length);
		const host = displayHost(bare, hostOf(bare) ?? "");
		let path = bare;
		try {
			path = new URL(bare).pathname;
		} catch {
			// scp-like spec: keep it whole.
		}
		const hash = path.indexOf("#");
		const at = path.lastIndexOf("@");
		const ref =
			at === -1
				? undefined
				: path.slice(at + 1, hash === -1 ? undefined : hash);
		return gitFinding(
			file.path,
			line,
			what,
			evidence,
			ref !== undefined && /^[0-9a-f]{40}$/i.test(ref),
			ref
				? `${displayUrl(url)} at "${truncate(maskTokens(ref), 60)}"`
				: displayUrl(url),
			host,
		);
	}
	if (lower.startsWith("https://")) {
		return onPypi(url)
			? undefined
			: pipSourceFinding(
					file.path,
					line,
					what,
					url,
					"not the Python Package Index",
				);
	}
	if (lower.startsWith("file:")) {
		// `file://host/path` (localhost included) names an absolute path.
		const path = url.slice("file:".length);
		return path.startsWith("//") || escapesRoot(dirOf(file.path), path)
			? pathFinding(file.path, line, what, evidence)
			: undefined;
	}
	return undefined;
};

const isUrlValue = (value: string) => /^[a-z][a-z0-9+.-]*:\/\//i.test(value);

/** `--index-url`, `--extra-index-url` and `--find-links`. */
const sourceOptionFindings = (
	file: SourceFile,
	line: number,
	option: string,
	value: string,
	evidence: string,
): FindingInput[] => {
	const out: FindingInput[] = [];
	if (isInsecureUrl(value))
		out.push(
			insecureFinding(
				file.path,
				line,
				`The package source ${displayUrl(value)}`,
				evidence,
			),
		);
	const host = hostOf(value);
	if (option === "--index-url") {
		if (host && !onPypi(value) && !isInsecureUrl(value))
			out.push({
				...base,
				ruleId: rule("custom-registry"),
				title: truncate(
					`${baseName(file.path)} installs packages from ${displayHost(value, host)}`,
					120,
				),
				severity: "info",
				message: truncate(
					`${file.path} sets ${displayUrl(value)} as pip's package index. Whoever runs that index decides what gets installed, and the setting lives in the repository, so a change to it deserves the same review as a change to the code.`,
					600,
				),
				location: { file: file.path, line },
				evidence,
				remediation:
					"Confirm the host is your organisation's index. Keep index settings in pip.conf or CI where possible, and review changes to them.",
				references: [PIP_INSTALL],
				tags: ["registry"],
			});
		return out;
	}
	if (option === "--extra-index-url" || isUrlValue(value))
		out.push({
			...base,
			ruleId: rule("extra-index-url"),
			title:
				option === "--find-links"
					? "pip searches extra package links"
					: "pip searches an extra package index",
			severity: "medium",
			message: truncate(
				`${file.path} adds ${displayUrl(value)} with ${option}. pip treats every index and link page as equal and installs the highest version it finds on any of them, so a public package with the same name as an internal one (dependency confusion) can win.`,
				500,
			),
			location: { file: file.path, line },
			evidence,
			remediation:
				"Use a single --index-url that proxies PyPI and your private packages (devpi, Artifactory, Nexus, CodeArtifact), or pin every package with --require-hashes.",
			references: [PIP_INSTALL, PIP_CONFUSION, cweUrl(427)],
			tags: ["cwe-427", "owasp-a08"],
		});
	return out;
};

/** `--requirement` and `--constraint`: a finding, or a local file to include. */
const includeOptionFinding = (
	file: SourceFile,
	line: number,
	option: string,
	value: string,
	evidence: string,
): FindingInput | string => {
	const what = option.slice(2);
	if (isInsecureUrl(value))
		return insecureFinding(
			file.path,
			line,
			`The ${what} file ${displayUrl(value)}`,
			evidence,
		);
	if (isUrlValue(value))
		return pipSourceFinding(
			file.path,
			line,
			`the ${what} file`,
			value,
			"a remote file whose contents can change between installs",
		);
	if (resolveInRepo(dirOf(file.path), value) === undefined)
		return pathFinding(
			file.path,
			line,
			`The ${what} file ${truncate(value, 60)}`,
			`${what} file: ${truncate(value, 120)}`,
		);
	return value;
};

/** Findings for one option with a value; local includes go to `includes`. */
const optionFindings = (
	file: SourceFile,
	line: number,
	option: string,
	value: string,
	includes: string[],
): FindingInput[] => {
	const evidence = `${option} ${displayUrl(value)}`;
	switch (option) {
		case "--trusted-host":
			return [
				tlsFinding(
					{ file: file.path, line, evidence },
					`pip (host ${truncate(displayUrl(value), 60)})`,
				),
			];
		case "--index-url":
		case "--extra-index-url":
		case "--find-links":
			return sourceOptionFindings(file, line, option, value, evidence);
		case "--requirement":
		case "--constraint": {
			const f = includeOptionFinding(file, line, option, value, evidence);
			if (typeof f !== "string") return [f];
			includes.push(f);
			return [];
		}
		case "--editable": {
			const f = isUrlValue(value)
				? pipDirectReference(file, line, "", value)
				: undefined;
			return f ? [f] : [];
		}
		default:
			return [];
	}
};

/** The option at `tokens[t]` and its value, and the index of the last token used. */
const pipOption = (
	tokens: ReadonlyArray<string>,
	t: number,
): { option?: string; value?: string; next: number } => {
	const token = tokens[t] ?? "";
	if (token.startsWith("--")) {
		const eq = token.indexOf("=");
		const option = pipLongOption(eq === -1 ? token : token.slice(0, eq));
		if (eq !== -1) return { option, value: token.slice(eq + 1), next: t };
		return option && PIP_VALUE_OPTIONS.has(option)
			? { option, value: tokens[t + 1], next: t + 1 }
			: { option, next: t };
	}
	const short = token.startsWith("-")
		? PIP_SHORT_OPTIONS[token.slice(0, 2)]
		: undefined;
	if (!short) return { next: t };
	return token.length > 2
		? { option: short, value: token.slice(2), next: t }
		: { option: short, value: tokens[t + 1], next: t + 1 };
};

/** A requirement token: `name @ url`, `name@url`, `@ url` or a bare URL. */
const requirementFinding = (
	file: SourceFile,
	line: number,
	tokens: ReadonlyArray<string>,
	t: number,
): FindingInput | undefined => {
	const token = tokens[t] ?? "";
	if (token === "@" || !token.includes("://")) return undefined;
	const scheme = token.indexOf("://");
	const at = token.lastIndexOf("@", scheme);
	const url = at === -1 ? token : token.slice(at + 1);
	const name =
		at > 0
			? token.slice(0, at)
			: at === 0 || tokens[t - 1] === "@"
				? (tokens[t - (at === 0 ? 1 : 2)] ?? "")
				: "";
	return pipDirectReference(file, line, name, url);
};

/**
 * pip requirements and constraints files: index and link options, included
 * files, and direct references. `includes` lists local `-r`/`-c` files for
 * the caller to read and check too.
 */
export const requirementsFindings = (
	file: SourceFile,
): { readonly findings: FindingInput[]; readonly includes: string[] } => {
	const out: FindingInput[] = [];
	const includes: string[] = [];
	for (const [raw, line] of logicalLines(stripBom(file.text))) {
		const hash = raw.search(/(^|\s)#/);
		const tokens = (hash === -1 ? raw : raw.slice(0, hash))
			.trim()
			.split(/\s+/)
			.filter(Boolean);
		for (let t = 0; t < tokens.length; t++) {
			const { option, value, next } = pipOption(tokens, t);
			if (option === undefined) {
				const f = requirementFinding(file, line, tokens, t);
				if (f) out.push(f);
				continue;
			}
			t = next;
			if (value !== undefined)
				out.push(...optionFindings(file, line, option, value, includes));
		}
	}
	return { findings: capPerRule(out), includes };
};

/** Pipfile `[[source]]` blocks. */
export const pipfileFindings = (file: SourceFile): FindingInput[] => {
	const out: FindingInput[] = [];
	let inSource = false;
	file.text.split("\n").forEach((raw, i) => {
		const t = raw.trim();
		if (t.startsWith("[")) {
			inSource = t.replace(/\s+/g, "") === "[[source]]";
			return;
		}
		if (!inSource) return;
		const eq = t.indexOf("=");
		if (eq === -1) return;
		const key = t.slice(0, eq).trim();
		const value = unquote(t.slice(eq + 1).trim());
		if (key === "url" && isInsecureUrl(value))
			out.push(
				insecureFinding(
					file.path,
					i + 1,
					`The package index ${displayUrl(value)}`,
					`url = ${displayUrl(value)}`,
				),
			);
		else if (key === "verify_ssl" && value.toLowerCase() === "false")
			out.push(
				tlsFinding({ file: file.path, line: i + 1, evidence: t }, "pipenv"),
			);
	});
	return out;
};
