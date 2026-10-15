import type { FindingInput } from "@openaudit/core";

import { baseName, cweUrl, owaspUrl, type SourceFile, truncate } from "../util";
import {
	base,
	capPerRule,
	type FindingSite,
	gitFinding,
	insecureFinding,
	PIP_CONFUSION,
	PIP_INSTALL,
	pathFinding,
	rule,
	tlsFinding,
} from "./findings";
import { scrubText } from "./scrub";
import { dirOf, stripBom, unquote } from "./shared";
import {
	displayHost,
	displayUrl,
	escapesRoot,
	hostOf,
	isInsecureUrl,
	onPypi,
	parseUrl,
	resolveInRepo,
} from "./sources";
import type {
	FilePath,
	FileText,
	Host,
	PackageName,
	TextLine,
	Url,
} from "./types";

/*                               Python, Composer                             */

/** A pip option name such as `--index-url`, or a prefix of one. */
type PipOptionName = string;

/** The whitespace-separated tokens of a requirements line, and an index into them. */
type Tokens = ReadonlyArray<string>;
type TokenIndex = number;

/** Where in a requirements file a finding points. */
interface PipSite {
	readonly file: SourceFile;
	readonly line: number;
}

const siteOf = (at: PipSite): FindingSite => ({
	file: at.file.path,
	line: at.line,
});

/** An option with a value, and the evidence to show for it. */
interface PipArg {
	readonly option: PipOptionName;
	readonly value: string;
	readonly evidence: string;
}

/** A requirement installed from outside the package index. */
interface DirectRef {
	readonly what: string;
	readonly url: Url;
	readonly evidence: string;
}

/** A download that bypasses the package index, and why that matters. */
interface RemoteSource {
	readonly what: string;
	readonly url: Url;
	readonly why: string;
}

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
const pipLongOption = (name: PipOptionName): PipOptionName | undefined => {
	if (PIP_LONG_OPTIONS.includes(name)) return name;
	const matches = PIP_LONG_OPTIONS.filter((o) => o.startsWith(name));
	return matches.length === 1 ? matches[0] : undefined;
};

/** Logical lines of a requirements file (`\` continuations joined), with start lines. */
const logicalLines = (text: FileText): Array<readonly [string, number]> => {
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
	at: PipSite,
	{ what, url, why }: RemoteSource,
): FindingInput => {
	const file = at.file.path;
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
		location: { file, line: at.line },
		evidence: truncate(`${what}: ${shown}`),
		remediation:
			"Publish the package to PyPI or your private index and require it by version, or pin the download with --hash.",
		references: [PIP_INSTALL, cweUrl(829), owaspUrl("a08")],
		tags: ["cwe-829", "owasp-a08"],
	};
};

const VCS_PREFIX = /^(git|hg|svn|bzr)\+/;

/** The `@ref` of a VCS requirement (`git+https://host/repo@ref#egg=…`), if any. */
const vcsRef = (bare: Url): string | undefined => {
	// An scp-like spec does not parse: keep it whole.
	const path = parseUrl(bare)?.pathname ?? bare;
	const hash = path.indexOf("#");
	const at = path.lastIndexOf("@");
	return at === -1
		? undefined
		: path.slice(at + 1, hash === -1 ? undefined : hash);
};

/** A `git+`, `hg+`, `svn+` or `bzr+` requirement; `bare` is its URL without the prefix. */
const vcsFinding = (at: PipSite, ref: DirectRef, bare: Url): FindingInput => {
	const host = displayHost(bare, hostOf(bare) ?? "");
	const commit = vcsRef(bare);
	return gitFinding(siteOf(at), ref.what, ref.evidence, {
		pinned: commit !== undefined && /^[0-9a-f]{40}$/i.test(commit),
		how: commit
			? `${displayUrl(ref.url)} at "${truncate(scrubText(commit), 60)}"`
			: displayUrl(ref.url),
		host,
	});
};

/** A `file:` requirement: a finding when it leaves the repository. */
const fileReferenceFinding = (
	at: PipSite,
	ref: DirectRef,
): FindingInput | undefined => {
	// `file://host/path` (localhost included) names an absolute path.
	const path = ref.url.slice("file:".length);
	const outside =
		path.startsWith("//") || escapesRoot(dirOf(at.file.path), path);
	return outside ? pathFinding(siteOf(at), ref.what, ref.evidence) : undefined;
};

/** A VCS, URL or path requirement (`name @ url`, a bare URL, `-e url`). */
const pipDirectReference = (
	at: PipSite,
	name: PackageName,
	url: Url,
): FindingInput | undefined => {
	const lower = url.toLowerCase();
	const what = name || "a direct reference";
	const ref: DirectRef = { what, url, evidence: `${what}: ${displayUrl(url)}` };
	if (isInsecureUrl(url))
		return insecureFinding(siteOf(at), what, ref.evidence);
	const vcs = VCS_PREFIX.exec(lower);
	if (vcs) return vcsFinding(at, ref, url.slice(vcs[0].length));
	if (lower.startsWith("https://"))
		return onPypi(url)
			? undefined
			: pipSourceFinding(at, {
					what,
					url,
					why: "not the Python Package Index",
				});
	if (lower.startsWith("file:")) return fileReferenceFinding(at, ref);
	return undefined;
};

const isUrlValue = (value: Url) => /^[a-z][a-z0-9+.-]*:\/\//i.test(value);

/** A TLS index URL on a host other than PyPI. */
const isCustomIndex = (url: Url): boolean =>
	!onPypi(url) && !isInsecureUrl(url);

const customIndexFinding = (
	at: PipSite,
	{ value, evidence }: PipArg,
	host: Host,
): FindingInput => ({
	...base,
	ruleId: rule("custom-registry"),
	title: truncate(
		`${baseName(at.file.path)} installs packages from ${displayHost(value, host)}`,
		120,
	),
	severity: "info",
	message: truncate(
		`${at.file.path} sets ${displayUrl(value)} as pip's package index. Whoever runs that index decides what gets installed, and the setting lives in the repository, so a change to it deserves the same review as a change to the code.`,
		600,
	),
	location: { file: at.file.path, line: at.line },
	evidence,
	remediation:
		"Confirm the host is your organisation's index. Keep index settings in pip.conf or CI where possible, and review changes to them.",
	references: [PIP_INSTALL],
	tags: ["registry"],
});

const extraIndexFinding = (
	at: PipSite,
	{ option, value, evidence }: PipArg,
): FindingInput => ({
	...base,
	ruleId: rule("extra-index-url"),
	title:
		option === "--find-links"
			? "pip searches extra package links"
			: "pip searches an extra package index",
	severity: "medium",
	message: truncate(
		`${at.file.path} adds ${displayUrl(value)} with ${option}. pip treats every index and link page as equal and installs the highest version it finds on any of them, so a public package with the same name as an internal one (dependency confusion) can win.`,
		500,
	),
	location: { file: at.file.path, line: at.line },
	evidence,
	remediation:
		"Use a single --index-url that proxies PyPI and your private packages (devpi, Artifactory, Nexus, CodeArtifact), or pin every package with --require-hashes.",
	references: [PIP_INSTALL, PIP_CONFUSION, cweUrl(427)],
	tags: ["cwe-427", "owasp-a08"],
});

/** `--index-url`: the index replaces PyPI. */
const indexUrlFindings = (at: PipSite, arg: PipArg): FindingInput[] => {
	const host = hostOf(arg.value);
	return host && isCustomIndex(arg.value)
		? [customIndexFinding(at, arg, host)]
		: [];
};

/** `--extra-index-url` and `--find-links`: sources searched next to the index. */
const extraSourceFindings = (at: PipSite, arg: PipArg): FindingInput[] =>
	arg.option === "--extra-index-url" || isUrlValue(arg.value)
		? [extraIndexFinding(at, arg)]
		: [];

/** `--index-url`, `--extra-index-url` and `--find-links`. */
const sourceOptionFindings = (at: PipSite, arg: PipArg): FindingInput[] => {
	const insecure = isInsecureUrl(arg.value)
		? [
				insecureFinding(
					siteOf(at),
					`The package source ${displayUrl(arg.value)}`,
					arg.evidence,
				),
			]
		: [];
	return arg.option === "--index-url"
		? [...insecure, ...indexUrlFindings(at, arg)]
		: [...insecure, ...extraSourceFindings(at, arg)];
};

/** `--requirement` and `--constraint`: a finding, or a local file to include. */
const includeOptionFinding = (
	at: PipSite,
	{ option, value, evidence }: PipArg,
): FindingInput | FilePath => {
	const what = option.slice(2);
	if (isInsecureUrl(value))
		return insecureFinding(
			siteOf(at),
			`The ${what} file ${displayUrl(value)}`,
			evidence,
		);
	if (isUrlValue(value))
		return pipSourceFinding(at, {
			what: `the ${what} file`,
			url: value,
			why: "a remote file whose contents can change between installs",
		});
	if (resolveInRepo(dirOf(at.file.path), value) === undefined)
		return pathFinding(
			siteOf(at),
			`The ${what} file ${truncate(value, 60)}`,
			`${what} file: ${truncate(value, 120)}`,
		);
	return value;
};

/** `--trusted-host`: pip skips TLS verification for the host. */
const trustedHostFindings = (at: PipSite, arg: PipArg): FindingInput[] => [
	tlsFinding(
		{ file: at.file.path, line: at.line, evidence: arg.evidence },
		`pip (host ${truncate(displayUrl(arg.value), 60)})`,
	),
];

const includeFindings = (
	at: PipSite,
	arg: PipArg,
	includes: FilePath[],
): FindingInput[] => {
	const f = includeOptionFinding(at, arg);
	if (typeof f !== "string") return [f];
	includes.push(f);
	return [];
};

/** `--editable`: a URL is a direct reference, a local path is not checked. */
const editableFindings = (at: PipSite, arg: PipArg): FindingInput[] => {
	const f = isUrlValue(arg.value)
		? pipDirectReference(at, "", arg.value)
		: undefined;
	return f ? [f] : [];
};

type OptionHandler = (
	at: PipSite,
	arg: PipArg,
	includes: FilePath[],
) => FindingInput[];

const OPTION_HANDLERS = new Map<PipOptionName, OptionHandler>([
	["--trusted-host", trustedHostFindings],
	["--index-url", sourceOptionFindings],
	["--extra-index-url", sourceOptionFindings],
	["--find-links", sourceOptionFindings],
	["--requirement", includeFindings],
	["--constraint", includeFindings],
	["--editable", editableFindings],
]);

/** Findings for one option with a value; local includes go to `includes`. */
const optionFindings = (
	at: PipSite,
	option: { readonly option: PipOptionName; readonly value: string },
	includes: FilePath[],
): FindingInput[] => {
	const arg = {
		...option,
		evidence: `${option.option} ${displayUrl(option.value)}`,
	};
	return OPTION_HANDLERS.get(arg.option)?.(at, arg, includes) ?? [];
};

/** A parsed option: its name and value, and the index of the last token used. */
interface ParsedOption {
	readonly option?: PipOptionName;
	readonly value?: string;
	readonly next: TokenIndex;
}

/** A `--name`, `--name=value` or `--name value` option at `tokens[t]`. */
const longPipOption = (tokens: Tokens, t: TokenIndex): ParsedOption => {
	const token = tokens[t] ?? "";
	const eq = token.indexOf("=");
	const option = pipLongOption(eq === -1 ? token : token.slice(0, eq));
	if (eq !== -1) return { option, value: token.slice(eq + 1), next: t };
	return option && PIP_VALUE_OPTIONS.has(option)
		? { option, value: tokens[t + 1], next: t + 1 }
		: { option, next: t };
};

/** The option at `tokens[t]` and its value, and the index of the last token used. */
const pipOption = (tokens: Tokens, t: TokenIndex): ParsedOption => {
	const token = tokens[t] ?? "";
	if (token.startsWith("--")) return longPipOption(tokens, t);
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
	at: PipSite,
	tokens: Tokens,
	t: TokenIndex,
): FindingInput | undefined => {
	const token = tokens[t] ?? "";
	if (token === "@" || !token.includes("://")) return undefined;
	const scheme = token.indexOf("://");
	const sep = token.lastIndexOf("@", scheme);
	const url = sep === -1 ? token : token.slice(sep + 1);
	const name =
		sep > 0
			? token.slice(0, sep)
			: sep === 0 || tokens[t - 1] === "@"
				? (tokens[t - (sep === 0 ? 1 : 2)] ?? "")
				: "";
	return pipDirectReference(at, name, url);
};

/** The tokens of a requirements line, without its comment. */
const lineTokens = (raw: TextLine): string[] => {
	const hash = raw.search(/(^|\s)#/);
	return (hash === -1 ? raw : raw.slice(0, hash))
		.trim()
		.split(/\s+/)
		.filter(Boolean);
};

/** Findings for one logical line; local includes go to `includes`. */
const lineFindings = (
	at: PipSite,
	raw: TextLine,
	includes: FilePath[],
): FindingInput[] => {
	const out: FindingInput[] = [];
	const tokens = lineTokens(raw);
	for (let t = 0; t < tokens.length; t++) {
		const { option, value, next } = pipOption(tokens, t);
		if (option === undefined) {
			const f = requirementFinding(at, tokens, t);
			if (f) out.push(f);
			continue;
		}
		t = next;
		if (value !== undefined)
			out.push(...optionFindings(at, { option, value }, includes));
	}
	return out;
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
	for (const [raw, line] of logicalLines(stripBom(file.text)))
		out.push(...lineFindings({ file, line }, raw, includes));
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
					{ file: file.path, line: i + 1 },
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
