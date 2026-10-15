import { type FindingInput, redact } from "@openaudit/core";

import {
	cweUrl,
	lineLocator,
	owaspLlmUrl,
	owaspUrl,
	type SourceFile,
	scrubLine,
	truncate,
} from "../util";
import { fallbackServers } from "./fallback";
import {
	fields,
	type JsonEntry,
	type JsonNode,
	parseJsoncDetailed,
} from "./json";
import {
	type Candidate,
	candidatesOf,
	type LiteralSecret,
	literalSecret,
} from "./mcp-credentials";
import {
	type LaunchedPackage,
	launchedPackages,
	npmName,
	type Token,
} from "./mcp-launch";
import { type Located, split, unwrap } from "./mcp-unwrap";
import {
	bestEffort,
	finding,
	GEMINI_CONFIG,
	MCP_SECURITY,
	unparsed,
} from "./shared";

export { type LaunchedPackage, launchedPackages } from "./mcp-launch";

/* -------------------------------------------------------------------------- */
/*                                 MCP servers                                */
/* -------------------------------------------------------------------------- */

/** One server entry. Duplicate names are separate entries. */
export interface McpServer {
	readonly name: string;
	readonly nameOffset: number;
	readonly node: JsonNode;
}

/** Text from the config, before it is made safe to print. */
type RawText = string;
/** A package name as a lockfile or manifest lists it. */
type PackageName = string;

/** Servers under every `mcpServers`, `servers` or `mcp_servers` table, duplicates included. */
export const serversIn = (root: JsonNode | undefined): McpServer[] =>
	["mcpServers", "servers", "mcp_servers"].flatMap((table) =>
		fields(root, table).flatMap((t) =>
			t.kind === "object"
				? t.entries
						.filter((e) => e.value.kind === "object")
						.map((e) => ({
							name: e.key,
							nameOffset: e.keyOffset,
							node: e.value,
						}))
				: [],
		),
	);

const stringsOf = (nodes: ReadonlyArray<JsonNode>): Located[] =>
	nodes.flatMap((n) =>
		n.kind === "string"
			? [{ value: n.value, offset: n.offset }]
			: n.kind === "array"
				? stringsOf(n.items)
				: [],
	);

/* -------------------------------------------------------------------------- */
/*                                   Output                                   */
/* -------------------------------------------------------------------------- */

/**
 * Text that is safe to print: URL userinfo (up to the last `@`, as WHATWG
 * parses it, with `\` as `/`) and every query, fragment and `;` parameter
 * value are masked, then known secrets and credential shapes are scrubbed.
 * Bounded quantifiers keep it linear on hostile input.
 */
export const safeText = (
	s: RawText,
	known: ReadonlyArray<string> = [],
): string =>
	scrubLine(
		s
			.replace(
				/([a-z][\w+.-]{0,30}:[\\/]{2})([^/\\?#\s]*)/gi,
				(_m, scheme: string, authority: string) => {
					const at = authority.lastIndexOf("@");
					return at === -1
						? `${scheme}${authority}`
						: `${scheme}****@${authority.slice(at + 1)}`;
				},
			)
			.replace(/([?&#;][^=&#;?\s]{0,200}=)[^&#;\s]*/g, "$1****"),
		known,
	);

/** Makes config text safe and short enough to print. */
type Clean = (s: RawText) => string;

const SUBCOMMANDS = new Set(["run", "exec", "x", "dlx", "tool", "container"]);

/**
 * The launch command up to the package, with flag values and other operands
 * replaced by `…`: `docker run -i -e … ghcr.io/org/mcp`. Values passed to
 * flags (`-e TOKEN=…`, `--index-url https://user:pass@…`) never appear.
 */
const launchEvidence = (
	tokens: ReadonlyArray<Token>,
	upTo: number,
	clean: Clean,
) =>
	truncate(
		tokens
			.slice(0, upTo + 1)
			.map((t, i) =>
				i === 0 || i === upTo
					? clean(t)
					: t.startsWith("-")
						? clean(t.replace(/=[\s\S]*$/, "=…"))
						: i <= 3 && SUBCOMMANDS.has(t)
							? t
							: "…",
			)
			.join(" "),
	);

const LOOPBACK =
	/^(?:localhost|.+\.localhost|127(?:\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0|host\.docker\.internal)$/i;

const REMOTE_INSTALL_REMEDIATION: Readonly<
	Record<LaunchedPackage["ecosystem"], string>
> = {
	npm: "Pin an exact version (`npx -y pkg@1.2.3`), or add the server as a dependency so the lockfile pins it with an integrity hash.",
	pypi: "Pin an exact version (`uvx pkg@1.2.3` or `uvx --from pkg==1.2.3 cmd`), or install it into a locked environment.",
	docker:
		"Pin the image by digest (`image@sha256:…`), or at least by a version tag.",
};

const isRemote = (url: URL) =>
	url.hostname !== "" && !LOOPBACK.test(url.hostname);

/** WHATWG-parsed http URL (leading spaces, tabs and case as a client sees them). */
const plainHttpHost = (value: RawText): string | undefined => {
	try {
		const url = new URL(value.trim());
		return url.protocol === "http:" && isRemote(url) ? url.hostname : undefined;
	} catch {
		return undefined;
	}
};

/** How to scan a file's servers. */
export interface McpScan {
	/** Packages the project itself depends on, which its lockfile pins. */
	readonly localPackages: ReadonlySet<PackageName>;
	/** Gemini CLI settings, where `trust: true` skips confirmations. */
	readonly gemini: boolean;
}

/** What every finding about one server needs. */
interface ServerContext extends McpScan {
	readonly path: string;
	readonly lineOf: (offset: number) => number;
	readonly clean: Clean;
	/** The server's name, safe to print. */
	readonly name: string;
}

interface Credential {
	readonly c: Candidate;
	readonly s: LiteralSecret;
}

/** Every literal credential in a server, once per offset and secret. */
const credentialsIn = (server: McpServer): Credential[] => {
	const seen = new Set<string>();
	return candidatesOf(server).flatMap((c) => {
		const s = literalSecret(c);
		const id = `${c.offset}:${s?.secret}`;
		if (!s || seen.has(id)) return [];
		seen.add(id);
		return [{ c, s }];
	});
};

/** A package one launch of the server fetches. */
interface Launch {
	readonly pkg: LaunchedPackage;
	readonly offset: number;
	readonly tokens: ReadonlyArray<Token>;
}

const launchOf = (command: Located, args: ReadonlyArray<Located>): Launch[] => {
	const located = unwrap([...split(command), ...args]);
	const tokens = located.map((t) => t.value);
	return launchedPackages(tokens).map((pkg) => ({
		pkg,
		offset: located[pkg.token]?.offset ?? command.offset,
		tokens,
	}));
};

/** Each `command` with each `args` list (or none). */
const launchesOf = (node: JsonNode): Launch[] => {
	const argLists = fields(node, "args").map((a) => stringsOf([a]));
	const lists = argLists.length > 0 ? argLists : [[]];
	return stringsOf(fields(node, "command")).flatMap((command) =>
		lists.flatMap((args) => launchOf(command, args)),
	);
};

/** npm packages the project depends on are pinned by its lockfile. */
const isLocal = (
	pkg: LaunchedPackage,
	localPackages: ReadonlySet<PackageName>,
) => pkg.ecosystem === "npm" && localPackages.has(npmName(pkg.spec));

const unpinnedFinding = (
	{ pkg, offset, tokens }: Launch,
	at: ServerContext,
): FindingInput =>
	finding("mcp-unpinned-server", at.path, at.lineOf(offset), {
		title: `MCP server "${at.name}" runs an unpinned ${pkg.ecosystem === "docker" ? "image" : "package"}`,
		severity: "medium",
		category: "supply-chain",
		message: `MCP server "${at.name}" launches \`${at.clean(pkg.spec)}\` without an exact version, so each start can fetch and run whatever the registry serves at that moment${pkg.autoYes ? " (-y installs it without asking)" : ""}. A compromised or hijacked release then runs with the agent's access to this machine.`,
		evidence: launchEvidence(tokens, pkg.token, at.clean),
		remediation: REMOTE_INSTALL_REMEDIATION[pkg.ecosystem],
		references: [
			owaspLlmUrl("llm03"),
			cweUrl(1357),
			`${MCP_SECURITY}#local-mcp-server-compromise`,
		],
		confidence: "high",
		tags: ["cwe-1357", "owasp-llm03"],
	});

const unpinnedFindings = (
	node: JsonNode,
	at: ServerContext,
): FindingInput[] => {
	const reported = new Set<string>();
	const findings: FindingInput[] = [];
	for (const launch of launchesOf(node)) {
		const { pkg } = launch;
		const id = `${launch.offset}:${pkg.spec}`;
		if (pkg.pinned || isLocal(pkg, at.localPackages)) continue;
		if (reported.has(id)) continue;
		reported.add(id);
		findings.push(unpinnedFinding(launch, at));
	}
	return findings;
};

const plaintextFinding = (
	url: Located,
	host: string,
	at: ServerContext,
): FindingInput =>
	finding("mcp-plaintext-http", at.path, at.lineOf(url.offset), {
		title: `MCP server "${at.name}" is reached over plain HTTP`,
		severity: "medium",
		category: "security",
		message: `MCP server "${at.name}" uses ${at.clean(host)} over http://, so tool calls, results and any credentials are sent unencrypted and can be read or altered on the network.`,
		evidence: at.clean(url.value),
		remediation:
			"Use https:// for every MCP server that is not on the loopback interface.",
		references: [cweUrl(319), owaspUrl("a02"), MCP_SECURITY],
		confidence: "high",
		tags: ["cwe-319", "owasp-a02"],
	});

const plaintextFindings = (node: JsonNode, at: ServerContext) =>
	stringsOf(
		["url", "httpUrl", "serverUrl"].flatMap((k) => fields(node, k)),
	).flatMap((url) => {
		const host = plainHttpHost(url.value);
		return host ? [plaintextFinding(url, host, at)] : [];
	});

const credentialFinding = (
	{ c, s }: Credential,
	at: ServerContext,
): FindingInput => {
	const where = at.clean(
		c.key && !c.where.endsWith(c.key) ? `${c.where} ${c.key}` : c.where,
	);
	return finding("mcp-inline-credential", at.path, at.lineOf(c.offset), {
		title: `${s.title} in MCP server config`,
		severity: s.severity,
		category: "security",
		message: `MCP server "${at.name}" has a literal credential in ${where}. Anyone who can read the repository can use it, and agents that read the config can leak it.`,
		evidence: `${where}: ${redact(s.secret)}`,
		remediation:
			// biome-ignore lint/suspicious/noTemplateCurlyInString: MCP config variable syntax
			"Revoke and rotate the credential, then reference an environment variable instead (`${VAR}` in .mcp.json, `${env:VAR}` in Cursor and VS Code, `env_vars`/`bearer_token_env_var` in Codex).",
		references: [cweUrl(798), owaspUrl("a07"), MCP_SECURITY],
		confidence: s.confidence,
		tags: ["cwe-798", "owasp-a07", "secrets"],
	});
};

const isTrustTrue = (e: JsonEntry) =>
	e.key === "trust" && e.value.kind === "scalar" && e.value.value === true;

const trustFindings = (node: JsonNode, at: ServerContext): FindingInput[] => {
	const trusted =
		node.kind === "object" ? node.entries.find(isTrustTrue) : undefined;
	if (!at.gemini || !trusted) return [];
	return [
		finding("mcp-server-trusted", at.path, at.lineOf(trusted.keyOffset), {
			title: `MCP server "${at.name}" bypasses tool confirmations`,
			severity: "medium",
			category: "security",
			message: `\`trust: true\` makes Gemini CLI run every tool of MCP server "${at.name}" without asking, so a prompt injection can drive that server unchecked.`,
			evidence: `mcpServers.${at.name}.trust: true`,
			remediation:
				"Remove `trust: true` and allow-list the specific read-only tools you need with `includeTools` or `tools.allowed`.",
			references: [owaspLlmUrl("llm06"), GEMINI_CONFIG],
			confidence: "high",
			tags: ["owasp-llm06"],
		}),
	];
};

export const scanServers = (
	file: SourceFile,
	servers: ReadonlyArray<McpServer>,
	scan: McpScan,
): FindingInput[] => {
	// Find every literal credential first, so no output string can repeat one.
	const credentials = servers.map(credentialsIn);
	const known = credentials.flat().map(({ s }) => s.secret);
	const clean: Clean = (s) => truncate(safeText(s.slice(0, 2000), known), 120);
	const base = {
		...scan,
		path: file.path,
		lineOf: lineLocator(file.text),
		clean,
	};
	return servers.flatMap((server, i) => {
		const at: ServerContext = { ...base, name: clean(server.name) };
		return [
			...unpinnedFindings(server.node, at),
			...plaintextFindings(server.node, at),
			...(credentials[i] ?? []).map((cred) => credentialFinding(cred, at)),
			...trustFindings(server.node, at),
		];
	});
};

export const scanMcpJson = (
	file: SourceFile,
	localPackages: ReadonlySet<PackageName>,
): FindingInput[] => {
	const scan = {
		localPackages,
		gemini: /(?:^|\/)\.gemini\/settings\.json$/i.test(file.path),
	};
	const parsed = parseJsoncDetailed(file.text);
	if (parsed.ok) return scanServers(file, serversIn(parsed.root), scan);
	if (file.text.trim() === "") return [];
	const line = lineLocator(file.text)(parsed.offset);
	return [
		unparsed(
			file.path,
			line,
			`is not valid JSON(C): ${parsed.reason} at line ${line}`,
		),
		...bestEffort(scanServers(file, fallbackServers(file.text, false), scan)),
	];
};
