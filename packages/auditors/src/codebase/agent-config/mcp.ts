import { type FindingInput, redact, type Severity } from "@openaudit/core";

import { isPlaceholder, SECRET_KEY_NAME, SECRET_RULES } from "../secrets";
import {
	baseName,
	cweUrl,
	lineLocator,
	owaspLlmUrl,
	owaspUrl,
	type SourceFile,
	scrubLine,
	shannonEntropy,
	truncate,
} from "../util";
import { fallbackServers } from "./fallback";
import { fields, type JsonNode, parseJsoncDetailed } from "./json";
import {
	bestEffort,
	finding,
	GEMINI_CONFIG,
	MCP_SECURITY,
	unparsed,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                 MCP servers                                */
/* -------------------------------------------------------------------------- */

/** One server entry. Duplicate names are separate entries. */
export interface McpServer {
	readonly name: string;
	readonly nameOffset: number;
	readonly node: JsonNode;
}

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

interface Located {
	readonly value: string;
	readonly offset: number;
}

const stringsOf = (nodes: ReadonlyArray<JsonNode>): Located[] =>
	nodes.flatMap((n) =>
		n.kind === "string"
			? [{ value: n.value, offset: n.offset }]
			: n.kind === "array"
				? stringsOf(n.items)
				: [],
	);

export interface LaunchedPackage {
	readonly launcher: string;
	readonly spec: string;
	/** Index of the spec among the launch tokens. */
	readonly token: number;
	readonly pinned: boolean;
	readonly ecosystem: "npm" | "pypi" | "docker";
	readonly autoYes: boolean;
}

const exeName = (t: string) =>
	baseName(t)
		.replace(/\.(?:cmd|exe|bat)$/i, "")
		.toLowerCase();

const EXACT_SEMVER =
	/^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const LOCAL_SPEC = /^(?:\.{0,2}\/|~|file:|link:|[A-Za-z]:\\)|\$/;

/** undefined for local or unresolvable specs, which nothing fetches. */
const npmPinned = (spec: string): boolean | undefined => {
	if (LOCAL_SPEC.test(spec) || /^https?:\/\//.test(spec)) return undefined;
	if (
		/^(?:git\+|git:|github:|gitlab:|bitbucket:)|^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(
			spec,
		)
	)
		return /#[0-9a-f]{40}$/i.test(spec);
	const at = spec.lastIndexOf("@");
	return at > 0 && EXACT_SEMVER.test(spec.slice(at + 1));
};

const npmName = (spec: string) => {
	const at = spec.lastIndexOf("@");
	return at > 0 ? spec.slice(0, at) : spec;
};

const pypiPinned = (spec: string): boolean | undefined => {
	if (
		LOCAL_SPEC.test(spec) ||
		/^https?:\/\//.test(spec) ||
		/\.(?:whl|tar\.gz|zip)$/.test(spec)
	)
		return undefined;
	if (/^git\+/.test(spec)) return /@[0-9a-f]{40}(?:#.*)?$/i.test(spec);
	return /^[\w.[\],-]+(?:===?\s*[\w.!+-]+|@\d[\w.!+-]*)$/.test(spec);
};

const imagePinned = (image: string): boolean | undefined => {
	if (image.includes("$")) return undefined;
	if (/@sha256:[0-9a-f]{64}$/i.test(image)) return true;
	const tagAt = image.indexOf(":", image.lastIndexOf("/") + 1);
	// Version tags contain a digit; latest, main, edge, stable… move.
	return tagAt !== -1 && /\d/.test(image.slice(tagAt + 1));
};

const DOCKER_VALUE_FLAGS = new Set(
	"-e --env --env-file -v --volume --mount -p --publish --name -u --user -w --workdir --network --net --entrypoint -l --label --platform --add-host --cap-add --cap-drop --security-opt -m --memory --cpus --pull --hostname -h --ulimit --tmpfs --device --log-driver --log-opt --restart --dns --ipc --pid --gpus --runtime --shm-size --stop-signal --userns --volumes-from --group-add --cidfile --label-file --expose --link".split(
		" ",
	),
);
const UV_VALUE_FLAGS = new Set(
	"--with --with-editable --with-requirements --python -p --index --index-url --extra-index-url --default-index --find-links -f --constraint -c --overrides --build-constraint".split(
		" ",
	),
);
const PIPX_VALUE_FLAGS = new Set(
	"--python --index-url -i --pip-args --backend".split(" "),
);

/** The package, distribution or image an MCP launch command fetches. */
export const launchedPackages = (
	tokens: ReadonlyArray<string>,
): LaunchedPackage[] => {
	const launcher = exeName(tokens[0] ?? "");
	const sub = tokens[1];
	const out: LaunchedPackage[] = [];
	const add = (
		ecosystem: LaunchedPackage["ecosystem"],
		token: number,
		autoYes = false,
	) => {
		const spec = tokens[token];
		if (spec === undefined) return;
		const pinned =
			ecosystem === "npm"
				? npmPinned(spec)
				: ecosystem === "pypi"
					? pypiPinned(spec)
					: imagePinned(spec);
		if (pinned !== undefined)
			out.push({
				launcher: tokens[0] ?? "",
				spec,
				token,
				pinned,
				ecosystem,
				autoYes,
			});
	};

	const npmLike = (from: number) => {
		let autoYes = false;
		let named = false;
		const packages: number[] = [];
		for (let i = from; i < tokens.length; i++) {
			const t = tokens[i] ?? "";
			if (t === "--") continue;
			if (t === "-y" || t === "--yes") autoYes = true;
			else if (t === "-p" || t === "--package") {
				packages.push(++i);
				named = true;
			} else if (t.startsWith("--package=")) named = true;
			else if (t === "-c" || t === "--call") i++;
			else if (!t.startsWith("-")) {
				if (!named) packages.push(i);
				break;
			}
		}
		for (const p of packages) add("npm", p, autoYes);
	};

	/** uvx/pipx: `--from`/`--spec` names the package, else the command does. */
	const valueFlagged = (
		from: number,
		valueFlags: ReadonlySet<string>,
		packageFlag: string,
	) => {
		const packages: number[] = [];
		let named = false;
		for (let i = from; i < tokens.length; i++) {
			const t = tokens[i] ?? "";
			if (t === packageFlag) {
				packages.push(++i);
				named = true;
			} else if (t === "--with") packages.push(++i);
			else if (valueFlags.has(t)) i++;
			else if (!t.startsWith("-")) {
				if (!named) packages.unshift(i);
				break;
			}
		}
		return packages;
	};

	if (launcher === "npx" || launcher === "bunx") npmLike(1);
	else if (launcher === "npm" && (sub === "exec" || sub === "x")) npmLike(2);
	else if ((launcher === "pnpm" || launcher === "yarn") && sub === "dlx")
		npmLike(2);
	else if (launcher === "bun" && sub === "x") npmLike(2);
	else if (
		launcher === "uvx" ||
		(launcher === "uv" &&
			sub === "tool" &&
			(tokens[2] === "run" || tokens[2] === "x"))
	)
		for (const p of valueFlagged(
			launcher === "uvx" ? 1 : 3,
			UV_VALUE_FLAGS,
			"--from",
		))
			add("pypi", p);
	else if (launcher === "pipx" && sub === "run")
		for (const p of valueFlagged(2, PIPX_VALUE_FLAGS, "--spec")) add("pypi", p);
	else if (
		(launcher === "docker" || launcher === "podman") &&
		(sub === "run" || (sub === "container" && tokens[2] === "run"))
	) {
		for (let i = sub === "run" ? 2 : 3; i < tokens.length; i++) {
			const t = tokens[i] ?? "";
			if (DOCKER_VALUE_FLAGS.has(t)) i++;
			else if (!t.startsWith("-")) {
				add("docker", i);
				break;
			}
		}
	}
	return out;
};

/* -------------------------------------------------------------------------- */
/*                               Launch commands                              */
/* -------------------------------------------------------------------------- */

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);
const ASSIGNMENT = /^[A-Za-z_]\w*=/;

const split = (loc: Located): Located[] =>
	loc.value
		.trim()
		.split(/\s+/)
		.filter(Boolean)
		.map((value) => ({ value, offset: loc.offset }));

/**
 * The launcher behind the wrappers MCP configs use: leading `KEY=value`
 * assignments, `env`, `cmd /c` and `sh -c "…"`.
 */
const unwrap = (tokens: ReadonlyArray<Located>, depth = 0): Located[] => {
	let t = [...tokens];
	for (let guard = 0; guard < 16 && t.length > 0; guard++) {
		const first = t[0]?.value ?? "";
		const head = exeName(first);
		if (ASSIGNMENT.test(first)) t = t.slice(1);
		else if (head === "env" || head === "cmd") {
			t = t.slice(1);
			while (t[0] && /^(?:-|\/[a-z]$|[A-Za-z_]\w*=)/i.test(t[0].value))
				t = t.slice(1);
		} else if (SHELLS.has(head) && /^-\w*c$/.test(t[1]?.value ?? "")) {
			const script = t[2];
			return script && depth < 2 ? unwrap(split(script), depth + 1) : [];
		} else break;
	}
	return t;
};

/* -------------------------------------------------------------------------- */
/*                                 Credentials                                */
/* -------------------------------------------------------------------------- */

const isReference = (value: string) => /\$\{|^\$[A-Za-z_]|^\{?env:/.test(value);

const CREDENTIAL_KEY = new RegExp(
	`${SECRET_KEY_NAME.source}|(?:^|[_-])(?:token|credential)s?(?:$|[_-])|^(?:proxy-)?authorization$|^cookie$|^x-[\\w-]*(?:key|token|auth)[\\w-]*$`,
	"i",
);
/** Short query-parameter names that carry credentials in URLs. */
const QUERY_SECRET =
	/^(?:key|token|sig|signature|auth|code|secret|pass|password|pwd|apikey|api[_-]?key|access[_-]?token|private[_-]?token)$/i;
const NOT_A_SECRET_KEY =
	/(?:_|-|^)(?:url|uri|host|path|file|name|id|type|scopes?|header|length|min|max|ttl|timeout|env|var)$/i;

interface Candidate {
	readonly where: string;
	readonly key: string;
	readonly value: string;
	readonly offset: number;
	readonly query?: boolean;
}

/** Query, fragment and userinfo credentials, parsed the WHATWG way (as clients do). */
const urlCandidates = (
	where: string,
	value: string,
	offset: number,
): Candidate[] => {
	if (!value.includes(":")) return [];
	let url: URL;
	try {
		url = new URL(value.trim());
	} catch {
		return [];
	}
	if (!url.host) return [];
	const params = [
		...url.searchParams,
		...new URLSearchParams(url.hash.slice(1)),
	];
	const out: Candidate[] = params.map(([key, v]) => ({
		where: `${where} ?${key}`,
		key,
		value: v,
		offset,
		query: true,
	}));
	if (url.password) {
		let password = url.password;
		try {
			password = decodeURIComponent(password);
		} catch {
			// Keep the encoded form.
		}
		out.push({
			where: `${where} password`,
			key: "password",
			value: password,
			offset,
		});
	}
	return out;
};

const KEY_VALUE = /^(--?[\w-]{1,60}|[A-Za-z_]\w{0,60})=([\s\S]+)$/;
const HEADER = /^([A-Za-z][\w-]{0,60})\s*:\s*([\s\S]+)$/;
const WINDOWS_SWITCH = /^\/([\w-]{1,60}):([\s\S]+)$/;

/**
 * Every way one string can carry a named value: `--flag=value`, `KEY=value`,
 * `Header: value`, `/name:value`, URL parts, and the same for each
 * whitespace-separated word.
 */
const expand = (
	where: string,
	key: string,
	value: string,
	offset: number,
	depth = 0,
): Candidate[] => {
	const out: Candidate[] = [];
	if (depth === 0 && /\s/.test(value.trim()))
		for (const word of value.trim().split(/\s+/))
			out.push(...expand(where, "", word, offset, 1));
	out.push({ where, key, value, offset });
	if (depth > 3) return out;
	for (const re of [KEY_VALUE, HEADER, WINDOWS_SWITCH]) {
		const m = re.exec(value);
		if (!m || (re === HEADER && (m[2] ?? "").startsWith("//"))) continue;
		out.push(...expand(where, m[1] ?? "", m[2] ?? "", offset, depth + 1));
	}
	out.push(...urlCandidates(where, value, offset));
	return out;
};

/** Every string in a server entry, keys and its name included. */
const candidatesOf = (server: McpServer): Candidate[] => {
	const out: Candidate[] = [
		{
			where: "server name",
			key: "",
			value: server.name,
			offset: server.nameOffset,
		},
	];
	const walk = (node: JsonNode, path: string, key: string, depth: number) => {
		if (depth > 32) return;
		if (node.kind === "string")
			out.push(...expand(path, key, node.value, node.offset));
		else if (node.kind === "array")
			node.items.forEach((item, i) => {
				const at = `${path}[${i}]`;
				walk(item, at, key, depth + 1);
				// `--api-key value`, `-H "Authorization: …"`
				const prev = node.items[i - 1];
				if (
					prev?.kind === "string" &&
					prev.value.startsWith("-") &&
					item.kind === "string"
				)
					out.push(...expand(at, prev.value, item.value, item.offset, 1));
			});
		else if (node.kind === "object")
			for (const e of node.entries) {
				out.push({
					where: `${path || "server"} key`,
					key: "",
					value: e.key,
					offset: e.keyOffset,
				});
				walk(e.value, path ? `${path}.${e.key}` : e.key, e.key, depth + 1);
			}
	};
	walk(server.node, "", "", 0);
	return out;
};

interface LiteralSecret {
	readonly title: string;
	readonly severity: Severity;
	readonly secret: string;
	readonly confidence: "high" | "medium" | "low";
}

/** Provider token shapes from code.secrets, then credential-named literals. */
const literalSecret = (c: Candidate): LiteralSecret | undefined => {
	if (isReference(c.value)) return undefined;
	for (const rule of SECRET_RULES) {
		for (const m of c.value.matchAll(rule.pattern)) {
			const secret = m.groups?.secret ?? m.groups?.auth ?? m[0];
			if (rule.id !== "private-key" && isPlaceholder(secret)) continue;
			if (rule.minEntropy && shannonEntropy(secret) < rule.minEntropy) continue;
			return {
				title: rule.title,
				severity: rule.severity,
				secret,
				confidence: rule.confidence ?? "high",
			};
		}
	}
	const named = c.query
		? QUERY_SECRET.test(c.key) || CREDENTIAL_KEY.test(c.key)
		: CREDENTIAL_KEY.test(c.key);
	if (!c.key || !named || NOT_A_SECRET_KEY.test(c.key)) return undefined;
	const value = c.value.trim().replace(/^(?:bearer|basic|token)\s+/i, "");
	if (
		value.length < 8 ||
		/\s/.test(value) ||
		isPlaceholder(value) ||
		shannonEntropy(value) < 3 ||
		/^https?:\/\/|^[a-z]+(?:[._-][a-z]+)*$/.test(value)
	)
		return undefined;
	return {
		title: "Credential",
		severity: "high",
		secret: value,
		confidence: "medium",
	};
};

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
	s: string,
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

const SUBCOMMANDS = new Set(["run", "exec", "x", "dlx", "tool", "container"]);

/**
 * The launch command up to the package, with flag values and other operands
 * replaced by `…`: `docker run -i -e … ghcr.io/org/mcp`. Values passed to
 * flags (`-e TOKEN=…`, `--index-url https://user:pass@…`) never appear.
 */
const launchEvidence = (
	tokens: ReadonlyArray<string>,
	upTo: number,
	clean: (s: string) => string,
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

/** WHATWG-parsed http URL (leading spaces, tabs and case as a client sees them). */
const plainHttpHost = (value: string): string | undefined => {
	try {
		const url = new URL(value.trim());
		return url.protocol === "http:" &&
			url.hostname &&
			!LOOPBACK.test(url.hostname)
			? url.hostname
			: undefined;
	} catch {
		return undefined;
	}
};

export const scanServers = (
	path: string,
	text: string,
	servers: ReadonlyArray<McpServer>,
	localPackages: ReadonlySet<string>,
	gemini: boolean,
): FindingInput[] => {
	const lineOf = lineLocator(text);

	// Find every literal credential first, so no output string can repeat one.
	const credentials = servers.map((server) => {
		const seen = new Set<string>();
		return candidatesOf(server).flatMap((c) => {
			const s = literalSecret(c);
			const id = `${c.offset}:${s?.secret}`;
			if (!s || seen.has(id)) return [];
			seen.add(id);
			return [{ c, s }];
		});
	});
	const known = credentials.flat().map(({ s }) => s.secret);
	const clean = (s: string) => truncate(safeText(s.slice(0, 2000), known), 120);

	const findings: FindingInput[] = [];
	servers.forEach((server, i) => {
		const name = clean(server.name);
		const { node } = server;

		const commands = stringsOf(fields(node, "command"));
		const argLists = fields(node, "args").map((a) => stringsOf([a]));
		const reported = new Set<string>();
		for (const command of commands)
			for (const args of argLists.length > 0 ? argLists : [[]]) {
				const tokens = unwrap([...split(command), ...args]);
				const values = tokens.map((t) => t.value);
				for (const pkg of launchedPackages(values)) {
					if (pkg.pinned) continue;
					if (pkg.ecosystem === "npm" && localPackages.has(npmName(pkg.spec)))
						continue;
					const offset = tokens[pkg.token]?.offset ?? command.offset;
					const id = `${offset}:${pkg.spec}`;
					if (reported.has(id)) continue;
					reported.add(id);
					findings.push(
						finding("mcp-unpinned-server", path, lineOf(offset), {
							title: `MCP server "${name}" runs an unpinned ${pkg.ecosystem === "docker" ? "image" : "package"}`,
							severity: "medium",
							category: "supply-chain",
							message: `MCP server "${name}" launches \`${clean(pkg.spec)}\` without an exact version, so each start can fetch and run whatever the registry serves at that moment${pkg.autoYes ? " (-y installs it without asking)" : ""}. A compromised or hijacked release then runs with the agent's access to this machine.`,
							evidence: launchEvidence(values, pkg.token, clean),
							remediation: REMOTE_INSTALL_REMEDIATION[pkg.ecosystem],
							references: [
								owaspLlmUrl("llm03"),
								cweUrl(1357),
								`${MCP_SECURITY}#local-mcp-server-compromise`,
							],
							confidence: "high",
							tags: ["cwe-1357", "owasp-llm03"],
						}),
					);
				}
			}

		for (const url of stringsOf(
			["url", "httpUrl", "serverUrl"].flatMap((k) => fields(node, k)),
		)) {
			const host = plainHttpHost(url.value);
			if (host)
				findings.push(
					finding("mcp-plaintext-http", path, lineOf(url.offset), {
						title: `MCP server "${name}" is reached over plain HTTP`,
						severity: "medium",
						category: "security",
						message: `MCP server "${name}" uses ${clean(host)} over http://, so tool calls, results and any credentials are sent unencrypted and can be read or altered on the network.`,
						evidence: clean(url.value),
						remediation:
							"Use https:// for every MCP server that is not on the loopback interface.",
						references: [cweUrl(319), owaspUrl("a02"), MCP_SECURITY],
						confidence: "high",
						tags: ["cwe-319", "owasp-a02"],
					}),
				);
		}

		for (const { c, s } of credentials[i] ?? []) {
			const where = clean(
				c.key && !c.where.endsWith(c.key) ? `${c.where} ${c.key}` : c.where,
			);
			findings.push(
				finding("mcp-inline-credential", path, lineOf(c.offset), {
					title: `${s.title} in MCP server config`,
					severity: s.severity,
					category: "security",
					message: `MCP server "${name}" has a literal credential in ${where}. Anyone who can read the repository can use it, and agents that read the config can leak it.`,
					evidence: `${where}: ${redact(s.secret)}`,
					remediation:
						// biome-ignore lint/suspicious/noTemplateCurlyInString: MCP config variable syntax
						"Revoke and rotate the credential, then reference an environment variable instead (`${VAR}` in .mcp.json, `${env:VAR}` in Cursor and VS Code, `env_vars`/`bearer_token_env_var` in Codex).",
					references: [cweUrl(798), owaspUrl("a07"), MCP_SECURITY],
					confidence: s.confidence,
					tags: ["cwe-798", "owasp-a07", "secrets"],
				}),
			);
		}

		const trusted =
			node.kind === "object"
				? node.entries.find(
						(e) =>
							e.key === "trust" &&
							e.value.kind === "scalar" &&
							e.value.value === true,
					)
				: undefined;
		if (gemini && trusted)
			findings.push(
				finding("mcp-server-trusted", path, lineOf(trusted.keyOffset), {
					title: `MCP server "${name}" bypasses tool confirmations`,
					severity: "medium",
					category: "security",
					message: `\`trust: true\` makes Gemini CLI run every tool of MCP server "${name}" without asking, so a prompt injection can drive that server unchecked.`,
					evidence: `mcpServers.${name}.trust: true`,
					remediation:
						"Remove `trust: true` and allow-list the specific read-only tools you need with `includeTools` or `tools.allowed`.",
					references: [owaspLlmUrl("llm06"), GEMINI_CONFIG],
					confidence: "high",
					tags: ["owasp-llm06"],
				}),
			);
	});
	return findings;
};

export const scanMcpJson = (
	file: SourceFile,
	localPackages: ReadonlySet<string>,
): FindingInput[] => {
	const gemini = /(?:^|\/)\.gemini\/settings\.json$/i.test(file.path);
	const parsed = parseJsoncDetailed(file.text);
	if (parsed.ok)
		return scanServers(
			file.path,
			file.text,
			serversIn(parsed.root),
			localPackages,
			gemini,
		);
	if (file.text.trim() === "") return [];
	const line = lineLocator(file.text)(parsed.offset);
	return [
		unparsed(
			file.path,
			line,
			`is not valid JSON(C): ${parsed.reason} at line ${line}`,
		),
		...bestEffort(
			scanServers(
				file.path,
				file.text,
				fallbackServers(file.text, false),
				localPackages,
				gemini,
			),
		),
	];
};
