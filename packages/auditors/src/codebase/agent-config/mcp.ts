import { type FindingInput, redact, type Severity } from "@openaudit/core";

import { isPlaceholder, SECRET_KEY_NAME, SECRET_RULES } from "../secrets";
import {
	baseName,
	cweUrl,
	isRecord,
	lineLocator,
	owaspLlmUrl,
	owaspUrl,
	parseJsonc,
	type SourceFile,
	scrubLine,
	shannonEntropy,
	truncate,
} from "../util";
import { finding, GEMINI_CONFIG, locate, MCP_SECURITY } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                 MCP servers                                */
/* -------------------------------------------------------------------------- */

export interface McpServer {
	readonly name: string;
	readonly command?: string;
	readonly args: ReadonlyArray<string>;
	readonly env: Readonly<Record<string, string>>;
	readonly headers: Readonly<Record<string, string>>;
	readonly url?: string;
	readonly trust: boolean;
	/** Offset of the server's entry in the file; values are searched after it. */
	readonly anchor: number;
}

export const strings = (v: unknown): string[] =>
	Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

const stringMap = (v: unknown): Record<string, string> =>
	isRecord(v)
		? Object.fromEntries(
				Object.entries(v).filter(
					(e): e is [string, string] => typeof e[1] === "string",
				),
			)
		: {};

const toServer = (
	name: string,
	raw: Record<string, unknown>,
	anchor: number,
): McpServer => {
	const url = [raw.httpUrl, raw.url, raw.serverUrl].find(
		(u) => typeof u === "string",
	);
	return {
		name,
		command: typeof raw.command === "string" ? raw.command : undefined,
		args: strings(raw.args),
		env: stringMap(raw.env),
		headers: { ...stringMap(raw.headers), ...stringMap(raw.http_headers) },
		url: url as string | undefined,
		trust: raw.trust === true,
		anchor,
	};
};

export const serversOf = (
	table: unknown,
	anchorOf: (name: string) => number,
): McpServer[] =>
	isRecord(table)
		? Object.entries(table).flatMap(([name, raw]) =>
				isRecord(raw) ? [toServer(name, raw, anchorOf(name))] : [],
			)
		: [];

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

const isReference = (value: string) => /\$\{|^\$[A-Za-z_]|^\{?env:/.test(value);

const CREDENTIAL_KEY = new RegExp(
	`${SECRET_KEY_NAME.source}|(?:^|[_-])(?:token|credential)s?(?:$|[_-])|^(?:proxy-)?authorization$`,
	"i",
);
const NOT_A_SECRET_KEY =
	/(?:_|-|^)(?:url|uri|host|path|file|name|id|type|scopes?|header|length|min|max|ttl|timeout|env|var)$/i;

interface Candidate {
	readonly where: string;
	readonly key: string;
	readonly value: string;
}

/** Strings in a server entry that could hold a literal credential. */
const credentialCandidates = (server: McpServer): Candidate[] => {
	const out: Candidate[] = [];
	for (const [k, v] of Object.entries(server.env))
		out.push({ where: `env.${k}`, key: k, value: v });
	for (const [k, v] of Object.entries(server.headers))
		out.push({ where: `headers.${k}`, key: k, value: v });
	const args = server.args;
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const eq = /^(--?[\w-]+)=(.+)$/.exec(a);
		if (eq)
			out.push({
				where: `args ${eq[1]}`,
				key: eq[1] ?? "",
				value: eq[2] ?? "",
			});
		else if (
			/^--?[\w-]*(?:token|key|secret|password|passwd|credential)[\w-]*$/i.test(
				a,
			) &&
			args[i + 1] !== undefined
		) {
			out.push({ where: `args ${a}`, key: a, value: args[i + 1] ?? "" });
			i++;
		} else out.push({ where: "args", key: "", value: a });
	}
	if (server.url) {
		out.push({ where: "url", key: "", value: server.url });
		try {
			const url = new URL(server.url);
			for (const [k, v] of url.searchParams)
				out.push({ where: `url ?${k}`, key: k, value: v });
			if (url.password)
				out.push({
					where: "url password",
					key: "password",
					value: decodeURIComponent(url.password),
				});
		} catch {
			// Not a URL; the raw string was already checked.
		}
	}
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
	if (!c.key || !CREDENTIAL_KEY.test(c.key) || NOT_A_SECRET_KEY.test(c.key))
		return undefined;
	const value = c.value.replace(/^(?:bearer|basic|token)\s+/i, "");
	if (
		value.length < 8 ||
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

export const scanServers = (
	path: string,
	text: string,
	servers: ReadonlyArray<McpServer>,
	localPackages: ReadonlySet<string>,
	gemini: boolean,
): FindingInput[] => {
	const lineOf = lineLocator(text);
	const findings: FindingInput[] = [];
	for (const server of servers) {
		const { name, anchor } = server;
		const at = (value: string) => lineOf(locate(text, value, anchor));

		if (server.command) {
			const tokens = [...server.command.trim().split(/\s+/), ...server.args];
			for (const pkg of launchedPackages(tokens)) {
				if (pkg.pinned) continue;
				if (pkg.ecosystem === "npm" && localPackages.has(npmName(pkg.spec)))
					continue;
				findings.push(
					finding("mcp-unpinned-server", path, at(pkg.spec), {
						title: `MCP server "${name}" runs an unpinned ${pkg.ecosystem === "docker" ? "image" : "package"}`,
						severity: "medium",
						category: "supply-chain",
						message: `MCP server "${name}" launches \`${pkg.spec}\` without an exact version, so each start can fetch and run whatever the registry serves at that moment${pkg.autoYes ? " (-y installs it without asking)" : ""}. A compromised or hijacked release then runs with the agent's access to this machine.`,
						evidence: truncate(
							scrubLine(tokens.slice(0, pkg.token + 1).join(" ")),
						),
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

		if (server.url && /^http:\/\//i.test(server.url)) {
			let host = "";
			try {
				host = new URL(server.url).hostname;
			} catch {
				host = "";
			}
			if (host && !LOOPBACK.test(host))
				findings.push(
					finding("mcp-plaintext-http", path, at(server.url), {
						title: `MCP server "${name}" is reached over plain HTTP`,
						severity: "medium",
						category: "security",
						message: `MCP server "${name}" uses ${host} over http://, so tool calls, results and any credentials are sent unencrypted and can be read or altered on the network.`,
						evidence: truncate(scrubLine(server.url)),
						remediation:
							"Use https:// for every MCP server that is not on the loopback interface.",
						references: [cweUrl(319), owaspUrl("a02"), MCP_SECURITY],
						confidence: "high",
						tags: ["cwe-319", "owasp-a02"],
					}),
				);
		}

		for (const c of credentialCandidates(server)) {
			const s = literalSecret(c);
			if (!s) continue;
			findings.push(
				finding("mcp-inline-credential", path, at(c.value), {
					title: `${s.title} in MCP server config`,
					severity: s.severity,
					category: "security",
					message: `MCP server "${name}" has a literal credential in ${c.where}. Anyone who can read the repository can use it, and agents that read the config can leak it.`,
					evidence: `${c.where}: ${redact(s.secret)}`,
					remediation:
						// biome-ignore lint/suspicious/noTemplateCurlyInString: MCP config variable syntax
						"Revoke and rotate the credential, then reference an environment variable instead (`${VAR}` in .mcp.json, `${env:VAR}` in Cursor and VS Code, `env_vars`/`bearer_token_env_var` in Codex).",
					references: [cweUrl(798), owaspUrl("a07"), MCP_SECURITY],
					confidence: s.confidence,
					tags: ["cwe-798", "owasp-a07", "secrets"],
				}),
			);
		}

		if (gemini && server.trust)
			findings.push(
				finding(
					"mcp-server-trusted",
					path,
					lineOf(locate(text, '"trust"', anchor)),
					{
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
					},
				),
			);
	}
	return findings;
};

export const scanMcpJson = (
	file: SourceFile,
	localPackages: ReadonlySet<string>,
): FindingInput[] => {
	const json = parseJsonc(file.text);
	if (!isRecord(json)) return [];
	const key = isRecord(json.mcpServers) ? "mcpServers" : "servers";
	const tableAt = Math.max(0, file.text.indexOf(`"${key}"`));
	const servers = serversOf(json[key], (name) =>
		Math.max(tableAt, file.text.indexOf(JSON.stringify(name), tableAt)),
	);
	return scanServers(
		file.path,
		file.text,
		servers,
		localPackages,
		/(?:^|\/)\.gemini\/settings\.json$/.test(file.path),
	);
};
