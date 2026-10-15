import {
	defineAuditor,
	type FindingInput,
	MAX_TEXT_BYTES,
	requireWorkspace,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	isBinaryPath,
	isFixturePath,
	isRecord,
	owaspLlmUrl,
	parseJsonc,
	type SourceFile,
} from "../util";
import { scanInstructionFile } from "./instructions";
import { scanMcpJson } from "./mcp";
import { scanClaudeSettings, scanCodexConfig } from "./settings";
import { finding, ID, unparsed } from "./shared";

export { hiddenUnicode, scanInstructionFile } from "./instructions";
export { hiddenRegions } from "./markdown";
export { type LaunchedPackage, launchedPackages } from "./mcp";

/*
 * AI-agent configuration committed to a repository: instruction files the
 * agent reads as trusted context (AGENTS.md, Cursor/Copilot/Windsurf/Cline
 * rules, GEMINI.md), MCP server configs it launches, and permission settings
 * that decide what it may do without asking. Everything here is read from
 * disk and parsed; nothing is executed.
 */

/**
 * Files agents load as instructions. Case-insensitive: on macOS and Windows
 * filesystems `agents.md` is what an agent opening AGENTS.md reads. Every
 * file under a rules directory counts, whatever its extension.
 */
const INSTRUCTION_FILE =
	/(?:^|\/)(?:AGENTS?\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules)$|(?:^|\/)\.github\/(?:copilot-instructions\.md|(?:instructions|prompts|chatmodes|agents)\/.+)$|(?:^|\/)(?:\.cursor\/rules|\.clinerules|\.windsurf\/rules|\.kiro\/steering|\.roo\/rules[^/]*|\.continue\/rules|\.amazonq\/rules)\/.+$/i;
/** `.mcp.json` (Claude Code), `mcp.json` (Cursor, VS Code), Claude Desktop, Gemini CLI. */
const MCP_CONFIG =
	/(?:^|\/)(?:\.?mcp\.json|claude_desktop_config\.json|\.gemini\/settings\.json)$/i;
const CLAUDE_SETTINGS = /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i;
const CODEX_CONFIG = /(?:^|\/)\.codex\/config\.toml$/i;

const isInstructionFile = (path: string): boolean =>
	INSTRUCTION_FILE.test(path) && !isBinaryPath(path);

/** Configs only take effect where an agent starts, never inside fixtures. */
const isConfigFile = (path: string): boolean =>
	!isFixturePath(path) &&
	(MCP_CONFIG.test(path) ||
		CLAUDE_SETTINGS.test(path) ||
		CODEX_CONFIG.test(path));

type AgentFile = SourceFile | { readonly path: string; readonly size?: number };

/**
 * Reads an agent file without the generic reader's skips: fixture paths
 * (for instruction files), size below the workspace limit, NUL bytes and
 * minified-looking text are exactly where an attacker would hide content.
 * Only files the workspace refuses to read come back without text, and
 * those are reported, never dropped.
 */
const readAgentFile = (ws: Workspace, path: string) =>
	ws.size(path).pipe(
		Effect.flatMap(
			(size): Effect.Effect<AgentFile, unknown> =>
				size > MAX_TEXT_BYTES
					? Effect.succeed({ path, size })
					: Effect.map(ws.readText(path), (text) => ({ path, text })),
		),
		Effect.orElseSucceed((): AgentFile => ({ path })),
	);

const unscanned = (file: { path: string; size?: number }): FindingInput =>
	finding("instruction-file-unscanned", file.path, 1, {
		title: "Agent instruction file could not be audited",
		severity: "low",
		category: "security",
		message:
			file.size === undefined
				? `${file.path} could not be read, so its instructions were not checked.`
				: `${file.path} is ${file.size} bytes, over the ${MAX_TEXT_BYTES}-byte read limit, so its instructions were not checked. Agents may still load it.`,
		remediation:
			"Keep instruction files short enough to review, and read this one in full before trusting it.",
		references: [owaspLlmUrl("llm01")],
		confidence: "high",
		tags: ["owasp-llm01"],
	});

/* -------------------------------------------------------------------------- */
/*                                   Auditor                                  */
/* -------------------------------------------------------------------------- */

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"];

/** Packages declared in a package.json, which npx resolves from node_modules. */
const declaredPackages = (ws: Workspace, path: string) =>
	ws.readText(path).pipe(
		Effect.map((text) => {
			const json = parseJsonc(text);
			if (!isRecord(json)) return [];
			return DEP_FIELDS.flatMap((f) =>
				isRecord(json[f]) ? Object.keys(json[f]) : [],
			);
		}),
		Effect.orElseSucceed(() => []),
	);

const dirOf = (path: string) => {
	const i = path.lastIndexOf("/");
	return i === -1 ? "" : `${path.slice(0, i)}/`;
};

/** The project a config belongs to: `a/.cursor/mcp.json` → `a/`. */
const projectDir = (path: string) =>
	dirOf(path).replace(/(?:^|\/)\.(?:cursor|vscode|gemini|codex)\/$/, (m) =>
		m.startsWith("/") ? "/" : "",
	);

/** Packages any MCP or Codex config's project declares in package.json. */
const localPackagesOf = (
	ws: Workspace,
	listed: ReadonlyArray<string>,
	files: ReadonlyArray<SourceFile>,
) => {
	const all = new Set(listed);
	const manifests = new Set(
		files
			.filter((f) => MCP_CONFIG.test(f.path) || CODEX_CONFIG.test(f.path))
			.flatMap((f) => [`${projectDir(f.path)}package.json`, "package.json"])
			.filter((p) => all.has(p)),
	);
	return Effect.forEach([...manifests], (p) => declaredPackages(ws, p)).pipe(
		Effect.map((names) => new Set(names.flat())),
	);
};

const instructionFindings = (file: AgentFile): FindingInput[] =>
	"text" in file ? scanInstructionFile(file) : [unscanned(file)];

const unreadConfig = (file: AgentFile): FindingInput[] =>
	"text" in file
		? []
		: [
				unparsed(
					file.path,
					1,
					file.size === undefined
						? "could not be read"
						: `is ${file.size} bytes, over the ${MAX_TEXT_BYTES}-byte read limit`,
				),
			];

/** Each config scanner and the files it reads. */
const CONFIG_SCANS: ReadonlyArray<{
	readonly applies: RegExp;
	readonly scan: (
		file: SourceFile,
		localPackages: ReadonlySet<string>,
	) => FindingInput[];
}> = [
	{ applies: MCP_CONFIG, scan: scanMcpJson },
	{ applies: CLAUDE_SETTINGS, scan: (file) => scanClaudeSettings(file) },
	{ applies: CODEX_CONFIG, scan: scanCodexConfig },
];

const configFindings = (
	file: SourceFile,
	localPackages: ReadonlySet<string>,
): FindingInput[] =>
	CONFIG_SCANS.filter((c) => c.applies.test(file.path)).flatMap((c) =>
		c.scan(file, localPackages),
	);

export const agentConfig = defineAuditor({
	id: ID,
	title: "AI agent configuration",
	description:
		"Audits committed AI-agent configuration: hidden Unicode and hidden instructions in AGENTS.md and Cursor/Copilot/Windsurf/Cline/Gemini rule files, unpinned or plaintext MCP servers and inlined credentials in MCP configs, and over-broad Claude Code, Gemini CLI and Codex permission settings.",
	categories: ["security", "supply-chain"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const listed = yield* ws.files;
			const instructions = yield* Effect.forEach(
				listed.filter(isInstructionFile),
				(path) => readAgentFile(ws, path),
				{ concurrency: 16 },
			);
			const configs = yield* Effect.forEach(
				listed.filter(isConfigFile),
				(path) => readAgentFile(ws, path),
				{ concurrency: 16 },
			);
			const files = configs.filter((f): f is SourceFile => "text" in f);
			if (configs.length === 0 && instructions.length === 0)
				return yield* skip(
					"No agent instruction files, MCP configs or agent settings found",
				);

			// npx runs a declared dependency from node_modules, pinned by the lockfile.
			const localPackages = yield* localPackagesOf(ws, listed, files);
			return [
				...instructions.flatMap(instructionFindings),
				...configs.flatMap(unreadConfig),
				...files.flatMap((file) => configFindings(file, localPackages)),
			];
		}),
});
