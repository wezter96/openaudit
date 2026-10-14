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
	readTextFiles,
	type SourceFile,
} from "../util";
import { scanInstructionFile } from "./instructions";
import { scanMcpJson } from "./mcp";
import { scanClaudeSettings, scanCodexConfig } from "./settings";
import { finding, ID } from "./shared";

export {
	hiddenRegions,
	hiddenUnicode,
	scanInstructionFile,
} from "./instructions";
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

type Instruction =
	| SourceFile
	| { readonly path: string; readonly size?: number };

/**
 * Reads an instruction file without the generic reader's skips: fixture
 * paths, NUL bytes and minified-looking text are exactly where an attacker
 * would hide instructions. Only files the workspace refuses to read come
 * back without text.
 */
const readInstruction = (ws: Workspace, path: string) =>
	ws.size(path).pipe(
		Effect.flatMap(
			(size): Effect.Effect<Instruction, unknown> =>
				size > MAX_TEXT_BYTES
					? Effect.succeed({ path, size })
					: Effect.map(ws.readText(path), (text) => ({ path, text })),
		),
		Effect.orElseSucceed((): Instruction => ({ path })),
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
			const instructions = yield* Effect.forEach(
				(yield* ws.files).filter(isInstructionFile),
				(path) => readInstruction(ws, path),
				{ concurrency: 16 },
			);
			const files = yield* readTextFiles(ws, isConfigFile, {
				allowMinified: true,
			});
			if (files.length === 0 && instructions.length === 0)
				return yield* skip(
					"No agent instruction files, MCP configs or agent settings found",
				);

			// npx runs a declared dependency from node_modules, pinned by the lockfile.
			const all = new Set(yield* ws.files);
			const manifests = new Set(
				files
					.filter((f) => MCP_CONFIG.test(f.path) || CODEX_CONFIG.test(f.path))
					.flatMap((f) => [`${projectDir(f.path)}package.json`, "package.json"])
					.filter((p) => all.has(p)),
			);
			const localPackages = new Set(
				(yield* Effect.forEach([...manifests], (p) =>
					declaredPackages(ws, p),
				)).flat(),
			);

			const findings: FindingInput[] = [];
			for (const file of instructions)
				findings.push(
					...("text" in file ? scanInstructionFile(file) : [unscanned(file)]),
				);
			for (const file of files) {
				if (MCP_CONFIG.test(file.path))
					findings.push(...scanMcpJson(file, localPackages));
				if (CLAUDE_SETTINGS.test(file.path))
					findings.push(...scanClaudeSettings(file));
				if (CODEX_CONFIG.test(file.path))
					findings.push(...scanCodexConfig(file, localPackages));
			}
			return findings;
		}),
});
