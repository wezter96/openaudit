import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { isFixturePath, isRecord, parseJsonc, readTextFiles } from "../util";
import { scanInstructionFile } from "./instructions";
import { scanMcpJson } from "./mcp";
import { scanClaudeSettings, scanCodexConfig } from "./settings";
import { ID } from "./shared";

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

const INSTRUCTION_FILE =
	/(?:^|\/)(?:AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.github\/copilot-instructions\.md|\.github\/instructions\/[^/]+\.instructions\.md)$|(?:^|\/)(?:\.cursor\/rules|\.clinerules|\.windsurf\/rules)\/.+\.mdc?$/;
/** `.mcp.json` (Claude Code), `mcp.json` (Cursor, VS Code), Claude Desktop, Gemini CLI. */
const MCP_CONFIG =
	/(?:^|\/)(?:\.?mcp\.json|claude_desktop_config\.json|\.gemini\/settings\.json)$/;
const CLAUDE_SETTINGS = /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/;
const CODEX_CONFIG = /(?:^|\/)\.codex\/config\.toml$/;

const isAgentConfig = (path: string): boolean =>
	!isFixturePath(path) &&
	(INSTRUCTION_FILE.test(path) ||
		MCP_CONFIG.test(path) ||
		CLAUDE_SETTINGS.test(path) ||
		CODEX_CONFIG.test(path));

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
			const files = yield* readTextFiles(ws, isAgentConfig);
			if (files.length === 0)
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
			for (const file of files) {
				if (INSTRUCTION_FILE.test(file.path))
					findings.push(...scanInstructionFile(file));
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
