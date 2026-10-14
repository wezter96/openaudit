import { baseName, extOf, languageOf } from "../util";

/* What a file is, from its path and shebang: code, agent instructions or prose. */

/** `agent` files are instructions read by coding agents. */
export type Kind = "code" | "agent" | "text";

const CODE_EXT = new Set([
	"sh",
	"bash",
	"zsh",
	"fish",
	"ksh",
	"ps1",
	"psm1",
	"bat",
	"cmd",
	"lua",
	"pl",
	"pm",
	"r",
	"sql",
	"ex",
	"exs",
	"erl",
	"hrl",
	"hs",
	"ml",
	"mli",
	"fs",
	"fsx",
	"clj",
	"cljs",
	"zig",
	"nim",
	"groovy",
	"gradle",
	"kts",
	"m",
	"mm",
	"sol",
	"tf",
	"hcl",
	"vb",
	"jl",
	"cr",
	"elm",
	"dockerfile",
	"html",
	"htm",
	"xhtml",
	"svg",
]);

const CODE_NAME =
	/^(Dockerfile|Containerfile|Makefile|GNUmakefile|Justfile|Jenkinsfile|Rakefile|Gemfile|Vagrantfile|Podfile|Fastfile)(\.|$)|^\.gitlab-ci\.ya?ml$/;

const TEXT_EXT = new Set([
	"md",
	"mdx",
	"markdown",
	"txt",
	"text",
	"rst",
	"adoc",
	"asciidoc",
	"org",
	"tex",
	"json",
	"jsonc",
	"json5",
	"yaml",
	"yml",
	"toml",
	"ini",
	"cfg",
	"conf",
	"properties",
	"env",
	"po",
	"pot",
	"ftl",
	"arb",
	"strings",
	"stringsdict",
	"xliff",
	"xlf",
	"resx",
	"xml",
	"plist",
	"csv",
	"tsv",
	"map",
]);

/** Instruction and rule files that coding agents load into their prompt. */
const AGENT_FILE =
	/(^|\/)(AGENTS?|CLAUDE|CLAUDE\.local|GEMINI|SKILL)\.md$|(^|\/)\.(cursorrules|windsurfrules|clinerules)$|\.mdc$|(^|\/)\.github\/(copilot-instructions\.md|(instructions|prompts|chatmodes|agents)\/[^/]+\.md)$|(^|\/)\.(cursor\/rules|clinerules|windsurf\/rules|kiro\/steering|roo\/rules[^/]*|continue\/rules|amazonq\/rules|claude\/(commands|agents|skills))\//i;

/** Sources that interleave prose with code (JSX, component templates). */
export const MARKUP_EXT = new Set([
	"jsx",
	"tsx",
	"vue",
	"svelte",
	"astro",
	"html",
	"htm",
	"xhtml",
	"svg",
]);

/** Config files whose values run as commands. */
const EXECUTABLE_CONFIG =
	/(^|\/)(package\.json|composer\.json|deno\.jsonc?|Taskfile\.ya?ml|\.pre-commit-config\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.travis\.ya?ml|cloudbuild\.ya?ml|buildspec\.ya?ml|\.envrc|\.circleci\/config\.ya?ml|\.husky\/[^/]+)$/;

/** Extensionless prose; other unknown files are judged as code. */
const PROSE_NAME =
	/^(README|LICEN[CS]E|COPYING|NOTICE|AUTHORS|CONTRIBUTORS|CHANGELOG|CHANGES|HISTORY|CODEOWNERS)$/i;

/**
 * Undefined for unknown files, which are scanned as code. Scripts inside
 * agent folders (`.claude/skills/x/run.py`) are code, and so is any file
 * whose `text` starts with a shebang, whatever its name.
 */
export const kindOf = (path: string, text?: string): Kind | undefined => {
	if (text?.startsWith("#!")) return "code";
	const ext = extOf(path);
	if (
		languageOf(path) ||
		CODE_EXT.has(ext) ||
		CODE_NAME.test(baseName(path)) ||
		EXECUTABLE_CONFIG.test(path) ||
		/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(path)
	)
		return "code";
	if (AGENT_FILE.test(path)) return "agent";
	if (
		TEXT_EXT.has(ext) ||
		/^\.env(\.|$)/.test(baseName(path)) ||
		PROSE_NAME.test(baseName(path))
	)
		return "text";
	return undefined;
};
