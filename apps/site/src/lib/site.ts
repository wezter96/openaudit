import registry from "../generated/registry.json";
import selfAudit from "../generated/self-audit.json";
import { NAV, REPO } from "./nav";

/** The deployment origin and base path, from astro.config.ts. */
export const SITE = import.meta.env.SITE.replace(/\/$/, "");
const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
/** A site path ("/docs/") as a URL under the base path. */
export const u = (path: string) => `${BASE}${path}`;
/** The site path of a URL pathname that includes the base path. */
export const unbase = (pathname: string) =>
	BASE && pathname.startsWith(BASE)
		? pathname.slice(BASE.length) || "/"
		: pathname;
export { NAV, REPO };
export const BLOB = `${REPO}/blob/main`;
export const OPENSVERIGE = "https://opensverige.se/";
export const AUTHOR = { name: "Anton Wester", url: "https://antonwester.se/" };
export const IMAGE = "ghcr.io/wezter96/openaudit";

export const PITCH = "One scored audit of everything you ship.";

/** The sentence a visitor pastes into their AI agent; llms.txt tells the agent how. */
export const HANDOFF =
	"Audit this project with openaudit (https://openaudit.se/llms.txt). Fix what matters most, then run it again to check.";

export const DEVELOPERS_DESCRIPTION =
	"openaudit for developers: the CLI, MCP server and CI integrations, the ten audit areas, what runs for each target and language, and how findings merge and score.";

/** Agents that can run commands, so they can follow the handoff. */
export const HANDOFF_AGENTS = "Claude Code, Cursor, Codex, Windsurf or Copilot";

/** The docs pages, in reading order; titles and descriptions live here only. */
export const DOCS = [
	{
		slug: "",
		title: "Getting started",
		description:
			"Install openaudit, run your first audit and read the report. openaudit needs Bun 1.4 or newer; scanners are optional.",
	},
	{
		slug: "cli",
		title: "CLI reference",
		description:
			"Every openaudit command and flag: targets, output formats, auditor selection, baselines, diff mode, exit codes and agent mode.",
	},
	{
		slug: "configuration",
		title: "Configuration",
		description:
			"openaudit.config.json: suppressions, auditor selection and per-auditor settings, with the full key reference and what a config inside the audited target may change.",
	},
	{
		slug: "ci",
		title: "CI and integrations",
		description:
			"Run openaudit in GitHub Actions, GitLab CI, pre-commit or the Docker image, upload SARIF to code scanning and fail builds on new findings.",
	},
	{
		slug: "agents",
		title: "MCP and agents",
		description:
			"Connect Claude Code, Cursor, Codex or a remote agent to openaudit over MCP, run the ten judgment-heavy playbooks, or run them headless with --agentic.",
	},
	{
		slug: "api",
		title: "HTTP API",
		description:
			"The self-hosted HTTP API in apps/server: URL audits and the auditor and playbook catalogue over REST, with its OpenAPI document.",
	},
	{
		slug: "report",
		title: "Report and scoring",
		description:
			"How openaudit scores each area from 0 to 100, how grades and severities are defined, and what the interactive HTML, JSON, SARIF and Markdown reports contain.",
	},
	{
		slug: "safety",
		title: "Safety",
		description:
			"openaudit treats every target as hostile: confined file reads, origin-scoped HTTP, opt-in for tools that run project code, and agents without a shell.",
	},
	{
		slug: "contributing",
		title: "Contributing",
		description:
			"Set up the openaudit monorepo, add an auditor or wrap a scanner safely, and open a pull request that passes the full check.",
	},
] as const;
export type DocSlug = (typeof DOCS)[number]["slug"];
/** A docs page's entry in DOCS. */
export const doc = (slug: DocSlug) =>
	DOCS.find((d) => d.slug === slug) ?? DOCS[0];
/** The site path of a docs page. */
export const docPath = (slug: string) => `/docs/${slug ? `${slug}/` : ""}`;

export type Category =
	| "security"
	| "accessibility"
	| "performance"
	| "seo"
	| "privacy"
	| "best-practices"
	| "reliability"
	| "maintainability"
	| "supply-chain"
	| "compliance";

export const CATEGORY_LABEL: Record<string, string> = {
	security: "Security",
	accessibility: "Accessibility",
	performance: "Performance",
	seo: "SEO",
	privacy: "Privacy",
	"best-practices": "Best practices",
	reliability: "Reliability",
	maintainability: "Maintainability",
	"supply-chain": "Supply chain",
	compliance: "Compliance",
};
export const CATEGORIES = Object.keys(CATEGORY_LABEL);

export const TARGET_LABEL: Record<string, string> = {
	codebase: "Codebase",
	url: "URL",
	webapp: "Web app",
	container: "Container",
	iac: "Infrastructure as code",
	mobile: "Mobile build",
	cloud: "Cloud account",
};
export const TARGETS = Object.keys(TARGET_LABEL);

export const ENGINE_LABEL: Record<string, string> = {
	builtin: "Built-in",
	external: "Wrapped scanner",
	agentic: "Agent",
};
export const ENGINES = Object.keys(ENGINE_LABEL);

export type Auditor = (typeof registry.auditors)[number];
export type Playbook = (typeof registry.playbooks)[number];
export const auditors: ReadonlyArray<Auditor> = registry.auditors;
export const playbooks: ReadonlyArray<Playbook> = registry.playbooks;

/** Distinct external tools the registry wraps. */
export const wrappedTools = [
	...new Set(auditors.flatMap((a) => (a.tool ? [a.tool] : []))),
].sort();

export const counts = {
	builtin: auditors.filter((a) => a.engine === "builtin").length,
	external: auditors.filter((a) => a.engine === "external").length,
	agentic: auditors.filter((a) => a.engine === "agentic").length,
	tools: wrappedTools.length,
	playbooks: playbooks.length,
	all: auditors.length,
};

export const CATALOGUE_DESCRIPTION = `All ${counts.all} openaudit auditors: ${counts.builtin} built in, ${counts.external} that wrap an external tool and ${counts.agentic} agentic, filterable by target, area and engine.`;

export interface CategoryScore {
	readonly category: string;
	readonly score: number;
	readonly grade: string;
	readonly counts: Record<string, number>;
}

export interface SelfAudit {
	readonly available: boolean;
	readonly version?: string;
	readonly finishedAt?: string;
	readonly durationMs?: number;
	readonly kinds?: ReadonlyArray<string>;
	readonly score?: number;
	readonly grade?: string;
	readonly counts?: Record<string, number>;
	readonly auditors?: Record<string, number>;
	readonly categories?: ReadonlyArray<CategoryScore>;
}
export const self: SelfAudit = selfAudit;

/** Absolute URL of a site path. */
export const pageUrl = (path: string) => `${SITE}${u(path)}`;

/**
 * The Markdown version of a site page: "/docs/cli/" -> "/docs/cli/index.md".
 * The report has its own, written by the CLI. worker/agents.ts maps paths the
 * same way.
 */
export const markdownPath = (path: string) =>
	path === "/report/" ? "/report/openaudit-report.md" : `${path}index.md`;

/** `/docs/ci/` -> `docs-ci`, `/` -> `index`; the OG image name of a page. */
export const ogName = (path: string) =>
	path.replace(/^\/|\/$/g, "").replace(/\//g, "-") || "index";
