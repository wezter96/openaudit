import registry from "../generated/registry.json";
import selfAudit from "../generated/self-audit.json";

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
export const REPO = "https://github.com/wezter96/openaudit";
export const BLOB = `${REPO}/blob/main`;
export const OPENSVERIGE = "https://opensverige.se/";
export const IMAGE = "ghcr.io/wezter96/openaudit";

export const PITCH = "One scored audit of everything you ship.";

export const NAV = [
	{ href: "/docs/", label: "Docs" },
	{ href: "/auditors/", label: "Auditors" },
	{ href: "/report/", label: "Live report" },
	{ href: "/architecture/", label: "Architecture" },
] as const;

export const DOCS = [
	{ slug: "", title: "Getting started" },
	{ slug: "cli", title: "CLI reference" },
	{ slug: "configuration", title: "Configuration" },
	{ slug: "ci", title: "CI and integrations" },
	{ slug: "agents", title: "MCP and agents" },
	{ slug: "report", title: "Report and scoring" },
	{ slug: "safety", title: "Safety" },
	{ slug: "contributing", title: "Contributing" },
] as const;

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

/** `/docs/ci/` -> `docs-ci`, `/` -> `index`; the OG image name of a page. */
export const ogName = (path: string) =>
	path.replace(/^\/|\/$/g, "").replace(/\//g, "-") || "index";
