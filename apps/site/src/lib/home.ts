/**
 * Data for the landing page, derived from the registry, the README and the
 * self-audit at build time.
 */
import { readRepo } from "./markdown";
import {
	type Auditor,
	auditors,
	CATEGORIES,
	CATEGORY_LABEL,
	counts,
	self,
	TARGET_LABEL,
	TARGETS,
} from "./site";

const readme = readRepo("README.md");

/** "openaudit runs 32 built-in auditors and wraps 45 established …" */
export const readmeIntro = (
	readme.split("\n").find((l) => l.startsWith("openaudit runs ")) ?? ""
).trim();
/** The README's own count of wrapped scanners, so the site never disagrees. */
export const wrappedCount = Number(
	/wraps (\d+)/.exec(readmeIntro)?.[1] ?? counts.tools,
);

export interface Example {
	readonly severity: "critical" | "high" | "medium" | "low" | "info";
	readonly rule: string;
	readonly title: string;
	readonly where: string;
}

/**
 * One example finding per area. Rule ids, titles and severities are real
 * (packages/auditors); the locations are illustrative.
 */
const EXAMPLES: Record<string, Example> = {
	security: {
		severity: "critical",
		rule: "code.secrets/aws-access-key-id",
		title: "AWS access key ID",
		where: "src/config.ts:14",
	},
	accessibility: {
		severity: "high",
		rule: "code.accessibility/img-alt-missing",
		title: "Image without alt text",
		where: "src/components/Hero.tsx:22",
	},
	performance: {
		severity: "medium",
		rule: "web.performance/render-blocking-script",
		title: "Render-blocking script in <head>",
		where: "https://example.com/  head > script",
	},
	seo: {
		severity: "medium",
		rule: "web.seo/broken-link",
		title: "Broken internal link (404)",
		where: "https://example.com/pricing",
	},
	privacy: {
		severity: "medium",
		rule: "webapp.browser/tracking-cookie-before-consent",
		title: "Tracking cookies set before consent",
		where: "https://example.com/",
	},
	"best-practices": {
		severity: "low",
		rule: "container.dockerfile/add-instead-of-copy",
		title: "ADD used where COPY suffices",
		where: "Dockerfile:7",
	},
	reliability: {
		severity: "low",
		rule: "iac.kubernetes/probes-missing",
		title: "Health probes missing",
		where: "k8s/deployment.yaml:18",
	},
	maintainability: {
		severity: "medium",
		rule: "code.quality/ts-strict-disabled",
		title: "TypeScript strict mode disabled",
		where: "tsconfig.json:4",
	},
	"supply-chain": {
		severity: "medium",
		rule: "container.dockerfile/from-latest",
		title: "Base image uses a mutable tag",
		where: "Dockerfile:1",
	},
	compliance: {
		severity: "medium",
		rule: "code.scancode/strong-copyleft",
		title: "vendor/parser.c: GPL-3.0-only",
		where: "vendor/parser.c:1",
	},
};

/** One short line per area for the landing page; README's table has the full list. */
const AREA_LINE: Record<string, string> = {
	security:
		"Secrets, risky code, TLS and headers, exposed files, container and cloud config.",
	accessibility:
		"WCAG checks in code, on rendered pages and in Android layouts.",
	performance: "Page weight, caching, Core Web Vitals, bundle and image size.",
	seo: "Titles, descriptions, crawlability, sitemaps and broken links.",
	privacy: "Trackers before consent, analytics SDKs, personal data in logs.",
	"best-practices":
		"Repo hygiene, Dockerfile and IaC lint, GitHub Actions hardening.",
	reliability: "Type errors, broken pages, redirect chains, missing probes.",
	maintainability: "Lint, strict typing, duplication, dead code, huge files.",
	"supply-chain":
		"Vulnerable dependencies, unpinned versions, licences, image CVEs.",
	compliance:
		"Licence duties, cookie consent, OWASP and CWE mapping, CIS benchmarks.",
};

/**
 * Wrapped tools people know and look for, most recognised first. An area
 * lists these ahead of the rest; the others follow, the ones that run by
 * default before the opt-in ones, alphabetically.
 */
const KEY_TOOLS = [
	"semgrep",
	"trivy",
	"gitleaks",
	"osv-scanner",
	"trufflehog",
	"lighthouse",
	"checkov",
	"zizmor",
	"grype",
	"bandit",
	"gosec",
	"govulncheck",
	"hadolint",
	"ruff",
	"oxlint",
	"eslint",
	"tsc",
	"kubescape",
	"pa11y",
	"actionlint",
	"shellcheck",
];
const toolRank = (tool: string, own: readonly Auditor[]) => {
	const key = KEY_TOOLS.indexOf(tool);
	if (key >= 0) return key;
	const byDefault = own.some((a) => a.tool === tool && !a.optIn);
	return KEY_TOOLS.length + (byDefault ? 0 : 1);
};

export const areas = CATEGORIES.map((id) => {
	const label = CATEGORY_LABEL[id] ?? id;
	const own = auditors.filter((a) => a.categories.includes(id));
	const score = self.categories?.find((c) => c.category === id);
	return {
		id,
		label,
		text: AREA_LINE[id] ?? "",
		grade: score?.grade ?? null,
		score: score?.score ?? null,
		count: own.length,
		tools: (
			[
				...new Set(
					own
						.filter((a) => a.engine === "external" && a.tool)
						.map((a) => a.tool),
				),
			] as string[]
		).sort((a, b) => toolRank(a, own) - toolRank(b, own) || a.localeCompare(b)),
		example: EXAMPLES[id],
	};
});

/** Auditors per target and area, for the coverage matrix. */
export const matrix = TARGETS.map((t) => ({
	id: t,
	label: TARGET_LABEL[t] ?? t,
	total: auditors.filter((a) => a.targets.includes(t)).length,
	cells: CATEGORIES.map(
		(c) =>
			auditors.filter((a) => a.targets.includes(t) && a.categories.includes(c))
				.length,
	),
}));
export const matrixMax = Math.max(...matrix.flatMap((r) => r.cells));

export const TARGET_COMMAND: Record<string, string> = {
	codebase: "bunx @openaudit/cli .",
	url: "bunx @openaudit/cli https://example.com",
	webapp: "bunx @openaudit/cli https://example.com --browser",
	container: "bunx @openaudit/cli image:nginx:1.27",
	iac: "bunx @openaudit/cli ./infra",
	mobile: "bunx @openaudit/cli ./app-release.apk",
	cloud: "bunx @openaudit/cli cloud:aws --only cloud",
};

/** Short column labels for narrow screens. */
export const AREA_SHORT: Record<string, string> = {
	security: "Sec",
	accessibility: "A11y",
	performance: "Perf",
	seo: "SEO",
	privacy: "Priv",
	"best-practices": "BP",
	reliability: "Rel",
	maintainability: "Mnt",
	"supply-chain": "Sup",
	compliance: "Comp",
};
