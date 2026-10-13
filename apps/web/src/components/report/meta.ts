import type {
	AuditorEngine,
	AuditorStatus,
	Category,
	Grade,
	Report,
	Severity,
	TargetKind,
} from "@openaudit/core/model";

/*
 * Display metadata for the report model. Kept here (not imported as values
 * from @openaudit/core/model) so pages that only render reports do not pull
 * Effect Schema into the bundle; the report viewer loads it lazily to validate.
 */

export const SEVERITY_ORDER: ReadonlyArray<Severity> = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
];

export const SEVERITY_LABEL: Record<Severity, string> = {
	critical: "Critical",
	high: "High",
	medium: "Medium",
	low: "Low",
	info: "Info",
};

/** Tailwind text colour per severity (tokens defined in index.css). */
export const SEVERITY_TEXT: Record<Severity, string> = {
	critical: "text-sev-critical",
	high: "text-sev-high",
	medium: "text-sev-medium",
	low: "text-sev-low",
	info: "text-sev-info",
};

export const SEVERITY_BG: Record<Severity, string> = {
	critical: "bg-sev-critical",
	high: "bg-sev-high",
	medium: "bg-sev-medium",
	low: "bg-sev-low",
	info: "bg-sev-info",
};

export const CATEGORY_LABEL: Record<Category, string> = {
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

export const TARGET_LABEL: Record<TargetKind, string> = {
	codebase: "Codebase",
	url: "URL",
	webapp: "Web app",
	container: "Container",
	iac: "Infrastructure as code",
	mobile: "Mobile build",
	cloud: "Cloud account",
};

export const ENGINE_LABEL: Record<AuditorEngine, string> = {
	builtin: "Built-in",
	external: "External tool",
	agentic: "Agentic",
};

export const STATUS_LABEL: Record<AuditorStatus, string> = {
	passed: "Passed",
	failed: "Findings",
	skipped: "Skipped",
	error: "Error",
};

export const GRADE_MEANING: Record<Grade, string> = {
	A: "Excellent",
	B: "Good",
	C: "Needs work",
	D: "Poor",
	F: "Failing",
};

export const formatDuration = (ms: number): string =>
	ms < 1000
		? `${Math.round(ms)} ms`
		: ms < 60_000
			? `${(ms / 1000).toFixed(1)} s`
			: `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`;

/** Only http(s) links from a report are rendered as anchors; reports are untrusted. */
export const safeHref = (value: string): string | undefined => {
	try {
		const url = new URL(value);
		return url.protocol === "https:" || url.protocol === "http:"
			? url.toString()
			: undefined;
	} catch {
		return undefined;
	}
};

/** URL, image, cloud provider, or just the folder/file name of a local path. */
export const targetName = (target: Report["target"]): string => {
	if (target.url) return target.url;
	if (target.image) return `image:${target.image}`;
	if (target.cloud) return `cloud:${target.cloud}`;
	const path = (target.root ?? target.file ?? target.input).replace(
		/[\\/]+$/,
		"",
	);
	return path.split(/[\\/]/).pop() || path;
};
