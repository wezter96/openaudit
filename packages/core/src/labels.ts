import type { Category, Severity } from "./model";

/*
 * Display labels for the report model. Type-only imports keep this module free
 * of Effect Schema, so UIs can import it without bundling the model.
 */

export const SEVERITY_LABEL: Record<Severity, string> = {
	critical: "Critical",
	high: "High",
	medium: "Medium",
	low: "Low",
	info: "Info",
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
