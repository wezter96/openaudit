/**
 * How the Worker serves the site to agents: Markdown by content negotiation,
 * discovery Link headers on HTML, and the content types and CORS of the
 * agent-facing files. Paths are site paths: the Worker serves openaudit.se
 * at the root, so there is no base path here.
 */

/** Whether `accept` ranks text/markdown at least as high as text/html. */
export const prefersMarkdown = (accept: string | null): boolean => {
	if (!accept) return false;
	let markdown = 0;
	// The most specific range that matches text/html decides its weight.
	let html = 0;
	let htmlSpecificity = -1;
	for (const part of accept.split(",")) {
		const [range = "", ...params] = part.trim().toLowerCase().split(";");
		const qParam = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
		const q = qParam ? Number(qParam.slice(2)) : 1;
		if (!Number.isFinite(q)) continue;
		const type = range.trim();
		if (type === "text/markdown") markdown = Math.max(markdown, q);
		const specificity =
			type === "text/html"
				? 2
				: type === "text/*"
					? 1
					: type === "*/*"
						? 0
						: -1;
		if (specificity > htmlSpecificity) {
			htmlSpecificity = specificity;
			html = q;
		}
	}
	return markdown > 0 && markdown >= html;
};

/**
 * The Markdown version of an HTML page: "/docs/cli/" -> "/docs/cli/index.md"
 * (src/lib/site.ts markdownPath does the same at build time). The report has
 * its own, written by the CLI. Undefined for anything that is not a page.
 */
export const markdownFor = (pathname: string): string | undefined => {
	if (pathname === "/report/" || pathname === "/report/openaudit-report.html")
		return "/report/openaudit-report.md";
	if (pathname.endsWith("/")) return `${pathname}index.md`;
	const last = pathname.slice(pathname.lastIndexOf("/") + 1);
	if (last.includes(".")) return undefined;
	return `${pathname}/index.md`;
};

/** RFC 8288 Link header for HTML pages: where agents find the rest. */
export const linkHeader = (markdown?: string): string =>
	[
		'</.well-known/api-catalog>; rel="api-catalog"',
		'</openapi.json>; rel="service-desc"; type="application/json"',
		'</docs/>; rel="service-doc"; type="text/html"',
		'</llms.txt>; rel="describedby"; type="text/plain"',
		'</.well-known/ai-catalog.json>; rel="ai-catalog"; type="application/json"',
		...(markdown
			? [`<${markdown}>; rel="alternate"; type="text/markdown"`]
			: []),
	].join(", ");

/** About 4 characters a token: the estimate x-markdown-tokens reports. */
export const estimateTokens = (text: string) => Math.ceil(text.length / 4);

const JSON_TYPE = "application/json";
const MARKDOWN = "text/markdown; charset=utf-8";
const TEXT = "text/plain; charset=utf-8";

/**
 * Content type and cross-origin access for agent-facing files, or undefined
 * when the path is not one of them. Everything listed is public and read-only.
 */
export const agentFile = (
	pathname: string,
): { readonly type: string } | undefined => {
	if (pathname === "/.well-known/api-catalog")
		return {
			type: 'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',
		};
	if (pathname === "/llms.txt" || pathname === "/llms-full.txt")
		return { type: TEXT };
	if (pathname.endsWith(".md")) return { type: MARKDOWN };
	if (pathname === "/openapi.json") return { type: JSON_TYPE };
	if (pathname.startsWith("/data/") && pathname.endsWith(".json"))
		return { type: JSON_TYPE };
	if (pathname.startsWith("/.well-known/")) {
		if (pathname.endsWith(".json")) return { type: JSON_TYPE };
		if (pathname.endsWith(".txt")) return { type: TEXT };
	}
	return undefined;
};

/** Headers that let any origin read a public file. */
export const PUBLIC_READ = {
	"Access-Control-Allow-Origin": "*",
	"Cross-Origin-Resource-Policy": "cross-origin",
} as const;
