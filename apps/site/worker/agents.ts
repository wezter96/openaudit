/**
 * How the Worker serves the site to agents: Markdown by content negotiation,
 * discovery Link headers on HTML, and the content types and CORS of the
 * agent-facing files. Paths are site paths: the Worker serves openaudit.se
 * at the root, so there is no base path here.
 */

/** How specifically a media range matches text/html; absent when it does not. */
const HTML_SPECIFICITY = new Map([
	["text/html", 2],
	["text/*", 1],
	["*/*", 0],
]);

/** One range of an Accept header with its weight; undefined when q is not a number. */
const mediaRange = (part: string) => {
	const [range = "", ...params] = part.trim().toLowerCase().split(";");
	const qParam = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
	const q = qParam ? Number(qParam.slice(2)) : 1;
	return Number.isFinite(q) ? { type: range.trim(), q } : undefined;
};

/** Whether `accept` ranks text/markdown at least as high as text/html. */
export const prefersMarkdown = (accept: string | null): boolean => {
	if (!accept) return false;
	let markdown = 0;
	// The most specific range that matches text/html decides its weight.
	let html = 0;
	let htmlSpecificity = -1;
	for (const { type, q } of accept
		.split(",")
		.flatMap((part) => mediaRange(part) ?? [])) {
		if (type === "text/markdown") markdown = Math.max(markdown, q);
		const specificity = HTML_SPECIFICITY.get(type) ?? -1;
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

/** Agent-facing files at fixed paths, with their content types. */
const AGENT_PATHS = new Map([
	[
		"/.well-known/api-catalog",
		'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',
	],
	["/llms.txt", TEXT],
	["/llms-full.txt", TEXT],
	["/openapi.json", JSON_TYPE],
]);

/** Agent-facing files by folder and extension; "" is any folder. */
const AGENT_EXTENSIONS: ReadonlyArray<
	readonly [folder: string, extension: string, type: string]
> = [
	["", ".md", MARKDOWN],
	["/data/", ".json", JSON_TYPE],
	["/.well-known/", ".json", JSON_TYPE],
	["/.well-known/", ".txt", TEXT],
];

/**
 * Content type and cross-origin access for agent-facing files, or undefined
 * when the path is not one of them. Everything listed is public and read-only.
 */
export const agentFile = (
	pathname: string,
): { readonly type: string } | undefined => {
	const type =
		AGENT_PATHS.get(pathname) ??
		AGENT_EXTENSIONS.find(
			([folder, extension]) =>
				pathname.startsWith(folder) && pathname.endsWith(extension),
		)?.[2];
	return type ? { type } : undefined;
};

/** Headers that let any origin read a public file. */
export const PUBLIC_READ = {
	"Access-Control-Allow-Origin": "*",
	"Cross-Origin-Resource-Policy": "cross-origin",
} as const;
