/**
 * The Markdown version of every page, at `<page>index.md` (`/index.md`,
 * `/docs/cli/index.md`, `/auditors/code.secrets/index.md`). The Worker also
 * serves it at the page's own URL for `Accept: text/markdown`.
 */
import type { APIRoute, GetStaticPaths } from "astro";
import { document, type MarkdownPage, markdownPages } from "../lib/llm";

export const getStaticPaths = (() =>
	markdownPages().map((page) => ({
		params: { page: `${page.path.slice(1)}index` },
		props: { page },
	}))) satisfies GetStaticPaths;

export const GET: APIRoute<{ page: MarkdownPage }> = ({ props }) =>
	new Response(document(props.page), {
		headers: { "Content-Type": "text/markdown; charset=utf-8" },
	});
