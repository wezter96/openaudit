/** /llms.txt (llmstxt.org): what the site is and where its Markdown lives. */
import type { APIRoute } from "astro";
import { llmsTxt } from "../lib/llm";

export const GET: APIRoute = () =>
	new Response(llmsTxt(), {
		headers: { "Content-Type": "text/plain; charset=utf-8" },
	});
