/** /llms-full.txt: the README pitch, every docs page and the catalogue. */
import type { APIRoute } from "astro";
import { llmsFullTxt } from "../lib/llm";

export const GET: APIRoute = () =>
	new Response(llmsFullTxt(), {
		headers: { "Content-Type": "text/plain; charset=utf-8" },
	});
