/** The docs split at their headings, and install snippets, for worker/mcp.ts. */
import type { APIRoute } from "astro";
import { docsData } from "../../lib/llm";

export const GET: APIRoute = () => Response.json(docsData());
