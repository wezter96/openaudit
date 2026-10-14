/**
 * The auditor registry and playbooks as JSON, read by the remote MCP server
 * (worker/mcp.ts) and the WebMCP tools (src/scripts/webmcp.ts).
 */
import type { APIRoute } from "astro";
import { catalogueData } from "../../lib/llm";

export const GET: APIRoute = () => Response.json(catalogueData());
