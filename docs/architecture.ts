/**
 * Regenerates docs/architecture.html from the auditor registry:
 * `bun docs/architecture.ts`.
 */
import { join } from "node:path";
import { allAuditors } from "../apps/cli/src/audit";

const dir = import.meta.dir;
const template = await Bun.file(join(dir, "architecture.template.html")).text();
const server = await Bun.file(
	join(dir, "..", "packages", "mcp", "src", "server.ts"),
).text();

const auditors = allAuditors().map((a) => ({
	id: a.id,
	title: a.title,
	engine: a.engine,
	tool: a.tool ?? null,
	optin: a.defaultEnabled === false,
	network: a.network === true,
	targets: a.targets,
	cats: a.categories,
}));
const mcpTools = [...server.matchAll(/registerTool\(\s*"([a-z_]+)"/g)].map(
	(m) => m[1],
);
// `<` is escaped so registry strings can never close the script element.
const json = (v: unknown) => JSON.stringify(v).replace(/</g, "\\u003c");

const html = template
	.replace("__AUDITORS__", json(auditors))
	.replace("__MCPTOOLS__", json(mcpTools))
	.replace("__DATE__", new Date().toISOString().slice(0, 10));
await Bun.write(join(dir, "architecture.html"), html);
console.log(
	`docs/architecture.html: ${auditors.length} auditors, ${mcpTools.length} MCP tools`,
);
