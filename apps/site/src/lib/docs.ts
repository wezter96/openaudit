/**
 * Data the docs pages compute from their sources, shared by the HTML pages
 * and their Markdown versions (src/lib/llm.ts) so the two never disagree.
 */
import config from "../generated/config.json";
import openapi from "../generated/openapi.json";
import { codeIn, paragraphsIn, readRepo } from "./markdown";

/* ---------------------------------------------------------- configuration */

interface Prop {
	readonly type?: string;
	readonly description?: string;
	readonly enum?: ReadonlyArray<string>;
	readonly items?: Prop;
	readonly anyOf?: ReadonlyArray<Prop>;
	readonly properties?: Record<string, Prop>;
	readonly required?: ReadonlyArray<string>;
	readonly additionalProperties?: boolean | Prop;
}
const typeOf = (p: Prop): string => {
	if (p.enum) return p.enum.map((v) => `"${v}"`).join(" | ");
	if (p.anyOf) return `(${p.anyOf.map(typeOf).join(" | ")})`;
	if (p.type === "array" && p.items) return `${typeOf(p.items)}[]`;
	if (p.type === "object" && p.properties)
		return `{ ${Object.keys(p.properties)
			.map((k) => (p.required?.includes(k) ? k : `${k}?`))
			.join(", ")} }`;
	return p.type ?? "any";
};

const defaults = config.defaults as Record<string, unknown>;
const defaultOf = (path: string[]): string => {
	let v: unknown = defaults;
	for (const k of path)
		v =
			v && typeof v === "object"
				? (v as Record<string, unknown>)[k]
				: undefined;
	return v === undefined ? "" : JSON.stringify(v);
};

export interface ConfigRow {
	readonly key: string;
	readonly type: string;
	readonly def: string;
	readonly trusted: boolean;
	readonly note: string;
}
/** One row per leaf key of the config schema, with its default. */
export const configRows: ReadonlyArray<ConfigRow> = (() => {
	const rows: ConfigRow[] = [];
	const walk = (props: Record<string, Prop>, path: string[]) => {
		for (const [k, p] of Object.entries(props)) {
			if (k === "$schema") continue;
			const full = [...path, k];
			const key = full.join(".");
			if (p.type === "object" && p.properties) {
				walk(p.properties, full);
				continue;
			}
			rows.push({
				key,
				type: typeOf(p),
				def: defaultOf(full),
				trusted: config.trustedOnly.includes(key),
				note: p.description ?? "",
			});
		}
	};
	walk(config.schema.properties as Record<string, Prop>, []);
	return rows;
})();
export const configSchema = config.schema;
export const configSchemaUrl = config.schemaUrl;

const AGENT = "packages/agent/README.md";
const HEADLESS = "1. Headless, inside openaudit (`openaudit --agentic`)";
/** The agentic auditors' settings example and the paragraph after it. */
export const agentSettings = {
	file: AGENT,
	code: codeIn(AGENT, HEADLESS)[0],
	text:
		paragraphsIn(AGENT, HEADLESS).find((p) =>
			p.startsWith("The available keys"),
		) ?? "",
};

/* ----------------------------------------------------------------- report */

export const SCORING_INTRO =
	"Each finding adds a penalty by severity, and an area's score decays as the penalty grows, so the first serious finding costs the most. Info findings never lower a score. The overall score is the average of the areas that were examined. These examples are computed by openaudit's own scoring code when the site is built:";

// CONTRIBUTING: "`critical` for directly exploitable …, `high` for …"
const severityLine =
	/\*\*Severity\*\*[^\n]+/.exec(readRepo("CONTRIBUTING.md"))?.[0] ?? "";
export const severities = [
	...severityLine.matchAll(
		/`(critical|high|medium|low|info)` for ([^,.]+?)(?=, and |, |\.)/g,
	),
].map((m) => ({ id: m[1] ?? "", text: m[2] ?? "" }));

export const label = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
export const plural = (n: number, s: string) =>
	`${n} ${s}${n === 1 ? "" : "s"}`;

/* --------------------------------------------------------------- HTTP API */

interface Operation {
	readonly summary?: string;
	readonly description?: string;
	readonly tags?: ReadonlyArray<string>;
}
/** Every operation in the generated OpenAPI document, in source order. */
export const apiOperations = Object.entries(
	openapi.paths as Record<string, Record<string, Operation>>,
).flatMap(([path, methods]) =>
	Object.entries(methods).map(([method, op]) => ({
		method: method.toUpperCase(),
		path,
		summary: op.summary ?? "",
		description: op.description ?? "",
	})),
);
export const apiServer = openapi.servers[0] ?? {
	url: "http://localhost:3000/api-reference",
	description: "",
};
export const apiInfo = openapi.info;

/** How to start apps/server; the variables are its .env.schema. */
export const API_RUN = `From a clone of the repository:

\`\`\`sh
bun install
CORS_ORIGIN=http://localhost:3001 bun run dev:server   # http://localhost:3000
\`\`\`

\`CORS_ORIGIN\` is required: the browser origin allowed to call the API. \`PORT\` changes the port. Behind a reverse proxy, set \`TRUST_PROXY=true\` so rate limits see the client address. \`ALLOW_PRIVATE_TARGETS=true\` lets URL audits reach private and loopback addresses; enable it only to audit your own internal services.

The API has no authentication. Anyone who can reach the server can use it, so keep it behind your own network controls if it should not be public. openaudit.se does not run this API.`;
