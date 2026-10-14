/**
 * WebMCP: read-only tools for an agent driving this page in a browser that
 * implements `document.modelContext` (older builds: `navigator.modelContext`).
 * site.ts loads this module only when the API exists, so elsewhere it costs
 * nothing. The tools read /data/catalogue.json from this origin and navigate
 * within the site; they change nothing.
 */

interface Auditor {
	readonly id: string;
	readonly title: string;
	readonly description: string;
	readonly engine: string;
	readonly tool: string | null;
	readonly categories: ReadonlyArray<string>;
	readonly targets: ReadonlyArray<string>;
	readonly optIn: boolean;
	readonly command: string;
	readonly url: string;
}
interface Catalogue {
	readonly version: string;
	readonly pages: ReadonlyArray<{
		readonly path: string;
		readonly title: string;
	}>;
	readonly auditors: ReadonlyArray<Auditor>;
	readonly playbooks: ReadonlyArray<{
		readonly id: string;
		readonly summary: string;
	}>;
}
interface ToolResult {
	readonly content: ReadonlyArray<{
		readonly type: "text";
		readonly text: string;
	}>;
	readonly isError?: boolean;
}
interface Tool {
	readonly name: string;
	readonly description: string;
	readonly inputSchema: object;
	readonly annotations?: { readonly readOnlyHint?: boolean };
	readonly execute: (input: Record<string, unknown>) => Promise<ToolResult>;
}
interface ModelContext {
	registerTool: (tool: Tool, options?: { signal?: AbortSignal }) => unknown;
}

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const text = (t: string, isError = false): ToolResult => ({
	content: [{ type: "text", text: t }],
	...(isError ? { isError } : {}),
});

let catalogue: Promise<Catalogue> | undefined;
const load = () => {
	catalogue ??= fetch(`${BASE}/data/catalogue.json`).then((r) => {
		if (!r.ok) throw new Error(`catalogue: HTTP ${r.status}`);
		return r.json() as Promise<Catalogue>;
	});
	return catalogue;
};
const str = (v: unknown, max = 200) =>
	typeof v === "string" ? v.trim().slice(0, max) : "";

const line = (a: Auditor) =>
	`- ${a.id}: ${a.title} (${a.engine}${a.tool ? `, wraps ${a.tool}` : ""}; ${a.categories.join(", ")}; ${a.optIn ? "opt-in" : "runs by default"})`;

const tools: Tool[] = [
	{
		name: "search_auditors",
		description:
			"Search openaudit's auditor catalogue by text, area or target kind. Read-only; returns ids, titles and areas.",
		inputSchema: {
			type: "object",
			properties: {
				query: {
					type: "string",
					description: "Words to match in the id, title, tool or description",
				},
				category: {
					type: "string",
					description: "Area, e.g. security, accessibility, seo",
				},
				target: {
					type: "string",
					description: "Target kind, e.g. codebase, url, container",
				},
			},
			additionalProperties: false,
		},
		annotations: { readOnlyHint: true },
		async execute(input) {
			const { auditors } = await load();
			const words = str(input.query).toLowerCase().split(/\s+/).filter(Boolean);
			const category = str(input.category, 40);
			const target = str(input.target, 40);
			const hits = auditors.filter(
				(a) =>
					(!category || a.categories.includes(category)) &&
					(!target || a.targets.includes(target)) &&
					words.every((w) =>
						`${a.id} ${a.title} ${a.tool ?? ""} ${a.description}`
							.toLowerCase()
							.includes(w),
					),
			);
			if (!hits.length) return text("No auditors match.");
			return text(
				`${hits.length} auditor(s):\n${hits.slice(0, 50).map(line).join("\n")}`,
			);
		},
	},
	{
		name: "get_auditor",
		description:
			"One openaudit auditor by id: what it checks, its targets and areas, and the command that runs only it. Read-only.",
		inputSchema: {
			type: "object",
			properties: {
				id: { type: "string", description: "Auditor id, e.g. code.secrets" },
			},
			required: ["id"],
			additionalProperties: false,
		},
		annotations: { readOnlyHint: true },
		async execute(input) {
			const { auditors, playbooks } = await load();
			const id = str(input.id, 100);
			const a = auditors.find((x) => x.id === id);
			if (!a)
				return text(
					`No auditor with id "${id}". Use search_auditors to find one.`,
					true,
				);
			const playbook = playbooks.find((p) => p.id === a.id);
			return text(
				[
					`${a.title} (${a.id})`,
					a.description,
					`Targets: ${a.targets.join(", ")}. Areas: ${a.categories.join(", ")}.`,
					`Run only this auditor: ${a.command}`,
					playbook ? `Playbook: ${playbook.summary}` : "",
					`Page: ${a.url}`,
				]
					.filter(Boolean)
					.join("\n"),
			);
		},
	},
	{
		name: "open_docs_page",
		description:
			"Navigate this tab to a page of the openaudit site (docs, auditor catalogue, guides, live report).",
		inputSchema: {
			type: "object",
			properties: {
				path: {
					type: "string",
					description:
						'Site path from the list returned on error, e.g. "/docs/cli/"',
				},
			},
			required: ["path"],
			additionalProperties: false,
		},
		async execute(input) {
			const { pages, auditors } = await load();
			const path = str(input.path, 200);
			const known =
				pages.some((p) => p.path === path) ||
				auditors.some((a) => `/auditors/${a.id}/` === path);
			if (!known)
				return text(
					`Unknown page "${path}". Pages:\n${pages.map((p) => `- ${p.path} (${p.title})`).join("\n")}\nAuditor pages are /auditors/<id>/.`,
					true,
				);
			location.assign(`${BASE}${path}`);
			return text(`Opening ${path}.`);
		},
	},
];

const context = ((document as unknown as { modelContext?: ModelContext })
	.modelContext ??
	(navigator as unknown as { modelContext?: ModelContext }).modelContext) as
	| ModelContext
	| undefined;
if (context && typeof context.registerTool === "function") {
	// Unregister when the page goes away (including into the back/forward cache).
	const controller = new AbortController();
	addEventListener("pagehide", () => controller.abort(), { once: true });
	for (const tool of tools) {
		Promise.resolve(
			context.registerTool(tool, { signal: controller.signal }),
		).catch(() => {
			/* a tool the browser refuses is simply not offered */
		});
	}
}
