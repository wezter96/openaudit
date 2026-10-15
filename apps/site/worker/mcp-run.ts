/** What each MCP tool does, reading the site's own static build (env.ASSETS). */

export interface Assets {
	readonly fetch: (request: Request) => Promise<Response>;
}

/* ------------------------------------------------------------------- data */

interface Auditor {
	readonly id: string;
	readonly title: string;
	readonly description: string;
	readonly engine: string;
	readonly tool: string | null;
	readonly categories: ReadonlyArray<string>;
	readonly targets: ReadonlyArray<string>;
	readonly network: boolean;
	readonly optIn: boolean;
	readonly command: string;
	readonly url: string;
}
interface Playbook {
	readonly id: string;
	readonly title: string;
	readonly summary: string;
	readonly needs: ReadonlyArray<string>;
	readonly markdown: string;
}
interface Catalogue {
	readonly auditors: ReadonlyArray<Auditor>;
	readonly playbooks: ReadonlyArray<Playbook>;
}
interface Section {
	readonly page: string;
	readonly heading: string;
	readonly url: string;
	readonly text: string;
}
interface Docs {
	readonly sections: ReadonlyArray<Section>;
	readonly install: Readonly<Record<string, string>>;
}

/** Build output is immutable per deployment, so each isolate reads it once. */
const cache = new WeakMap<Assets, Map<string, Promise<unknown>>>();
const asset = <T>(assets: Assets, path: string): Promise<T> => {
	let files = cache.get(assets);
	if (!files) {
		files = new Map();
		cache.set(assets, files);
	}
	let file = files.get(path);
	if (!file) {
		file = assets
			.fetch(new Request(`https://openaudit.se${path}`))
			.then((r) => {
				if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
				return r.json();
			});
		// A failed read is retried by the next request.
		file.catch(() => files?.delete(path));
		files.set(path, file);
	}
	return file as Promise<T>;
};

/* ---------------------------------------------------------------- results */

export interface ToolResult {
	readonly content: ReadonlyArray<{ type: "text"; text: string }>;
	readonly structuredContent?: Record<string, unknown>;
	readonly isError?: boolean;
}
const ok = (
	text: string,
	structured?: Record<string, unknown>,
): ToolResult => ({
	content: [{ type: "text", text }],
	...(structured ? { structuredContent: structured } : {}),
});
export const fail = (text: string): ToolResult => ({
	content: [{ type: "text", text }],
	isError: true,
});

/** `value` must be one of `allowed`, which come from the data itself. */
const oneOf = (
	name: string,
	value: string | undefined,
	allowed: Iterable<string>,
) => {
	const set = [...new Set(allowed)].sort();
	return value === undefined || set.includes(value)
		? undefined
		: `Unknown ${name} "${value}". Use one of: ${set.join(", ")}.`;
};

const summary = (a: Auditor) => ({
	id: a.id,
	title: a.title,
	engine: a.engine,
	tool: a.tool,
	categories: a.categories,
	targets: a.targets,
	runsByDefault: !a.optIn,
	url: a.url,
});

/* ----------------------------------------------------------- list_auditors */

interface AuditorFilter {
	readonly category: string | undefined;
	readonly target: string | undefined;
	readonly engine: string | undefined;
	readonly words: ReadonlyArray<string>;
}

const filterOf = (args: Args): AuditorFilter => ({
	category: args.category as string | undefined,
	target: args.target as string | undefined,
	engine: args.engine as string | undefined,
	words: ((args.query as string | undefined) ?? "")
		.toLowerCase()
		.split(/\s+/)
		.filter(Boolean)
		.slice(0, 10),
});

const filterProblem = (
	auditors: ReadonlyArray<Auditor>,
	filter: AuditorFilter,
) =>
	oneOf(
		"category",
		filter.category,
		auditors.flatMap((a) => a.categories),
	) ??
	oneOf(
		"target",
		filter.target,
		auditors.flatMap((a) => a.targets),
	) ??
	oneOf(
		"engine",
		filter.engine,
		auditors.map((a) => a.engine),
	);

/** An unset filter value allows everything. */
const allows = (value: string | undefined, list: ReadonlyArray<string>) =>
	!value || list.includes(value);

const matches = (a: Auditor, filter: AuditorFilter) =>
	allows(filter.category, a.categories) &&
	allows(filter.target, a.targets) &&
	allows(filter.engine, [a.engine]) &&
	filter.words.every((w) =>
		`${a.id} ${a.title} ${a.tool ?? ""} ${a.description}`
			.toLowerCase()
			.includes(w),
	);

const auditorLine = (a: Auditor) =>
	`- \`${a.id}\` ${a.title} (${a.engine}${a.tool ? `, wraps ${a.tool}` : ""}; ${a.categories.join(", ")}; ${a.optIn ? "opt-in" : "runs by default"})`;

const listText = (
	hits: ReadonlyArray<Auditor>,
	shown: ReadonlyArray<Auditor>,
) =>
	hits.length
		? `${hits.length} auditor(s)${shown.length < hits.length ? `, showing ${shown.length}` : ""}:\n\n${shown
				.map(auditorLine)
				.join("\n")}`
		: "No auditors match.";

/* ------------------------------------------------------------- get_auditor */

const auditorText = (a: Auditor, playbook: Playbook | undefined) =>
	[
		`# ${a.title}`,
		`\`${a.id}\`: ${a.description}`,
		`- Engine: ${a.engine}${a.tool ? ` (wraps ${a.tool})` : ""}\n- Targets: ${a.targets.join(", ")}\n- Areas: ${a.categories.join(", ")}\n- Runs: ${a.optIn ? "opt-in, only with --only" : "by default when the target applies"}\n- Network: ${a.network ? "contacts services beyond the target" : "only the target itself"}`,
		`Run only this auditor:\n\n\`\`\`sh\n${a.command}\n\`\`\``,
		playbook ? `## Playbook\n\n${playbook.markdown}` : "",
		`Page: ${a.url}`,
	]
		.filter(Boolean)
		.join("\n\n");

const playbookField = (playbook: Playbook | undefined) =>
	playbook
		? {
				playbook: {
					title: playbook.title,
					summary: playbook.summary,
					needs: playbook.needs,
					markdown: playbook.markdown,
				},
			}
		: {};

/* ------------------------------------------------------------- search_docs */

const termsOf = (query: string) =>
	[
		...new Set(
			query
				.toLowerCase()
				.split(/[^\p{L}\p{N}._-]+/u)
				.filter((t) => t.length >= 2),
		),
	].slice(0, 8);

/** How often `term` occurs in `haystack`, counting to at most 20. */
const count = (haystack: string, term: string) => {
	let n = 0;
	for (
		let i = haystack.indexOf(term);
		i >= 0 && n < 20;
		i = haystack.indexOf(term, i + term.length)
	)
		n++;
	return n;
};

const scoreSection = (s: Section, terms: ReadonlyArray<string>) => {
	const heading = s.heading.toLowerCase();
	const text = s.text.toLowerCase();
	let score = 0;
	let matched = 0;
	for (const t of terms) {
		const n = count(heading, t) * 3 + count(text, t);
		if (n) matched++;
		score += n;
	}
	// Sections that contain every term rank first.
	return {
		s,
		score: score + (matched === terms.length ? 100 : 0),
		matched,
	};
};

const snippetOf = (text: string, terms: ReadonlyArray<string>) => {
	const flat = text.replace(/\s+/g, " ");
	const at = Math.max(
		0,
		Math.min(
			...terms.map((t) => flat.toLowerCase().indexOf(t)).filter((i) => i >= 0),
		) - 80,
	);
	return `${at > 0 ? "…" : ""}${flat.slice(at, at + 280).trim()}${at + 280 < flat.length ? "…" : ""}`;
};

const docsText = (
	results: ReadonlyArray<{
		page: string;
		heading: string;
		url: string;
		snippet: string;
	}>,
	terms: ReadonlyArray<string>,
) =>
	results.length
		? results
				.map((r) => `## ${r.page}: ${r.heading}\n${r.url}\n\n${r.snippet}`)
				.join("\n\n")
		: `Nothing in the docs matches "${terms.join(" ")}".`;

/* ------------------------------------------------------------------ tools */

export type Args = Record<string, unknown>;
export const RUN: Record<
	string,
	(args: Args, assets: Assets) => Promise<ToolResult>
> = {
	async list_auditors(args, assets) {
		const { auditors } = await asset<Catalogue>(assets, "/data/catalogue.json");
		const filter = filterOf(args);
		const problem = filterProblem(auditors, filter);
		if (problem) return fail(problem);
		const hits = auditors.filter((a) => matches(a, filter));
		const shown = hits.slice(0, (args.limit as number | undefined) ?? 50);
		return ok(listText(hits, shown), {
			total: hits.length,
			auditors: shown.map(summary),
		});
	},

	async get_auditor(args, assets) {
		const { auditors, playbooks } = await asset<Catalogue>(
			assets,
			"/data/catalogue.json",
		);
		const id = args.id as string;
		const a = auditors.find((x) => x.id === id);
		if (!a)
			return fail(`No auditor with id "${id}". Use list_auditors to find one.`);
		const playbook = playbooks.find((p) => p.id === a.id);
		return ok(auditorText(a, playbook), {
			...summary(a),
			description: a.description,
			network: a.network,
			command: a.command,
			...playbookField(playbook),
		});
	},

	async search_docs(args, assets) {
		const { sections } = await asset<Docs>(assets, "/data/docs.json");
		const terms = termsOf(args.query as string);
		if (!terms.length)
			return fail("The query needs a word of two or more letters.");
		const results = sections
			.map((s) => scoreSection(s, terms))
			.filter((r) => r.matched > 0)
			.sort((a, b) => b.score - a.score)
			.slice(0, (args.limit as number | undefined) ?? 5)
			.map(({ s }) => ({
				page: s.page,
				heading: s.heading,
				url: s.url,
				snippet: snippetOf(s.text, terms),
			}));
		return ok(docsText(results, terms), { results });
	},

	async get_config_schema(_args, assets) {
		const schema = await asset<Record<string, unknown>>(
			assets,
			"/schema/config.json",
		);
		return ok(
			`The JSON Schema of openaudit.config.json (https://openaudit.se/schema/config.json):\n\n\`\`\`json\n${JSON.stringify(schema, null, 2)}\n\`\`\``,
			{ url: "https://openaudit.se/schema/config.json", schema },
		);
	},

	async get_install_instructions(args, assets) {
		const { install } = await asset<Docs>(assets, "/data/docs.json");
		const method = args.method as string | undefined;
		const problem = oneOf("method", method, Object.keys(install));
		if (problem) return fail(problem);
		const picked = method
			? { [method]: install[method] ?? "" }
			: { ...install };
		return ok(
			Object.entries(picked)
				.map(([k, v]) => (method ? v : `<!-- ${k} -->\n${v}`))
				.join("\n\n"),
			{ instructions: picked },
		);
	},
};
