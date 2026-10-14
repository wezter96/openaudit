/**
 * Guides: short pages that each answer one search, at /guides/<slug>/. Each
 * is a Markdown file in src/guides/ with front matter:
 *
 *   title:        the <title>, at most 60 characters
 *   heading:      the H1
 *   description:  the meta description, at most 155 characters
 *   order:        position in the footer and llms.txt
 *
 * The build fails on a missing field, an over-long title or description, or
 * a dash used as punctuation (the site's house style).
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { ROOT } from "./markdown";

export interface Guide {
	readonly slug: string;
	readonly title: string;
	readonly heading: string;
	readonly description: string;
	readonly order: number;
	/** Markdown, without the front matter or an H1. */
	readonly body: string;
	/** Repository path of the source file, for relative links. */
	readonly file: string;
}

const FILE_PREFIX = "apps/site/src/guides";
const DIR = join(ROOT, FILE_PREFIX);

const load = (name: string): Guide => {
	const slug = name.replace(/\.md$/, "");
	const text = readFileSync(join(DIR, name), "utf8");
	const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
	if (!m) throw new Error(`guides/${name}: no front matter`);
	const meta = parse(m[1] ?? "") as Partial<Record<string, unknown>>;
	const field = (key: string) => {
		const value = meta[key];
		if (typeof value !== "string" || !value.trim())
			throw new Error(`guides/${name}: missing ${key}`);
		return value.trim();
	};
	const guide: Guide = {
		slug,
		title: field("title"),
		heading: field("heading"),
		description: field("description"),
		order: typeof meta.order === "number" ? meta.order : 99,
		body: (m[2] ?? "").trim(),
		file: `${FILE_PREFIX}/${name}`,
	};
	if (guide.title.length > 60)
		throw new Error(`guides/${name}: title is over 60 characters`);
	if (guide.description.length > 155)
		throw new Error(`guides/${name}: description is over 155 characters`);
	if (/[–—]/.test(text))
		throw new Error(`guides/${name}: use a comma, colon or period, not a dash`);
	if (/^#\s/m.test(guide.body))
		throw new Error(
			`guides/${name}: the H1 comes from "heading"; use ## in the body`,
		);
	return guide;
};

export const guides: ReadonlyArray<Guide> = readdirSync(DIR)
	.filter((f) => f.endsWith(".md"))
	.map(load)
	.sort((a, b) => a.order - b.order || a.slug.localeCompare(b.slug));

export const guidePath = (slug: string) => `/guides/${slug}/`;
