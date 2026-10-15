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

type FrontMatter = Partial<Record<string, unknown>>;
/** A guide's file name in src/guides/, such as `mcp-security.md`. */
type FileName = string;
/** A front matter key. */
type FieldName = string;
/** A guide's whole Markdown file, front matter included. */
type FileText = string;
/** The last part of a guide's URL. */
type Slug = string;

/** A required front matter field, trimmed; `name` is the guide's file name. */
const field = (meta: FrontMatter, key: FieldName, name: FileName) => {
	const value = meta[key];
	if (typeof value !== "string" || !value.trim())
		throw new Error(`guides/${name}: missing ${key}`);
	return value.trim();
};

/** A house rule: whether a guide (and its whole file text) breaks it. */
interface HouseRule {
	readonly breaks: (guide: Guide, text: FileText) => boolean;
	readonly message: string;
}

const HOUSE_RULES: ReadonlyArray<HouseRule> = [
	{
		breaks: (guide) => guide.title.length > 60,
		message: "title is over 60 characters",
	},
	{
		breaks: (guide) => guide.description.length > 155,
		message: "description is over 155 characters",
	},
	{
		breaks: (_, text) => /[–—]/.test(text),
		message: "use a comma, colon or period, not a dash",
	},
	{
		breaks: (guide) => /^#\s/m.test(guide.body),
		message: 'the H1 comes from "heading"; use ## in the body',
	},
];

/** Throws on the first house rule the guide in file `name` breaks. */
const checkGuide = (guide: Guide, text: FileText, name: FileName) => {
	const broken = HOUSE_RULES.find((rule) => rule.breaks(guide, text));
	if (broken) throw new Error(`guides/${name}: ${broken.message}`);
};

const load = (name: FileName): Guide => {
	const text = readFileSync(join(DIR, name), "utf8");
	const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
	if (!m) throw new Error(`guides/${name}: no front matter`);
	const meta = parse(m[1] ?? "") as FrontMatter;
	const guide: Guide = {
		slug: name.replace(/\.md$/, ""),
		title: field(meta, "title", name),
		heading: field(meta, "heading", name),
		description: field(meta, "description", name),
		order: typeof meta.order === "number" ? meta.order : 99,
		body: (m[2] ?? "").trim(),
		file: `${FILE_PREFIX}/${name}`,
	};
	checkGuide(guide, text, name);
	return guide;
};

export const guides: ReadonlyArray<Guide> = readdirSync(DIR)
	.filter((f) => f.endsWith(".md"))
	.map(load)
	.sort((a, b) => a.order - b.order || a.slug.localeCompare(b.slug));

export const guidePath = (slug: Slug) => `/guides/${slug}/`;
