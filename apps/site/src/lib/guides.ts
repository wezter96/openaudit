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

type FrontMatter = Partial<Record<string, unknown>>;
/** A guide's file name in src/guides/, such as `mcp-security.md`. */
type FileName = string;
/** A front matter key. */
type FieldName = string;
/** A guide's whole Markdown file, front matter included. */
type FileText = string;
/** The last part of a guide's URL. */
type Slug = string;

/** A repository folder of Markdown pages, such as `apps/site/src/guides`. */
type Folder = string;
/** A page's repository path, such as `apps/site/src/guides/mcp-security.md`. */
type FilePath = string;

/** A required front matter field, trimmed. */
const field = (meta: FrontMatter, key: FieldName, file: FilePath) => {
	const value = meta[key];
	if (typeof value !== "string" || !value.trim())
		throw new Error(`${file}: missing ${key}`);
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

/** Throws on the first house rule the guide breaks. */
const checkGuide = (guide: Guide, text: FileText) => {
	const broken = HOUSE_RULES.find((rule) => rule.breaks(guide, text));
	if (broken) throw new Error(`${guide.file}: ${broken.message}`);
};

const load = (folder: Folder, name: FileName): Guide => {
	const file = `${folder}/${name}`;
	const text = readFileSync(join(ROOT, file), "utf8");
	const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
	if (!m) throw new Error(`${file}: no front matter`);
	const meta = parse(m[1] ?? "") as FrontMatter;
	const guide: Guide = {
		slug: name.replace(/\.md$/, ""),
		title: field(meta, "title", file),
		heading: field(meta, "heading", file),
		description: field(meta, "description", file),
		order: typeof meta.order === "number" ? meta.order : 99,
		body: (m[2] ?? "").trim(),
		file,
	};
	checkGuide(guide, text);
	return guide;
};

/**
 * Every Markdown page in a repository folder, checked against the house
 * rules and sorted by `order`. The policy pages (src/lib/policies.ts) are
 * written the same way.
 */
export const loadPages = (folder: Folder): ReadonlyArray<Guide> =>
	readdirSync(join(ROOT, folder))
		.filter((f) => f.endsWith(".md"))
		.map((name) => load(folder, name))
		.sort((a, b) => a.order - b.order || a.slug.localeCompare(b.slug));

export const guides = loadPages("apps/site/src/guides");

export const guidePath = (slug: Slug) => `/guides/${slug}/`;
