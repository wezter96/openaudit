/**
 * Renders markdown that lives elsewhere in the repository (README, the CLI
 * and agent READMEs, CONTRIBUTING), so the docs never drift from it. Links
 * are rewritten to the matching site page or to GitHub, headings get ids,
 * and code is highlighted with classes only, so the CSP needs no inline
 * styles.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { Marked, type Token, type Tokens } from "marked";
import { BLOB, REPO, u } from "./site";

/** A path inside the repository, e.g. "apps/cli/README.md". */
export type RepoPath = string;
/** Markdown source. */
export type Markdown = string;
/** A heading's text, as written after its #s. */
export type HeadingText = string;
/** A link target as written in markdown. */
type Href = string;
/** Text to show as is, before HTML escaping. */
type PlainText = string;
/** A code block's language tag, e.g. "sh". */
type Language = string;

/** The repository root: the nearest directory up from cwd with action.yml. */
export const ROOT = (() => {
	let dir = process.cwd();
	while (!existsSync(join(dir, "action.yml"))) {
		const up = dirname(dir);
		if (up === dir) throw new Error("Run the site build inside the repository");
		dir = up;
	}
	return dir;
})();

export const readRepo = (path: RepoPath): string =>
	readFileSync(join(ROOT, path), "utf8");

export const slugify = (text: HeadingText): string =>
	text
		.toLowerCase()
		.replace(/<[^>]+>/g, "")
		.replace(/[`*_]/g, "")
		.replace(/[^\p{L}\p{N}\s-]/gu, "")
		.trim()
		.replace(/\s+/g, "-");

/** Repository files that have a page of their own on the site. */
const PAGES: Record<string, string> = {
	"README.md#quick-start": "/docs/",
	"README.md#what-it-audits": "/developers/#areas",
	"README.md#languages-and-ecosystems": "/developers/#cov-langs",
	"README.md#what-it-checks-by-target": "/developers/#cov-targets",
	"README.md#the-report": "/docs/report/",
	"README.md#with-ai-agents": "/docs/agents/",
	"README.md#in-ci": "/docs/ci/",
	"README.md#configuration": "/docs/configuration/",
	"README.md#safety": "/docs/safety/",
	"README.md#contributing": "/docs/contributing/",
	"README.md#community": "/#trust",
	"README.md#ci": "/docs/ci/",
	"integrations/README.md": "/docs/ci/",
	"apps/cli/README.md": "/docs/cli/",
	"apps/cli/README.md#configuration": "/docs/configuration/",
	"apps/cli/README.md#agent-mode---json": "/docs/cli/#agent-mode---json",
	"apps/cli/README.md#mcp-server": "/docs/agents/#mcp-server",
	"apps/cli/README.md#mcp-over-http": "/docs/agents/#mcp-over-http",
	"apps/cli/README.md#ci-github-code-scanning": "/docs/ci/",
	"packages/agent/README.md": "/docs/agents/#playbooks",
	"CONTRIBUTING.md": "/docs/contributing/",
	"CONTRIBUTING.md#setup": "/docs/contributing/#setup",
};

const EXTERNAL: Record<string, string> = {
	"https://openaudit.se/report/": "/report/",
};

/** A link that needs no repository lookup: another scheme or a site path. */
const directLink = (href: Href): string | undefined => {
	if (EXTERNAL[href]) return u(EXTERNAL[href]);
	if (/^[a-z]+:/i.test(href)) return href;
	// A site path, as the guides write them.
	if (href.startsWith("/")) return u(href);
	return undefined;
};

/** A relative link resolved against the repository file it appears in. */
interface RepoLink {
	readonly file: RepoPath;
	/** The link's path part; empty for a same-file anchor. */
	readonly path: string;
	readonly hash: string;
}

const repoLink = (href: Href, from: RepoPath): RepoLink => {
	const [path = "", hash = ""] = href.split("#");
	const file = path
		? posix.normalize(posix.join(posix.dirname(from), path))
		: from;
	return { file, path, hash };
};

/** The site page (or same-page anchor) a repository link maps to, if any. */
const siteLink = ({ file, path, hash }: RepoLink): string | undefined => {
	const key = hash ? `${file}#${hash}` : file;
	if (PAGES[key]) return u(PAGES[key]);
	if (!path && hash) return `#${hash}`;
	if (!hash && PAGES[file]) return u(PAGES[file]);
	return undefined;
};

/** The repository file or folder on GitHub. */
const githubLink = ({ file, hash }: RepoLink): string => {
	const tree = file.endsWith("/") || !/\.[a-z0-9]+$/i.test(file);
	const url = tree ? `${REPO}/tree/main/${file}` : `${BLOB}/${file}`;
	return hash ? `${url}#${hash}` : url;
};

/** Resolve a link found in `from` (a repo path) to a site or GitHub URL. */
export const resolveLink = (href: Href, from: RepoPath): string => {
	const direct = directLink(href);
	if (direct !== undefined) return direct;
	const link = repoLink(href, from);
	return siteLink(link) ?? githubLink(link);
};

const esc = (s: PlainText) =>
	s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const span = (cls: "c" | "k" | "s", s: string) =>
	`<span class="${cls}">${s}</span>`;

/**
 * Wrap each match of `re` in a span chosen by `classify`, escaping the text
 * between matches; one pass, so markup is never matched twice.
 */
const tokens = (
	text: PlainText,
	re: RegExp,
	classify: (m: RegExpExecArray) => string,
): string => {
	let out = "";
	let last = 0;
	for (const m of text.matchAll(re)) {
		const at = m.index ?? 0;
		out += esc(text.slice(last, at)) + classify(m as RegExpExecArray);
		last = at + m[0].length;
	}
	return out + esc(text.slice(last));
};

const STRING = /"(?:[^"\\]|\\.)*"/;

const shellLine = (line: PlainText) => {
	const m = /^(.*?)(\s#\s.*|^#.*)$/.exec(line);
	const body = m ? (m[1] ?? "") : line;
	const comment = m ? (m[2] ?? "") : "";
	const cmd = /^(\s*)([\w./-]+)(.*)$/.exec(body);
	const highlighted = cmd
		? `${esc(cmd[1] ?? "")}${span("k", esc(cmd[2] ?? ""))}${esc(cmd[3] ?? "")}`
		: esc(body);
	return highlighted + (comment ? span("c", esc(comment)) : "");
};

const jsonToken = (m: RegExpExecArray) => {
	if (m[3]) return span("c", esc(m[3]));
	return m[2]
		? span("k", esc(m[1] ?? "")) + esc(m[2])
		: span("s", esc(m[1] ?? ""));
};

const yamlStrings = (t: PlainText) =>
	tokens(t, new RegExp(STRING.source, "g"), (m) => span("s", esc(m[0])));

const yamlLine = (line: PlainText) => {
	const comment = /(^|\s)#.*$/.exec(line);
	const body = comment ? line.slice(0, comment.index) : line;
	const tail = comment ? span("c", esc(line.slice(comment.index))) : "";
	const key = /^(\s*-?\s*)([\w.\-[\]]+)(\s*[:=])(.*)$/.exec(body);
	return (
		(key
			? `${esc(key[1] ?? "")}${span("k", esc(key[2] ?? ""))}${esc(key[3] ?? "")}${yamlStrings(key[4] ?? "")}`
			: yamlStrings(body)) + tail
	);
};

const byLine =
	(highlightLine: (line: PlainText) => string) => (code: PlainText) =>
		code.split("\n").map(highlightLine).join("\n");

const highlightJson = (code: PlainText) =>
	tokens(
		code,
		new RegExp(`(${STRING.source})(\\s*:)?|(\\/\\/.*$)`, "gm"),
		jsonToken,
	);

/** Highlighters by language tag; anything else is only escaped. */
const HIGHLIGHTERS = new Map<Language, (code: PlainText) => string>([
	...["sh", "bash", "shell", "console", "zsh"].map(
		(l) => [l, byLine(shellLine)] as const,
	),
	...["json", "jsonc"].map((l) => [l, highlightJson] as const),
	...["yaml", "yml", "toml"].map((l) => [l, byLine(yamlLine)] as const),
]);

/** Comments, strings and keys for the handful of languages the docs use. */
export const highlight = (code: PlainText, lang: Language): string =>
	(HIGHLIGHTERS.get(lang.toLowerCase()) ?? esc)(code);

const parser = (from: RepoPath, shift: number) => {
	const md = new Marked({ gfm: true });
	md.use({
		walkTokens(token: Token) {
			if (token.type === "link") {
				const link = token as Tokens.Link;
				link.href = resolveLink(link.href, from);
			}
		},
		renderer: {
			heading({ tokens, depth, text }: Tokens.Heading) {
				const level = Math.min(6, depth + shift);
				return `<h${level} id="${slugify(text)}">${this.parser.parseInline(tokens)}</h${level}>\n`;
			},
			code({ text, lang }: Tokens.Code) {
				const language = (lang ?? "").split(/\s/)[0] ?? "";
				return `<div class="code"><pre data-lang="${esc(language)}" tabindex="0"><code>${highlight(text, language)}</code></pre><button class="copy needs-js" type="button" data-copy>Copy</button></div>\n`;
			},
			table(token: Tokens.Table) {
				// A blank header cell still needs a name for screen readers.
				const cell = (c: Tokens.TableCell, tag: "th" | "td") =>
					`<${tag}${c.align ? ` class="a-${c.align}"` : ""}>${this.parser.parseInline(c.tokens) || (tag === "th" ? '<span class="sr-only">Details</span>' : "")}</${tag}>`;
				const head = `<tr>${token.header.map((c) => cell(c, "th")).join("")}</tr>`;
				const body = token.rows
					.map((r) => `<tr>${r.map((c) => cell(c, "td")).join("")}</tr>`)
					.join("");
				return `<div class="table"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>\n`;
			},
			link({ href, tokens }: Tokens.Link) {
				const ext =
					/^https?:/.test(href) && !href.startsWith("https://openaudit.se");
				return `<a href="${esc(href)}"${ext ? ' rel="noopener"' : ""}>${this.parser.parseInline(tokens)}</a>`;
			},
		},
	});
	return md;
};

/** A source line; `heading` is set for headings outside code fences. */
interface Line {
	readonly text: string;
	readonly heading:
		| { readonly level: number; readonly title: string | undefined }
		| undefined;
}

const headingOf = (line: string) => {
	const m = /^(#{1,6})\s+(.*)$/.exec(line);
	return m ? { level: m[1]?.length ?? 0, title: m[2]?.trim() } : undefined;
};

const linesOf = (source: Markdown): Line[] => {
	let fenced = false;
	return source.split("\n").map((text) => {
		if (/^(```|~~~)/.test(text)) fenced = !fenced;
		return { text, heading: fenced ? undefined : headingOf(text) };
	});
};

/** From the heading at `start` to the next heading of the same or a higher level. */
const sectionLines = (lines: ReadonlyArray<Line>, start: number) => {
	const level = lines[start]?.heading?.level ?? 0;
	const end = lines.findIndex(
		(l, i) =>
			i > start && (l.heading?.level ?? Number.POSITIVE_INFINITY) <= level,
	);
	return lines.slice(start, end < 0 ? undefined : end);
};

/**
 * One section of a markdown file: from the heading whose text is `heading`
 * to the next heading of the same or a higher level. `body` drops the
 * heading line itself.
 */
export const section = (
	source: Markdown,
	heading: HeadingText,
	options: { readonly body?: boolean } = {},
): string => {
	const lines = linesOf(source);
	const start = lines.findIndex((l) => l.heading?.title === heading);
	if (start < 0) throw new Error(`No section "${heading}"`);
	return sectionLines(lines, start)
		.slice(options.body ? 1 : 0)
		.map((l) => l.text)
		.join("\n")
		.trim();
};

/** Render repository markdown; `shift` demotes headings (## -> ### with 1). */
export const render = (source: Markdown, from: RepoPath, shift = 0): string =>
	parser(from, shift).parse(source, { async: false }) as string;

/** Render one section of a repository file. */
export const renderSection = (
	file: RepoPath,
	heading: HeadingText,
	options: { readonly body?: boolean; readonly shift?: number } = {},
): string =>
	render(section(readRepo(file), heading, options), file, options.shift ?? 0);

/** Inline markdown (a table cell, a bullet) rendered without a paragraph. */
export const inline = (
	source: Markdown,
	from: RepoPath = "README.md",
): string => parser(from, 0).parseInline(source, { async: false }) as string;

export interface MdTable {
	readonly header: ReadonlyArray<string>;
	readonly rows: ReadonlyArray<ReadonlyArray<string>>;
}

/** The first table in a section, each cell as raw inline markdown. */
export const tableIn = (file: RepoPath, heading: HeadingText): MdTable => {
	const tokens = new Marked().lexer(section(readRepo(file), heading));
	const table = tokens.find((t): t is Tokens.Table => t.type === "table");
	if (!table) throw new Error(`No table under "${heading}" in ${file}`);
	return {
		header: table.header.map((c) => c.text),
		rows: table.rows.map((r) => r.map((c) => c.text)),
	};
};

/** Bullets of the first list in a section, as raw inline markdown. */
export const listIn = (file: RepoPath, heading: HeadingText): string[] => {
	const tokens = new Marked().lexer(section(readRepo(file), heading));
	const list = tokens.find((t): t is Tokens.List => t.type === "list");
	return list ? list.items.map((i) => i.text) : [];
};

/** Bullets of the first list anywhere in a file before its first `##`. */
export const introListIn = (file: RepoPath): string[] => {
	const intro = readRepo(file).split(/\n## /)[0] ?? "";
	const list = new Marked()
		.lexer(intro)
		.find((t): t is Tokens.List => t.type === "list");
	return list ? list.items.map((i) => i.text) : [];
};

/** Paragraphs of a section (no tables, lists or code), as raw markdown. */
export const paragraphsIn = (file: RepoPath, heading: HeadingText): string[] =>
	new Marked()
		.lexer(section(readRepo(file), heading, { body: true }))
		.filter((t): t is Tokens.Paragraph => t.type === "paragraph")
		.map((p) => p.text);

/** Code blocks of a section, in order. */
export const codeIn = (file: RepoPath, heading: HeadingText): Tokens.Code[] =>
	new Marked()
		.lexer(section(readRepo(file), heading))
		.filter((t): t is Tokens.Code => t.type === "code");

/** Paragraphs between a file's title and its first `##` heading. */
export const introParagraphsIn = (file: RepoPath): string[] =>
	new Marked()
		.lexer(readRepo(file).split(/\n## /)[0] ?? "")
		.filter((t): t is Tokens.Paragraph => t.type === "paragraph")
		.map((p) => p.text);

/** `source` with one sub-section (heading and body) removed. */
export const withoutSection = (
	source: Markdown,
	heading: HeadingText,
): string => {
	const cut = section(source, heading);
	return source
		.replace(cut, "")
		.replace(/\n{3,}/g, "\n\n")
		.trim();
};
