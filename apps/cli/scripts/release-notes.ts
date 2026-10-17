/**
 * GitHub release notes from commit subjects: every published commit is one
 * bullet, so a subject is written for someone reading the release page and
 * the body carries the rationale. Ported from herdr-gpui, which does the same
 * with git-cliff.
 *
 *   bun apps/cli/scripts/release-notes.ts v0.3.2   # the notes for a tag
 *   bun apps/cli/scripts/release-notes.ts HEAD     # what is not released yet
 */

export interface Commit {
	readonly subject: string;
	readonly body: string;
}

export interface Range {
	/** The previous release tag, or undefined for the first release. */
	readonly previous?: string;
	/** What the compare link ends at: the tag, or `main` for a preview. */
	readonly target: string;
}

const SECTIONS = [
	"Added",
	"Changed",
	"Fixed",
	"Security",
	"Documentation",
] as const;
type Section = (typeof SECTIONS)[number];

const TYPE_SECTION: Readonly<Record<string, Section>> = {
	feat: "Added",
	fix: "Fixed",
	perf: "Changed",
	revert: "Changed",
	docs: "Documentation",
};
// A refactor changes no behaviour by definition. The Code Health pass alone
// would have put about 35 of them in v0.3.0's notes.
const HIDDEN_TYPES = new Set([
	"build",
	"chore",
	"ci",
	"refactor",
	"style",
	"test",
]);
// The site, the badge service and its scanner deploy on their own. None of
// them is in the npm package these notes describe.
const HIDDEN_SCOPES = new Set(["site", "badge", "badge-scanner"]);
// Merges, and the owner's version-bump commits ("Release 0.3.1").
const SKIPPED = /^(Merge |Release \d)/;
const SUBJECT =
	/^(?<type>[a-z]+)(?:\((?<scope>[^)]+)\))?(?<bang>!)?: (?<text>.+)$/;
const BREAKING_FOOTER = /^BREAKING[ -]CHANGE: /m;
const REPO = "https://github.com/wezter96/openaudit";

interface Entry {
	readonly section: Section;
	readonly line: string;
}

// A subject that starts with an identifier (`code.health`, `--browser`,
// `npm/pnpm`) keeps its case: capitalising would misspell it.
const IDENTIFIER = /^(\S*[._/`]|-)/;

const tidy = (text: string): string => {
	const trimmed = text.trim().replace(/\.$/, "");
	if (IDENTIFIER.test(trimmed)) return trimmed;
	return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
};

const scoped = (scope: string | undefined, text: string): string =>
	scope === undefined ? tidy(text) : `[${scope}] ${tidy(text)}`;

interface Parsed {
	/** Undefined when the subject is not conventional. */
	readonly type?: string;
	readonly scope?: string;
	readonly text: string;
	readonly breaking: boolean;
}

const parse = (commit: Commit): Parsed => {
	const subject = commit.subject.trim();
	const groups = SUBJECT.exec(subject)?.groups;
	return {
		type: groups?.type,
		scope: groups?.scope,
		text: groups?.text ?? subject,
		breaking: groups?.bang === "!" || BREAKING_FOOTER.test(commit.body),
	};
};

const hidden = ({ type, scope }: Parsed): boolean =>
	(type !== undefined && HIDDEN_TYPES.has(type)) ||
	(scope !== undefined && HIDDEN_SCOPES.has(scope));

/** A security fix is its own section; anything not conventional is Changed. */
const sectionOf = ({ type, scope }: Parsed): Section => {
	if (scope === "security") return "Security";
	return (type === undefined ? undefined : TYPE_SECTION[type]) ?? "Changed";
};

/** The section and bullet for one commit, or undefined when users never see it. */
export function entryFor(commit: Commit): Entry | undefined {
	if (SKIPPED.test(commit.subject.trim())) return undefined;
	const parsed = parse(commit);
	// The Security heading already says what a `security` scope would.
	const scope = parsed.scope === "security" ? undefined : parsed.scope;
	if (parsed.breaking) {
		return {
			section: "Changed",
			line: `**BREAKING:** ${scoped(parsed.scope, parsed.text)}`,
		};
	}
	if (sectionOf(parsed) !== "Security" && hidden(parsed)) return undefined;
	return { section: sectionOf(parsed), line: scoped(scope, parsed.text) };
}

const compareLink = (range: Range): string =>
	range.previous === undefined
		? ""
		: `**Full Changelog**: ${REPO}/compare/${range.previous}...${range.target}`;

/** The Markdown release body for commits listed oldest first. */
export function releaseNotes(
	commits: ReadonlyArray<Commit>,
	range: Range,
): string {
	const bySection = new Map<Section, Set<string>>();
	for (const commit of commits) {
		const entry = entryFor(commit);
		if (entry === undefined) continue;
		const lines = bySection.get(entry.section) ?? new Set<string>();
		lines.add(entry.line);
		bySection.set(entry.section, lines);
	}
	const blocks = SECTIONS.flatMap((section) => {
		const lines = bySection.get(section);
		if (lines === undefined) return [];
		return [`## ${section}\n\n${[...lines].map((l) => `- ${l}`).join("\n")}`];
	});
	if (blocks.length === 0)
		blocks.push("Maintenance release: no user-facing changes.");
	const link = compareLink(range);
	if (link !== "") blocks.push(link);
	return `${blocks.join("\n\n")}\n`;
}

/** `git log --format=%s%x1f%b%x1e` output, split into commits. */
export function parseLog(log: string): Commit[] {
	return log
		.split("\x1e")
		.map((record) => record.trim())
		.filter((record) => record !== "")
		.map((record) => {
			const [subject = "", body = ""] = record.split("\x1f");
			return { subject, body };
		});
}

const git = (...args: string[]): string | undefined => {
	const proc = Bun.spawnSync(["git", ...args], {
		stdout: "pipe",
		stderr: "pipe",
	});
	return proc.exitCode === 0 ? proc.stdout.toString().trim() : undefined;
};

if (import.meta.main) {
	const ref = process.argv[2];
	if (ref === undefined || ref === "") {
		console.error("usage: bun apps/cli/scripts/release-notes.ts <tag|HEAD>");
		process.exit(2);
	}
	const preview = ref === "HEAD";
	// A tag's notes start after the release before it. A preview starts after
	// the newest release, which may be HEAD itself.
	const previous = git(
		"describe",
		"--tags",
		"--abbrev=0",
		"--match",
		"v*",
		preview ? ref : `${ref}^`,
	);
	const revisions = previous === undefined ? ref : `${previous}..${ref}`;
	const log = git(
		"log",
		"--no-merges",
		"--reverse",
		"--format=%s%x1f%b%x1e",
		revisions,
	);
	if (log === undefined) {
		console.error(`git log ${revisions} failed: is ${ref} a commit here?`);
		process.exit(1);
	}
	const target = preview ? "main" : ref;
	process.stdout.write(releaseNotes(parseLog(log), { previous, target }));
}
