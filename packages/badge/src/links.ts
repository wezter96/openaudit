/**
 * Values that go into URLs or class names on the verification page, each
 * validated again at render time. Anything that fails renders as plain text
 * or not at all; nothing unvalidated becomes a link.
 */
import type { Grade, ProjectId, RepoSlug, ScanId, SiteUrl } from "./api";

/** GitHub's rules: owner 1 to 39 of `[A-Za-z0-9-]`, name 1 to 100 of `[A-Za-z0-9._-]`. */
const REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
const PROJECT = /^[a-z0-9][a-z0-9-]{0,159}$/;
const SCAN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{7,40}$/;
const ORIGIN = /^https?:\/\/[a-z0-9.-]+(?::\d{1,5})?$/;
const GRADES: ReadonlyArray<string> = ["A", "B", "C", "D", "F"];

/** A full commit hash. */
export type CommitSha = string;

const isDotName = (repo: RepoSlug) => /\/\.{1,2}$/.test(repo);

export const validRepo = (repo: RepoSlug) =>
	REPO.test(repo) && !isDotName(repo);

export const validProjectId = (id: ProjectId) => PROJECT.test(id);

export const validScanId = (id: ScanId) => SCAN.test(id);

export const validSha = (sha: CommitSha) => SHA.test(sha);

/** The grade's CSS class, or "" for anything that isn't a grade. */
export const gradeClass = (grade: Grade) =>
	GRADES.includes(grade) ? `g-${grade}` : "";

/** The site's https URL, or undefined when it isn't a plain https URL. */
export const httpsUrl = (site: SiteUrl): string | undefined => {
	try {
		const url = new URL(site);
		if (url.protocol !== "https:") return undefined;
		return url.username === "" && url.password === "" ? url.href : undefined;
	} catch {
		return undefined;
	}
};

/** The site's own origin, falling back to openaudit.se. */
export const safeOrigin = (origin: string) =>
	ORIGIN.test(origin) ? origin : "https://openaudit.se";

/** A finite number, rounded, as text. */
export const num = (n: number) =>
	Number.isFinite(n) ? String(Math.round(n)) : "?";
