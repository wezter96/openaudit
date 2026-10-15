import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { baseName, isSourcePath, isTestPath } from "../util";
import { type Commit, hotspotsOf, readHistory, revisionsOf } from "./git-log";

const ID = "code.history";
const DOCS = "https://openaudit.se/auditors/code.history/";

/** Commits touching more files than this are bulk edits, not a signal. */
const MAX_CHANGESET = 30;
const MIN_SHARED_COMMITS = 5;
const MIN_COUPLING_PERCENT = 50;
/** A main author whose last commit is this old has moved on. */
const INACTIVE_DAYS = 180;
const MAX_COUPLINGS = 20;

/** A test changing with the code it tests is expected, not hidden coupling. */
const isTestPair = (a: string, b: string) => isTestPath(a) !== isTestPath(b);

export interface Coupling {
	readonly a: string;
	readonly b: string;
	readonly shared: number;
	/** Shared commits as a share of the two files' average commits. */
	readonly percent: number;
}

const pairKey = (a: string, b: string) => `${a}\u0000${b}`;

const sharedCommits = (
	commits: ReadonlyArray<Commit>,
	keep: (f: string) => boolean,
) => {
	const shared = new Map<string, number>();
	for (const c of commits) {
		if (c.files.length > MAX_CHANGESET) continue;
		const files = c.files.filter(keep).sort();
		files.forEach((a, i) => {
			for (const b of files.slice(i + 1))
				shared.set(pairKey(a, b), (shared.get(pairKey(a, b)) ?? 0) + 1);
		});
	}
	return shared;
};

/** Files that keep changing together: hidden dependencies between them. */
export const couplingsOf = (
	commits: ReadonlyArray<Commit>,
	keep: (f: string) => boolean,
): Coupling[] => {
	const revs = revisionsOf(
		commits.filter((c) => c.files.length <= MAX_CHANGESET),
	);
	const out: Coupling[] = [];
	for (const [key, shared] of sharedCommits(commits, keep)) {
		const [a = "", b = ""] = key.split("\u0000");
		const percent = Math.round(
			(100 * shared) / (((revs.get(a) ?? 0) + (revs.get(b) ?? 0)) / 2),
		);
		if (shared < MIN_SHARED_COMMITS || percent < MIN_COUPLING_PERCENT) continue;
		if (!isTestPair(a, b)) out.push({ a, b, shared, percent });
	}
	return out.sort((x, y) => y.percent - x.percent || y.shared - x.shared);
};

export interface Ownership {
	readonly file: string;
	readonly author: string;
	/** The main author's share of the file's commits. */
	readonly share: number;
}

/** Each file's main author, by commits. */
export const ownershipOf = (
	commits: ReadonlyArray<Commit>,
	keep: (f: string) => boolean,
): Ownership[] => {
	const byFile = new Map<string, Map<string, number>>();
	for (const c of commits)
		for (const f of c.files.filter(keep)) {
			const authors = byFile.get(f) ?? new Map<string, number>();
			authors.set(c.author, (authors.get(c.author) ?? 0) + 1);
			byFile.set(f, authors);
		}
	return [...byFile].map(([file, authors]) => {
		const total = [...authors.values()].reduce((a, b) => a + b, 0);
		const [author = "", count = 0] =
			[...authors].sort((x, y) => y[1] - x[1])[0] ?? [];
		return { file, author, share: count / total };
	});
};

/** When each author last committed, in seconds. */
const lastSeen = (commits: ReadonlyArray<Commit>) => {
	const seen = new Map<string, number>();
	for (const c of commits)
		seen.set(c.author, Math.max(seen.get(c.author) ?? 0, c.time));
	return seen;
};

/**
 * Truck factor: how many of the top authors could leave before more than
 * half of the files have no remaining main author.
 */
export const truckFactor = (owners: ReadonlyArray<Ownership>): number => {
	const filesBy = new Map<string, number>();
	for (const o of owners)
		filesBy.set(o.author, (filesBy.get(o.author) ?? 0) + 1);
	const ranked = [...filesBy.values()].sort((a, b) => b - a);
	let orphaned = 0;
	for (const [i, n] of ranked.entries()) {
		orphaned += n;
		if (orphaned > owners.length / 2) return i + 1;
	}
	return ranked.length;
};

const couplingFinding = (c: Coupling): FindingInput => ({
	ruleId: `${ID}/change-coupling`,
	title: `${baseName(c.a)} and ${baseName(c.b)} change together`,
	severity: "info",
	category: "maintainability",
	message: `${c.a} and ${c.b} changed in the same commit ${c.shared} times (${c.percent}% of their changes) in the last year. Files that keep changing together share a hidden dependency: a change to one needs the other.`,
	location: { file: c.a },
	evidence: `${c.a} <-> ${c.b}`,
	remediation:
		"If the two files carry the same concept, move it into one place. If one depends on the other's details, give it an explicit interface.",
	references: [DOCS],
	tags: ["code-history", "change-coupling"],
});

const knowledgeLossFinding = (
	o: Ownership,
	hotspot: boolean,
): FindingInput => ({
	ruleId: `${ID}/knowledge-loss`,
	title: `Main author of ${baseName(o.file)} is no longer active`,
	severity: hotspot ? "low" : "info",
	category: "maintainability",
	message: `${o.author} wrote ${Math.round(o.share * 100)}% of the changes to ${o.file} and has not committed in ${INACTIVE_DAYS} days${hotspot ? ". The file is a hotspot, so it keeps needing changes" : ""}.`,
	location: { file: o.file },
	evidence: o.file,
	remediation:
		"Have someone who works on the code now review the file, document what it does and add tests around it.",
	references: [DOCS],
	tags: ["code-history", "knowledge"],
});

const truckFactorFinding = (
	factor: number,
	authors: number,
	files: number,
): FindingInput => ({
	ruleId: `${ID}/truck-factor`,
	title: `Truck factor ${factor}`,
	severity: "info",
	category: "maintainability",
	message:
		authors === 1
			? `One person wrote all the changes to ${files} files in the last year, so everything the code does lives in one head.`
			: `${factor} of ${authors} authors are the main authors of more than half of the ${files} files changed in the last year. If they left, most of the code would have no one who knows it well.`,
	remediation:
		"Spread knowledge: pair on changes, review each other's code and write down the decisions behind the main modules.",
	references: [DOCS],
	tags: ["code-history", "knowledge"],
});

const inactiveOwners = (
	commits: ReadonlyArray<Commit>,
	owners: ReadonlyArray<Ownership>,
) => {
	const seen = lastSeen(commits);
	const latest = Math.max(...commits.map((c) => c.time));
	const cutoff = latest - INACTIVE_DAYS * 86_400;
	return owners.filter((o) => (seen.get(o.author) ?? 0) < cutoff);
};

export const codeHistory = defineAuditor({
	id: ID,
	title: "Change coupling and knowledge",
	description:
		"Reads the last year of git history (commits only, never the working tree): files that keep changing in the same commits (hidden dependencies), source files whose main author has stopped committing (knowledge loss, higher in hotspots), and the truck factor, how many authors hold most of the knowledge. Skips when the target is not the root of a git repository.",
	categories: ["maintainability"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const history = yield* readHistory(ctx, ws.root);
			if ("unavailable" in history) return yield* skip(history.unavailable);
			const tracked = new Set(yield* ws.files);
			const keep = (f: string) => tracked.has(f) && isSourcePath(f);
			const commits = history.commits;
			if (!commits.length) return yield* skip("No commits in the last year.");
			const owners = ownershipOf(commits, keep);
			const hotspots = hotspotsOf(
				owners.map((o) => o.file),
				revisionsOf(commits),
			);
			const authors = new Set(commits.map((c) => c.author)).size;
			return [
				...couplingsOf(commits, keep)
					.slice(0, MAX_COUPLINGS)
					.map(couplingFinding),
				...inactiveOwners(commits, owners).map((o) =>
					knowledgeLossFinding(o, hotspots.has(o.file)),
				),
				...(owners.length
					? [truckFactorFinding(truckFactor(owners), authors, owners.length)]
					: []),
			];
		}),
});
