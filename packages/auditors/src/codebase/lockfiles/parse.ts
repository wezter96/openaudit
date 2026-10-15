import { baseName, type SourceFile } from "../util";
import { parseBunLock } from "./bun";
import { parseNpmLock } from "./npm";
import { parsePnpmLock } from "./pnpm";
import { type Lockfile, mergeLockfiles, shiftLines, stripBom } from "./shared";
import { parseYarnLock } from "./yarn";

interface ConflictSide {
	readonly text: string;
	/** Line in the file of each line of `text`. */
	readonly lines: ReadonlyArray<number>;
}

type ConflictState = "top" | "ours" | "parent" | "theirs";

const CONFLICT_MARKERS = ["<<<<<<<", "=======", ">>>>>>>"];

/** The state a conflict marker line switches to, or undefined for content. */
const markerState = (line: string): ConflictState | undefined => {
	if (line.startsWith("<<<<<<<")) return "ours";
	if (line.startsWith("|||||||")) return "parent";
	if (line === "=======") return "theirs";
	if (line.startsWith(">>>>>>>")) return "top";
	return undefined;
};

/** Collects the lines of one side of the conflicts. */
const sideCollector = (keep: ReadonlySet<ConflictState>) => {
	const text: string[] = [];
	const lines: number[] = [];
	return {
		add: (state: ConflictState, line: string, at: number) => {
			if (!keep.has(state)) return;
			text.push(line);
			lines.push(at);
		},
		side: (): ConflictSide => ({ text: text.join("\n"), lines }),
	};
};

/**
 * Both sides of git merge conflicts in a lockfile. npm (parse-conflict-json),
 * pnpm and Yarn resolve a conflicted lockfile by reading both sides and
 * merging them, so code.lockfiles checks both.
 */
export const conflictSides = (text: string): ConflictSide[] => {
	if (!CONFLICT_MARKERS.every((marker) => text.includes(marker))) return [];
	const ours = sideCollector(new Set(["top", "ours"]));
	const theirs = sideCollector(new Set(["top", "theirs"]));
	let state: ConflictState = "top";
	text.split(/\r\n|\r|\n/).forEach((line, i) => {
		const next = markerState(line);
		if (next) {
			state = next;
			return;
		}
		ours.add(state, line, i + 1);
		theirs.add(state, line, i + 1);
	});
	return [ours.side(), theirs.side()];
};

export const LOCKFILE_PARSERS: Readonly<
	Record<string, (file: SourceFile) => Lockfile | undefined>
> = {
	"package-lock.json": parseNpmLock,
	"npm-shrinkwrap.json": parseNpmLock,
	"bun.lock": parseBunLock,
	"pnpm-lock.yaml": parsePnpmLock,
	"yarn.lock": parseYarnLock,
};

/**
 * Parses a lockfile as a whole and, when it has merge conflicts, each side of
 * them (package managers merge both sides), then combines what parsed.
 */
export const parseLockfile = (file: SourceFile): Lockfile | undefined => {
	const parse = LOCKFILE_PARSERS[baseName(file.path)];
	if (!parse) return undefined;
	const text = stripBom(file.text);
	const whole = parse({ path: file.path, text });
	const sides = conflictSides(text).map((side) => {
		const lock = parse({ path: file.path, text: side.text });
		return lock && shiftLines(lock, (l) => side.lines[l - 1] ?? l);
	});
	const parsed = [whole, ...sides].filter((l) => l !== undefined);
	const merged = mergeLockfiles(parsed);
	if (!merged || !sides.includes(undefined)) return merged;
	return {
		...merged,
		problems: [
			...(merged.problems ?? []),
			{
				severity: "medium",
				what: "merge conflict side",
				reason:
					"One side of a merge conflict in it could not be parsed, and package managers may install from either side.",
			},
		],
	};
};
