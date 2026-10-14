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

/**
 * Both sides of git merge conflicts in a lockfile. npm (parse-conflict-json),
 * pnpm and Yarn resolve a conflicted lockfile by reading both sides and
 * merging them, so code.lockfiles checks both.
 */
export const conflictSides = (text: string): ConflictSide[] => {
	if (
		!text.includes("<<<<<<<") ||
		!text.includes("=======") ||
		!text.includes(">>>>>>>")
	)
		return [];
	const ours: string[] = [];
	const theirs: string[] = [];
	const oursLines: number[] = [];
	const theirsLines: number[] = [];
	let state: "top" | "ours" | "parent" | "theirs" = "top";
	text.split(/\r\n|\r|\n/).forEach((line, i) => {
		if (line.startsWith("<<<<<<<")) state = "ours";
		else if (line.startsWith("|||||||")) state = "parent";
		else if (line === "=======") state = "theirs";
		else if (line.startsWith(">>>>>>>")) state = "top";
		else {
			if (state === "top" || state === "ours") {
				ours.push(line);
				oursLines.push(i + 1);
			}
			if (state === "top" || state === "theirs") {
				theirs.push(line);
				theirsLines.push(i + 1);
			}
		}
	});
	return [
		{ text: ours.join("\n"), lines: oursLines },
		{ text: theirs.join("\n"), lines: theirsLines },
	];
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
