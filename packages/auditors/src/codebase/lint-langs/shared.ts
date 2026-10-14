import type { AuditorError, FindingInput } from "@openaudit/core";
import type { Effect } from "effect";

import { relPath, runCommand, withTempDir as withScratchDir } from "../../tool";

const MODULE_LIMIT = 10;
export const SHELL_FILE_LIMIT = 500;

const dirOf = (path: string) =>
	path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";

/** Keeps the first finding per rule and location. */
export const dedupe = (
	findings: ReadonlyArray<FindingInput>,
): FindingInput[] => {
	const seen = new Set<string>();
	return findings.filter((f) => {
		const key = `${f.ruleId}|${f.location?.file}|${f.location?.line}|${f.location?.column}|${f.message}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
};

/** Path inside the workspace, or undefined for files outside it. */
export const inRoot = (root: string, file: string | undefined) => {
	const rel = relPath(root, file);
	return rel && !rel.startsWith("../") && !rel.startsWith("/")
		? rel
		: undefined;
};

/** Runs a tool; fails with its output unless the exit code is in `okCodes`. */
export const run = runCommand;

/** Runs `fn` with a scratch directory that is always removed afterwards. */
export const withTempDir = <A, E>(
	fn: (dir: string) => Effect.Effect<A, E>,
): Effect.Effect<A, E | AuditorError> => withScratchDir("openaudit-lint-", fn);

/** Directories of the given manifest files, outermost only. */
export const manifestDirs = (
	files: ReadonlyArray<string>,
	name: string,
	nested: boolean,
): string[] => {
	const dirs = files
		.filter((f) => f === name || f.endsWith(`/${name}`))
		.map(dirOf)
		.sort((a, b) => a.split("/").length - b.split("/").length);
	const picked: string[] = [];
	for (const d of dirs) {
		// A Cargo workspace is linted from its root (`--workspace`); member crates
		// below an already selected directory are covered by it.
		if (!nested && picked.some((p) => p === "" || d.startsWith(`${p}/`)))
			continue;
		picked.push(d);
	}
	return picked.slice(0, MODULE_LIMIT);
};

/** Env that keeps Go tooling from switching toolchains or running cgo. */
export const GO_ENV = {
	GOTOOLCHAIN: "local",
	CGO_ENABLED: "0",
	GOFLAGS: "-mod=readonly",
};
