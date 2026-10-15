import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
	type Auditor,
	Exec,
	type ExecOptions,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import { fixture } from "./helpers";

export const recorded = (name: string) =>
	readFileSync(fixture("lint-js", "recorded", name), "utf8");
export const recordedJson = (name: string): unknown =>
	JSON.parse(recorded(name));

export const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		category: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId.replace(/^code\.\w+\//, "")} ${f.severity} ${f.category} ${f.location?.file ?? "-"}:${f.location?.line ?? "-"}`,
	);

interface Call {
	readonly cmd: ReadonlyArray<string>;
	readonly options: ExecOptions;
}

/** Runs an auditor on `dir` with a fake Exec that records every call. */
export const runFake = async (
	auditor: Auditor,
	dir: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>, options: ExecOptions) => ExecResult,
): Promise<{ report: Report; calls: Call[] }> => {
	const calls: Call[] = [];
	const report = await Effect.runPromise(
		runAudit({
			target: dir,
			auditors: [auditor],
			selection: { only: [auditor.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd: ReadonlyArray<string>, options: ExecOptions = {}) =>
							Effect.sync(() => {
								calls.push({ cmd, options });
								return run(cmd, options);
							}),
					}),
				),
			),
		),
	);
	return { report, calls };
};

export const withProject = async <A>(
	files: Record<string, string>,
	use: (dir: string) => Promise<A>,
): Promise<A> => {
	const dir = await mkdtemp(join(tmpdir(), "openaudit-lintjs-"));
	try {
		for (const [path, text] of Object.entries(files)) {
			await mkdir(dirname(join(dir, path)), { recursive: true });
			await writeFile(join(dir, path), text);
		}
		return await use(dir);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

export const ok = (stdout: string, code = 0): ExecResult => ({
	code,
	stdout,
	stderr: "",
});
export const findingsOf = (report: Report) =>
	report.results.flatMap((r) => r.findings);
export const statusOf = (report: Report) => report.results[0]?.status;
