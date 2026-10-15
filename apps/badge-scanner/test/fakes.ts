import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { ProcessRunner, RunOptions, RunResult } from "../src/types";

export const SHA = "0123456789abcdef0123456789abcdef01234567";

export interface FakeRepo {
	/** Content of `.openaudit-badge`; undefined leaves it out. */
	readonly badgeFile?: string;
	readonly cloneFails?: boolean;
	/** Exit code of every audit; default 1 (findings). */
	readonly auditCode?: number;
	/** Audits whose target matches this write no reports. */
	readonly brokenTarget?: RegExp;
}

export interface Call {
	readonly cmd: ReadonlyArray<string>;
	readonly options: RunOptions;
}

const ok = (stdout = ""): RunResult => ({
	code: 0,
	stdout,
	stderr: "",
	timedOut: false,
});

const fakeClone = (cmd: ReadonlyArray<string>, repo: FakeRepo): RunResult => {
	if (repo.cloneFails)
		return { ...ok(), code: 128, stderr: "fatal: repository not found\n" };
	const dir = cmd.at(-1) as string;
	mkdirSync(dir);
	if (repo.badgeFile !== undefined)
		writeFileSync(join(dir, ".openaudit-badge"), repo.badgeFile);
	return ok();
};

const fakeAudit = (cmd: ReadonlyArray<string>, repo: FakeRepo): RunResult => {
	const out = cmd[cmd.indexOf("--out") + 1] as string;
	const target = cmd[cmd.indexOf("--format") - 1] as string;
	if (!repo.brokenTarget?.test(target)) {
		writeFileSync(join(out, "openaudit-report.json"), `{"target":"${target}"}`);
		writeFileSync(join(out, "openaudit-report.html"), "<html></html>");
	}
	return { ...ok(), code: repo.auditCode ?? 1 };
};

/** A runner that fakes git and openaudit, and records every call. */
export const fakeRunner = (
	repo: FakeRepo,
	calls: Call[] = [],
): ProcessRunner => {
	return async (cmd, options) => {
		calls.push({ cmd, options });
		if (cmd.includes("clone")) return fakeClone(cmd, repo);
		if (cmd.includes("rev-parse")) return ok(`${SHA}\n`);
		if (cmd.includes("--version")) return ok("openaudit v9.8.7\n");
		return fakeAudit(cmd, repo);
	};
};
