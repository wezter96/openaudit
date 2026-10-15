import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
	backoffMs,
	IDLE_DELAY_MS,
	type LoopDeps,
	runLoop,
	tick,
} from "../src/loop";
import type { Job, JobResult, ScannerClient } from "../src/types";
import { fakeRunner } from "./fakes";

const JOB: Job = {
	id: "scan-7",
	projectId: "a-b",
	repo: "a/b",
	code: "code-7",
};

let base = "";
beforeEach(() => {
	base = mkdtempSync(join(tmpdir(), "oa-scanner-loop-"));
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

/** A client that hands out `jobs` in order, then fails or idles. */
const fakeClient = (steps: Array<Job | null | Error>) => {
	const reports: Array<[string, JobResult]> = [];
	const client: ScannerClient = {
		claim: async () => {
			const step = steps.shift() ?? null;
			if (step instanceof Error) throw step;
			return step;
		},
		report: async (id, result) => {
			reports.push([id, result]);
		},
	};
	return { client, reports };
};

const loopDeps = (client: ScannerClient, sleeps: number[] = []): LoopDeps => ({
	client,
	run: fakeRunner({ badgeFile: "code-7" }),
	openaudit: ["openaudit"],
	tmpBase: base,
	secrets: ["tok"],
	sleep: async (ms) => {
		sleeps.push(ms);
	},
	log: () => {},
});

describe("tick", () => {
	test("returns false when there is no job", async () => {
		const { client, reports } = fakeClient([null]);
		expect(await tick(loopDeps(client))).toBe(false);
		expect(reports).toEqual([]);
	});

	test("runs a job and reports it under its scan id", async () => {
		const { client, reports } = fakeClient([JOB]);
		expect(await tick(loopDeps(client))).toBe(true);
		expect(reports).toHaveLength(1);
		expect(reports[0]?.[0]).toBe("scan-7");
		expect(reports[0]?.[1].status).toBe("ok");
	});
});

describe("runLoop", () => {
	test("asks again at once after a job, idles without one, backs off on errors", async () => {
		const controller = new AbortController();
		const sleeps: number[] = [];
		const steps: Array<Job | null | Error> = [
			JOB,
			null,
			new Error("503 tok"),
			new Error("503"),
			null,
		];
		const { client, reports } = fakeClient(steps);
		const deps = loopDeps(client, sleeps);
		await runLoop(
			{
				...deps,
				sleep: async (ms) => {
					sleeps.push(ms);
					if (steps.length === 0) controller.abort();
				},
			},
			controller.signal,
		);
		expect(reports).toHaveLength(1);
		expect(sleeps).toEqual([
			IDLE_DELAY_MS,
			backoffMs(1),
			backoffMs(2),
			IDLE_DELAY_MS,
		]);
	});

	test("backoff doubles and is capped", () => {
		expect(backoffMs(1)).toBe(60_000);
		expect(backoffMs(2)).toBe(120_000);
		expect(backoffMs(10)).toBe(15 * 60_000);
	});
});
