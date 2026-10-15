/**
 * The openaudit badge scanner: claims a job from the badge API, clones and
 * audits the repo (and the verified site), reports the result, and repeats.
 * One job at a time, forever.
 *
 * Env: `SCANNER_TOKEN` (required), `API_URL` (default https://openaudit.se),
 * `OPENAUDIT_BIN` (default `openaudit`).
 */
import { makeScannerClient } from "./client";
import { readConfig } from "./config";
import { runLoop } from "./loop";
import { bunRunner } from "./process";
import { sweepWorkdirs } from "./workdir";

const config = readConfig();
const client = await makeScannerClient(config);
const swept = await sweepWorkdirs();
if (swept > 0) console.log(`removed ${swept} stale temp dir(s)`);

// As PID 1 in a container, Bun ignores signals it has no handler for. A job
// cut short leaves a temp dir, which the next start sweeps, and a running
// scan, which the API fails once its lease expires.
for (const signal of ["SIGINT", "SIGTERM"] as const)
	process.on(signal, () => {
		console.log(`${signal}: stopping`);
		process.exit(0);
	});

console.log(`badge scanner polling ${config.apiUrl}`);
await runLoop({
	client,
	run: bunRunner,
	openaudit: config.openaudit,
	secrets: [config.token],
});
