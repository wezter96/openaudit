#!/usr/bin/env node
// Entry point that works under Node too: openaudit itself needs Bun, so when
// run by Node (npx) it hands over to a Bun on PATH or explains how to get one.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

if (typeof Bun !== "undefined") {
	await import(cli);
} else {
	const run = spawnSync("bun", [cli, ...process.argv.slice(2)], {
		stdio: "inherit",
	});
	if (run.error?.code === "ENOENT") {
		console.error(
			"openaudit needs the Bun runtime (https://bun.sh), which was not found on PATH.\n" +
				"Install it with `curl -fsSL https://bun.sh/install | bash` (or `npm i -g bun`), then run again.\n" +
				"Or skip the install: `bunx @openaudit/cli`.",
		);
		process.exit(127);
	}
	process.exit(run.status ?? 1);
}
