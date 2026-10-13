// Bundles the CLI into dist/ for npm. The unpublished @openaudit/* workspace
// packages are inlined; every third-party package they import stays external
// and must be listed in this package's dependencies (checked below).
import { cpSync, existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "../../..");
const cliDir = join(import.meta.dir, "..");
const readJson = (path: string) => JSON.parse(readFileSync(path, "utf8"));

const cli = readJson(join(cliDir, "package.json"));
const workspaceNames = ["core", "auditors", "agent", "mcp"];

const thirdParty = new Set<string>();
for (const dir of workspaceNames) {
	const pkg = readJson(join(root, "packages", dir, "package.json"));
	for (const field of ["dependencies", "optionalDependencies"] as const) {
		for (const name of Object.keys(pkg[field] ?? {})) {
			if (!name.startsWith("@openaudit/")) thirdParty.add(name);
		}
	}
}

const declared = new Set([
	...Object.keys(cli.dependencies ?? {}),
	...Object.keys(cli.optionalDependencies ?? {}),
]);
const missing = [...thirdParty].filter((name) => !declared.has(name));
if (missing.length > 0) {
	console.error(
		`apps/cli/package.json must declare these runtime dependencies of the bundled packages: ${missing.join(", ")}`,
	);
	process.exit(1);
}

rmSync(join(cliDir, "dist"), { recursive: true, force: true });
const result = await Bun.build({
	entrypoints: [join(cliDir, "src/bin.ts")],
	outdir: join(cliDir, "dist"),
	naming: "cli.js",
	target: "bun",
	format: "esm",
	// Resolved at runtime (code.typecheck uses typescript/bin/tsc), so keep
	// subpaths and anything optional external too.
	external: [...declared, "typescript", ...[...declared].map((n) => `${n}/*`)],
});
if (!result.success) {
	for (const log of result.logs) console.error(log);
	process.exit(1);
}

const license = join(root, "LICENSE");
if (existsSync(license)) cpSync(license, join(cliDir, "LICENSE"));
console.log(`built ${result.outputs.map((o) => o.path).join(", ")}`);
