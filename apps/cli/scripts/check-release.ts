// Fails when the versions that must agree don't: apps/cli/package.json, VERSION
// in @openaudit/core (printed by --version and written into reports) and, when
// run for a tag (RELEASE_TAG=v1.2.3 or a GITHUB_REF_NAME starting with "v").
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "../../..");
const pkg = JSON.parse(
	readFileSync(join(root, "apps/cli/package.json"), "utf8"),
);
const engine = readFileSync(join(root, "packages/core/src/engine.ts"), "utf8");
const coreVersion = /export const VERSION = "([^"]+)"/.exec(engine)?.[1];

const errors: string[] = [];
if (coreVersion !== pkg.version)
	errors.push(
		`VERSION in packages/core/src/engine.ts (${coreVersion}) != apps/cli/package.json (${pkg.version})`,
	);
const tag = process.env.RELEASE_TAG ?? process.env.GITHUB_REF_NAME ?? "";
if (/^v\d/.test(tag) && tag !== `v${pkg.version}`)
	errors.push(`tag ${tag} != v${pkg.version} from apps/cli/package.json`);
if (pkg.private) errors.push("apps/cli/package.json is marked private");

if (errors.length > 0) {
	for (const e of errors) console.error(e);
	process.exit(1);
}
console.log(`release check ok: ${pkg.name}@${pkg.version}`);
