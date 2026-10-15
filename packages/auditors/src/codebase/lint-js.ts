import type { Auditor } from "@openaudit/core";

import { biome } from "./lint-js-biome";
import { eslint } from "./lint-js-eslint";
import { oxlint } from "./lint-js-oxlint";
import { typecheck } from "./lint-js-tsc";

/**
 * Type-checking and linting of JavaScript/TypeScript projects.
 *
 * Targets are hostile, so every wrapper either runs a tool that never executes
 * project code (tsc, oxlint with a sanitized config, biome) or is opt-in and
 * says so (eslint, whose config is a JS program). Each tool lives in its own
 * `lint-js-<tool>.ts` module.
 */

export { biome, parseBiomeReport } from "./lint-js-biome";
export { eslint, parseEslintReport } from "./lint-js-eslint";
export {
	frameworkPlugins,
	oxlint,
	parseOxlintReport,
	sanitizeOxlintConfig,
	withFrameworkPlugins,
} from "./lint-js-oxlint";
export {
	finalizeTscFindings,
	parseTscOutput,
	selectTsconfigs,
	type TscDiagnostic,
	tscFindings,
	typecheck,
} from "./lint-js-tsc";

export const lintJsAuditors: ReadonlyArray<Auditor> = [
	typecheck,
	oxlint,
	biome,
	eslint,
];
