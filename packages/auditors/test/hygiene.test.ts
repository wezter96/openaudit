import { describe, expect, test } from "bun:test";

import { hygiene } from "../src/codebase/hygiene";
import { fixture, ruleIds, runAuditor } from "./helpers";

describe("code.hygiene", () => {
	test("flags missing essentials", async () => {
		const report = await runAuditor(hygiene, fixture("hygiene-bad"));
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"code.hygiene/ci-missing",
			"code.hygiene/env-not-ignored",
			"code.hygiene/license-missing",
			"code.hygiene/lockfile-missing",
			"code.hygiene/readme-missing",
			"code.hygiene/security-policy-missing",
		]);
	});
});
