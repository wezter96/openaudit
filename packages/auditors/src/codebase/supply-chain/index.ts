import type { Auditor } from "@openaudit/core";

import { govulncheck } from "./go";
import { grype, syftLicenses } from "./grype-syft";
import { bunAudit, npmAudit, pnpmAudit } from "./js-audits";
import { pipAudit } from "./python";
import { cargoAudit } from "./rust";
import { scorecard } from "./scorecard";

/**
 * Supply-chain wrappers: vulnerable dependencies (govulncheck, pip-audit,
 * cargo-audit, npm/pnpm/bun audit, grype), licences (syft) and repository
 * posture (OpenSSF Scorecard).
 *
 * Safety: none of these installs or builds the target. The package-manager
 * audits read lockfiles only, pip-audit only sees a sanitised `name==version`
 * file we write ourselves, and syft/grype run from a scratch directory so a
 * hostile `.syft.yaml` / `.grype.yaml` in the target is never picked up.
 */

export * from "./go";
export * from "./grype-syft";
export * from "./js-audits";
export * from "./python";
export * from "./rust";
export * from "./scorecard";

export const supplyChainToolAuditors: ReadonlyArray<Auditor> = [
	govulncheck,
	pipAudit,
	cargoAudit,
	npmAudit,
	pnpmAudit,
	bunAudit,
	grype,
	syftLicenses,
	scorecard,
];
