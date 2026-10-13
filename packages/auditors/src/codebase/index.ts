import type { Auditor } from "@openaudit/core";

import { accessibility } from "./accessibility";
import { dependencies } from "./dependencies";
import { gitleaks, osvScanner, semgrep, trivyFs } from "./external";
import { hygiene } from "./hygiene";
import { performanceAuditor } from "./performance";
import { quality } from "./quality";
import { jscpd, knip, scancode } from "./quality-tools";
import { bandit, brakeman, codeql, gosec, trufflehog } from "./sast-tools";
import { secrets } from "./secrets";
import { security } from "./security";
import { supplyChainToolAuditors } from "./supply-chain-tools";

export const codebaseAuditors: ReadonlyArray<Auditor> = [
	hygiene,
	secrets,
	security,
	dependencies,
	accessibility,
	performanceAuditor,
	quality,
	gitleaks,
	semgrep,
	osvScanner,
	trivyFs,
	trufflehog,
	bandit,
	gosec,
	brakeman,
	codeql,
	jscpd,
	knip,
	scancode,
	...supplyChainToolAuditors,
];
