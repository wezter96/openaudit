import type { Auditor } from "@openaudit/core";

import { accessibility } from "./accessibility";
import { agentConfig } from "./agent-config";
import { api } from "./api";
import { dependencies } from "./dependencies";
import { gitleaks, osvScanner, semgrep, trivyFs } from "./external";
import { hygiene } from "./hygiene";
import { licenses } from "./licenses";
import { lintJsAuditors } from "./lint-js";
import {
	clippy,
	golangciLint,
	mypy,
	phpstan,
	pmd,
	ruff,
	shellcheck,
	staticcheck,
} from "./lint-langs";
import { mobsfscan } from "./mobsfscan";
import { performanceAuditor } from "./performance";
import { privacy as codePrivacy } from "./privacy";
import { quality } from "./quality";
import { jscpd, knip, scancode } from "./quality-tools";
import { bandit, brakeman, gosec, trufflehog } from "./sast-tools";
import { secrets } from "./secrets";
import { secretsHistory } from "./secrets-history";
import { security } from "./security";
import { spectral } from "./spectral";
import { strictness } from "./strictness";
import { supplyChainToolAuditors } from "./supply-chain-tools";

export const codebaseAuditors: ReadonlyArray<Auditor> = [
	hygiene,
	secrets,
	security,
	dependencies,
	licenses,
	accessibility,
	performanceAuditor,
	quality,
	strictness,
	api,
	codePrivacy,
	agentConfig,
	gitleaks,
	semgrep,
	osvScanner,
	trivyFs,
	trufflehog,
	bandit,
	gosec,
	brakeman,
	jscpd,
	knip,
	scancode,
	...supplyChainToolAuditors,
	...lintJsAuditors,
	ruff,
	staticcheck,
	shellcheck,
	mobsfscan,
	clippy,
	mypy,
	golangciLint,
	phpstan,
	pmd,
	spectral,
	secretsHistory,
];
