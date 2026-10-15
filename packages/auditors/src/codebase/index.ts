import type { Auditor } from "@openaudit/core";

import { accessibility } from "./accessibility";
import { agentConfig } from "./agent-config";
import { api } from "./api";
import { dependencies } from "./dependencies";
import { dependencyHealth } from "./dependency-health";
import { gitleaks, osvScanner, semgrep, trivyFs } from "./external";
import { codeHealth } from "./health";
import { codeHistory } from "./history";
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
import { lockfiles } from "./lockfiles";
import { mobsfscan } from "./mobsfscan";
import { oasdiff } from "./oasdiff";
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
import { unicode } from "./unicode";

export const codebaseAuditors: ReadonlyArray<Auditor> = [
	hygiene,
	secrets,
	security,
	unicode,
	dependencies,
	dependencyHealth,
	licenses,
	lockfiles,
	accessibility,
	performanceAuditor,
	quality,
	codeHealth,
	codeHistory,
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
	oasdiff,
	secretsHistory,
];
