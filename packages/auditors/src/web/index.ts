import type { Auditor } from "@openaudit/core";

import { accessibility } from "./accessibility";
import { apiExposure } from "./api-exposure";
import { browser } from "./browser";
import { dns } from "./dns";
import { exposure } from "./exposure";
import { headers } from "./headers";
import { lighthouse } from "./lighthouse";
import { pa11y } from "./pa11y";
import { performanceAuditor } from "./performance";
import { privacy } from "./privacy";
import { reliability } from "./reliability";
import { seo } from "./seo";
import { sslyze } from "./sslyze";
import { testssl } from "./testssl";
import { tlsAuditor } from "./tls";
import { zapBaseline } from "./zap";
import { zapActive } from "./zap-active";

export const webAuditors: ReadonlyArray<Auditor> = [
	headers,
	tlsAuditor,
	seo,
	accessibility,
	performanceAuditor,
	exposure,
	privacy,
	reliability,
	dns,
	apiExposure,
	browser,
	lighthouse,
	pa11y,
	zapBaseline,
	zapActive,
	sslyze,
	testssl,
];
