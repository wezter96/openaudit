import type { Auditor } from "@openaudit/core";

import { accessibility } from "./accessibility";
import { browser } from "./browser";
import { exposure } from "./exposure";
import { headers } from "./headers";
import { lighthouse } from "./lighthouse";
import { performanceAuditor } from "./performance";
import { privacy } from "./privacy";
import { seo } from "./seo";
import { tlsAuditor } from "./tls";

export const webAuditors: ReadonlyArray<Auditor> = [
	headers,
	tlsAuditor,
	seo,
	accessibility,
	performanceAuditor,
	exposure,
	privacy,
	browser,
	lighthouse,
];
