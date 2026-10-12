import type { Auditor } from "@openaudit/core";

import { android } from "./android";
import { ios } from "./ios";
import { mobileSecrets } from "./secrets";

export const mobileAuditors: ReadonlyArray<Auditor> = [
	android,
	ios,
	mobileSecrets,
];
