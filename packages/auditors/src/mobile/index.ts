import type { Auditor } from "@openaudit/core";
import { mobileAccessibility } from "./accessibility";
import { android } from "./android";
import { mobileDependencies } from "./dependencies";
import { ios } from "./ios";
import { mobilePerformance } from "./performance";
import { mobileSecrets } from "./secrets";

export const mobileAuditors: ReadonlyArray<Auditor> = [
	android,
	ios,
	mobileSecrets,
	mobileDependencies,
	mobileAccessibility,
	mobilePerformance,
];
