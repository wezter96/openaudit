import type { Auditor } from "@openaudit/core";

import { cloudAuditors } from "./cloud";
import { codebaseAuditors } from "./codebase";
import { infraAuditors } from "./infra";
import { mobileAuditors } from "./mobile";
import { webAuditors } from "./web";

export {
	cloudAuditors,
	codebaseAuditors,
	infraAuditors,
	mobileAuditors,
	webAuditors,
};

/** Every built-in and external-tool auditor. Agentic auditors live in @openaudit/agent. */
export const builtinAuditors: ReadonlyArray<Auditor> = [
	...codebaseAuditors,
	...webAuditors,
	...infraAuditors,
	...mobileAuditors,
	...cloudAuditors,
];
