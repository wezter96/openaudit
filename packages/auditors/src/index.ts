import type { Auditor } from "@openaudit/core";

import { codebaseAuditors } from "./codebase";
import { infraAuditors } from "./infra";
import { mobileAuditors } from "./mobile";
import { webAuditors } from "./web";

export { codebaseAuditors, infraAuditors, mobileAuditors, webAuditors };

/** Every built-in and external-tool auditor. Agentic auditors live in @openaudit/agent. */
export const builtinAuditors: ReadonlyArray<Auditor> = [
	...codebaseAuditors,
	...webAuditors,
	...infraAuditors,
	...mobileAuditors,
];
