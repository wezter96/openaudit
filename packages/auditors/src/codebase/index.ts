import type { Auditor } from "@openaudit/core";

import { hygiene } from "./hygiene";

export const codebaseAuditors: ReadonlyArray<Auditor> = [hygiene];
