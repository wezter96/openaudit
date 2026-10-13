import type { Auditor } from "@openaudit/core";

import { prowler } from "./prowler";

export const cloudAuditors: ReadonlyArray<Auditor> = [prowler];
