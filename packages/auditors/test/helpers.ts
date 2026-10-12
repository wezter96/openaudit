import { join } from "node:path";
import type { AuditOptions } from "@openaudit/core";
import { type Auditor, CoreLive, type Report, runAudit } from "@openaudit/core";
import { Effect } from "effect";

export const fixture = (...parts: string[]) =>
	join(import.meta.dir, "fixtures", ...parts);

/** Runs a single auditor against a target with live infrastructure. */
export const runAuditor = (
	auditor: Auditor,
	target: string,
	options: AuditOptions = {},
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
			options,
			selection: { only: [auditor.id] },
		}).pipe(Effect.provide(CoreLive)),
	);

export const ruleIds = (report: Report) =>
	report.results.flatMap((r) => r.findings.map((f) => f.ruleId)).sort();
