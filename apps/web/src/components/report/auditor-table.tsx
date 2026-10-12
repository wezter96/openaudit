import type { AuditorResult, AuditorStatus } from "@openaudit/core/model";
import { cn } from "@openaudit/ui/lib/utils";

import { ENGINE_LABEL, formatDuration, STATUS_LABEL } from "./meta";

const STATUS_CLASS: Record<AuditorStatus, string> = {
	passed: "text-ok",
	failed: "text-sev-high",
	skipped: "text-ink-soft",
	error: "text-sev-critical",
};

const STATUS_ORDER: Record<AuditorStatus, number> = {
	error: 0,
	failed: 1,
	passed: 2,
	skipped: 3,
};

/** Every auditor that was selected, with why it was skipped or errored. */
export function AuditorTable({
	results,
	captionId,
}: {
	results: ReadonlyArray<AuditorResult>;
	captionId?: string;
}) {
	const rows = [...results].sort(
		(a, b) =>
			STATUS_ORDER[a.status] - STATUS_ORDER[b.status] ||
			a.auditor.localeCompare(b.auditor),
	);

	if (rows.length === 0)
		return (
			<p className="border border-rule border-dashed px-4 py-6 text-ink-soft">
				No auditors applied to this target.
			</p>
		);

	return (
		<div className="relative overflow-x-auto border border-rule">
			<table aria-labelledby={captionId} className="w-full text-left text-sm">
				<thead className="bg-muted/70">
					<tr>
						<th scope="col" className="px-3 py-2 font-semibold">
							Auditor
						</th>
						<th scope="col" className="px-3 py-2 font-semibold">
							Status
						</th>
						<th scope="col" className="px-3 py-2 text-right font-semibold">
							Findings
						</th>
						<th scope="col" className="px-3 py-2 text-right font-semibold">
							Time
						</th>
						<th scope="col" className="px-3 py-2 font-semibold">
							Notes
						</th>
					</tr>
				</thead>
				<tbody className="divide-y divide-rule">
					{rows.map((r) => (
						<tr key={r.auditor} className="align-top">
							<th scope="row" className="px-3 py-2 font-normal">
								<span className="block font-medium">{r.title}</span>
								<span className="block font-mono text-ink-soft text-xs">
									{r.auditor}
									<span className="font-sans"> ({ENGINE_LABEL[r.engine]})</span>
								</span>
							</th>
							<td
								className={cn(
									"whitespace-nowrap px-3 py-2 font-semibold",
									STATUS_CLASS[r.status],
								)}
							>
								{STATUS_LABEL[r.status]}
							</td>
							<td className="px-3 py-2 text-right tabular-nums">
								{r.findings.length}
							</td>
							<td className="whitespace-nowrap px-3 py-2 text-right text-ink-soft tabular-nums">
								{formatDuration(r.durationMs)}
							</td>
							<td className="min-w-[16rem] px-3 py-2 text-ink-soft">
								{r.message ?? ""}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
