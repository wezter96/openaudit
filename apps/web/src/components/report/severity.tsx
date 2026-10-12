import type { Severity, SeverityCounts } from "@openaudit/core/model";
import { cn } from "@openaudit/ui/lib/utils";

import {
	SEVERITY_BG,
	SEVERITY_LABEL,
	SEVERITY_ORDER,
	SEVERITY_TEXT,
} from "./meta";

/** Severity as text plus a colour marker (never colour alone). */
export function SeverityBadge({
	severity,
	className,
}: {
	severity: Severity;
	className?: string;
}) {
	return (
		<span
			className={cn(
				"inline-flex items-center gap-1.5 font-semibold text-xs",
				SEVERITY_TEXT[severity],
				className,
			)}
		>
			<span
				aria-hidden="true"
				className={cn("size-2 shrink-0 rotate-45", SEVERITY_BG[severity])}
			/>
			{SEVERITY_LABEL[severity]}
		</span>
	);
}

/** A row of severity totals. */
export function SeverityCountsRow({ counts }: { counts: SeverityCounts }) {
	return (
		<dl className="grid grid-cols-5 border-rule border-y">
			{SEVERITY_ORDER.map((s) => (
				<div
					key={s}
					className="border-rule border-l px-3 py-3 first:border-l-0 sm:px-4"
				>
					<dt>
						<SeverityBadge severity={s} />
					</dt>
					<dd
						className={cn(
							"mt-1 font-bold text-2xl tabular-nums",
							counts[s] === 0 && "text-ink-soft",
						)}
					>
						{counts[s]}
					</dd>
				</div>
			))}
		</dl>
	);
}
