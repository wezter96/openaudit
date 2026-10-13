import type { Report } from "@openaudit/core/model";
import { cn } from "@openaudit/ui/lib/utils";

import { LocalDate } from "./local-date";
import { CATEGORY_LABEL, GRADE_MEANING, targetName } from "./meta";

/**
 * The inspection tag: overall grade and per-category scores, styled after the
 * manila tags inspectors hang on checked equipment.
 */
export function ScoreTag({
	report,
	caption,
	className,
}: {
	report: Pick<Report, "summary" | "target" | "finishedAt">;
	/** Line under the target, e.g. "Example report". Defaults to the audit date. */
	caption?: string;
	className?: string;
}) {
	const { summary, target } = report;
	// The engine scores an audit where nothing ran as 100; don't present that as an A.
	const graded = summary.categories.length > 0;
	const label = target.url ? hostOf(target.url) : targetName(target);

	return (
		<div
			className={cn(
				"[filter:drop-shadow(0_1px_0_var(--tag-edge))_drop-shadow(0_18px_28px_rgb(15_26_46/0.18))]",
				className,
			)}
		>
			<section
				aria-label={
					graded
						? `Overall grade ${summary.grade}, score ${summary.score} out of 100`
						: "Not graded: no auditor examined this target"
				}
				className="relative bg-tag px-6 pt-12 pb-6 text-tag-ink [clip-path:polygon(18%_0,82%_0,100%_11%,100%_100%,0_100%,0_11%)]"
			>
				<span
					aria-hidden="true"
					className="absolute top-4 left-1/2 size-5 -translate-x-1/2 rounded-full border-[3px] border-tag-edge bg-paper"
				/>
				<p className="truncate font-semibold text-sm" title={label}>
					{label}
				</p>
				<p className="text-sm opacity-80">
					{caption ?? <LocalDate iso={report.finishedAt} />}
				</p>

				<div className="mt-4 flex items-end gap-4 border-tag-ink/25 border-b-2 border-dashed pb-4">
					<span
						aria-hidden="true"
						className="font-black text-[6.5rem] leading-[0.8] tracking-tighter"
					>
						{graded ? summary.grade : "–"}
					</span>
					<span aria-hidden="true" className="pb-1">
						{graded ? (
							<>
								<span className="block font-bold text-3xl tabular-nums leading-none">
									{summary.score}
									<span className="font-medium text-base opacity-70">/100</span>
								</span>
								<span className="mt-1 block text-sm">
									{GRADE_MEANING[summary.grade]}
								</span>
							</>
						) : (
							<span className="block font-semibold">Not graded</span>
						)}
					</span>
				</div>

				{summary.categories.length > 0 ? (
					<ul className="mt-4 space-y-1.5 text-sm">
						{summary.categories.map((c) => (
							<li
								key={c.category}
								className="grid grid-cols-[7.5rem_1fr_2rem] items-center gap-3"
							>
								<span className="truncate">{CATEGORY_LABEL[c.category]}</span>
								<span aria-hidden="true" className="h-1.5 bg-tag-ink/15">
									<span
										className="block h-full bg-tag-ink"
										style={{ width: `${Math.max(2, c.score)}%` }}
									/>
								</span>
								<span className="text-right font-semibold tabular-nums">
									<span className="sr-only">{c.grade}, </span>
									{c.score}
								</span>
							</li>
						))}
					</ul>
				) : (
					<p className="mt-4 text-sm">
						No auditor examined this target, so there is nothing to grade.
					</p>
				)}
			</section>
		</div>
	);
}

const hostOf = (url: string) => {
	try {
		return new URL(url).host;
	} catch {
		return url;
	}
};
