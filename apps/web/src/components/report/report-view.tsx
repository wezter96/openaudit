import type { Report } from "@openaudit/core/model";
import type React from "react";
import { useId, useMemo } from "react";

import { AuditorTable } from "./auditor-table";
import { FindingsList } from "./findings-list";
import { LocalDate } from "./local-date";
import { formatDuration, SEVERITY_ORDER, targetName } from "./meta";
import { ScoreTag } from "./score-tag";
import { SeverityCountsRow } from "./severity";

/** Full rendering of an openaudit report. Headings start at h2. */
export function ReportView({
	report,
	tagCaption,
	showTag = true,
	titleRef,
}: {
	report: Report;
	tagCaption?: string;
	/** Hide the grade tag when the page already shows it. */
	showTag?: boolean;
	/** Lets the page move focus to the title once a report arrives. */
	titleRef?: React.Ref<HTMLHeadingElement>;
}) {
	const id = useId();
	const findings = useMemo(
		() =>
			report.results
				.flatMap((r) => r.findings)
				.filter((f) => f.duplicateOf === undefined)
				.sort(
					(a, b) =>
						SEVERITY_ORDER.indexOf(a.severity) -
						SEVERITY_ORDER.indexOf(b.severity),
				),
		[report],
	);
	const { auditors } = report.summary;

	return (
		<article aria-labelledby={`${id}-title`} className="space-y-12">
			<header
				className={
					showTag
						? "grid gap-10 lg:grid-cols-[22rem_1fr] lg:items-start"
						: undefined
				}
			>
				{showTag && (
					<ScoreTag
						report={report}
						caption={tagCaption}
						className="mx-auto w-full max-w-[22rem] lg:mx-0"
					/>
				)}
				<div className="min-w-0 space-y-6">
					<div>
						<h2
							ref={titleRef}
							tabIndex={-1}
							id={`${id}-title`}
							className="break-words font-bold text-2xl tracking-tight sm:text-3xl"
						>
							Report for {targetName(report.target)}
						</h2>
						<dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
							<dt className="text-ink-soft">Audited</dt>
							<dd>
								<LocalDate iso={report.startedAt} withTime />
							</dd>
							<dt className="text-ink-soft">Took</dt>
							<dd>{formatDuration(report.durationMs)}</dd>
							<dt className="text-ink-soft">Target type</dt>
							<dd>{report.target.kinds.join(", ")}</dd>
							{report.target.technologies.length > 0 && (
								<>
									<dt className="text-ink-soft">Detected</dt>
									<dd>{report.target.technologies.join(", ")}</dd>
								</>
							)}
							<dt className="text-ink-soft">Auditors</dt>
							<dd>
								{auditors.passed} passed, {auditors.failed} with findings,{" "}
								{auditors.skipped} skipped, {auditors.error} errored
							</dd>
							<dt className="text-ink-soft">Tool</dt>
							<dd>
								{report.tool.name} {report.tool.version}
							</dd>
						</dl>
					</div>
					<SeverityCountsRow counts={report.summary.counts} />
					{report.ai && (
						<section
							aria-labelledby={`${id}-ai`}
							className="border-signal border-l-4 bg-surface p-4"
						>
							<h3 id={`${id}-ai`} className="font-semibold">
								Priorities from {report.ai.model}
							</h3>
							<p className="mt-1 max-w-[72ch] text-sm">{report.ai.summary}</p>
							<ol className="mt-3 list-decimal space-y-2 pl-5 text-sm">
								{report.ai.priorities.map((p) => (
									<li key={p.title}>
										<span className="font-medium">{p.title}.</span> {p.why}{" "}
										<span className="text-ink-soft">Fix: {p.fix}</span>
									</li>
								))}
							</ol>
						</section>
					)}
				</div>
			</header>

			<section aria-labelledby={`${id}-findings`}>
				<h3
					id={`${id}-findings`}
					className="mb-4 font-bold text-xl tracking-tight"
				>
					Findings
				</h3>
				<FindingsList findings={findings} headingId={`${id}-findings`} />
			</section>

			<section aria-labelledby={`${id}-auditors`}>
				<h3
					id={`${id}-auditors`}
					className="mb-4 font-bold text-xl tracking-tight"
				>
					Auditors
				</h3>
				<AuditorTable results={report.results} captionId={`${id}-auditors`} />
			</section>
		</article>
	);
}
