import type { Category, Finding, Severity } from "@openaudit/core/model";
import { Button } from "@openaudit/ui/components/button";
import { Input } from "@openaudit/ui/components/input";
import { ChevronRight } from "lucide-react";
import { useId, useMemo, useState } from "react";

import {
	CATEGORY_LABEL,
	SEVERITY_LABEL,
	SEVERITY_ORDER,
	safeHref,
} from "./meta";
import { SeverityBadge } from "./severity";

const PAGE = 50;

const selectClass =
	"h-9 w-full border border-input bg-surface px-2 text-sm text-ink";

export function FindingsList({
	findings,
	headingId,
}: {
	findings: ReadonlyArray<Finding>;
	headingId?: string;
}) {
	const id = useId();
	const [severities, setSeverities] = useState<ReadonlySet<Severity>>(
		() => new Set(SEVERITY_ORDER),
	);
	const [category, setCategory] = useState<Category | "">("");
	const [auditor, setAuditor] = useState("");
	const [query, setQuery] = useState("");
	const [limit, setLimit] = useState(PAGE);

	const categories = useMemo(
		() => [...new Set(findings.map((f) => f.category))].sort(),
		[findings],
	);
	const auditors = useMemo(
		() => [...new Set(findings.map((f) => f.auditor))].sort(),
		[findings],
	);
	const severityCounts = useMemo(() => {
		const counts = new Map<Severity, number>();
		for (const f of findings)
			counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
		return counts;
	}, [findings]);

	const filtered = useMemo(() => {
		const q = query.trim().toLowerCase();
		return findings.filter(
			(f) =>
				severities.has(f.severity) &&
				(!category || f.category === category) &&
				(!auditor || f.auditor === auditor) &&
				(!q ||
					[
						f.title,
						f.message,
						f.ruleId,
						f.location?.file,
						f.location?.url,
						f.evidence,
					].some((v) => v?.toLowerCase().includes(q))),
		);
	}, [findings, severities, category, auditor, query]);

	const toggleSeverity = (s: Severity) => {
		setLimit(PAGE);
		setSeverities((prev) => {
			const next = new Set(prev);
			if (next.has(s)) next.delete(s);
			else next.add(s);
			return next;
		});
	};

	if (findings.length === 0)
		return (
			<p className="border border-rule border-dashed px-4 py-6 text-ink-soft">
				No findings. Every auditor that ran came back clean.
			</p>
		);

	return (
		<div>
			<search
				aria-labelledby={headingId}
				className="grid gap-4 border border-rule bg-surface p-4 md:grid-cols-[auto_1fr_1fr_1.4fr]"
			>
				<fieldset>
					<legend className="mb-1.5 font-medium text-sm">Severity</legend>
					<div className="flex flex-wrap gap-x-3 gap-y-1">
						{SEVERITY_ORDER.filter((s) => severityCounts.has(s)).map((s) => (
							<label
								key={s}
								className="inline-flex cursor-pointer items-center gap-1.5 text-sm"
							>
								<input
									type="checkbox"
									className="size-4 accent-[var(--signal)]"
									checked={severities.has(s)}
									onChange={() => toggleSeverity(s)}
								/>
								{SEVERITY_LABEL[s]}
								<span className="text-ink-soft tabular-nums">
									({severityCounts.get(s)})
								</span>
							</label>
						))}
					</div>
				</fieldset>
				<div>
					<label
						htmlFor={`${id}-cat`}
						className="mb-1.5 block font-medium text-sm"
					>
						Category
					</label>
					<select
						id={`${id}-cat`}
						className={selectClass}
						value={category}
						onChange={(e) => {
							setLimit(PAGE);
							setCategory(e.target.value as Category | "");
						}}
					>
						<option value="">All categories</option>
						{categories.map((c) => (
							<option key={c} value={c}>
								{CATEGORY_LABEL[c]}
							</option>
						))}
					</select>
				</div>
				<div>
					<label
						htmlFor={`${id}-aud`}
						className="mb-1.5 block font-medium text-sm"
					>
						Auditor
					</label>
					<select
						id={`${id}-aud`}
						className={selectClass}
						value={auditor}
						onChange={(e) => {
							setLimit(PAGE);
							setAuditor(e.target.value);
						}}
					>
						<option value="">All auditors</option>
						{auditors.map((a) => (
							<option key={a} value={a}>
								{a}
							</option>
						))}
					</select>
				</div>
				<div>
					<label
						htmlFor={`${id}-q`}
						className="mb-1.5 block font-medium text-sm"
					>
						Search
					</label>
					<Input
						id={`${id}-q`}
						type="search"
						className="h-9 bg-surface text-sm md:text-sm"
						placeholder="Title, rule, file or URL"
						value={query}
						onChange={(e) => {
							setLimit(PAGE);
							setQuery(e.target.value);
						}}
					/>
				</div>
			</search>

			<p aria-live="polite" className="mt-4 mb-2 text-ink-soft text-sm">
				Showing {Math.min(limit, filtered.length)} of {filtered.length}
				{filtered.length !== findings.length && ` (${findings.length} total)`}{" "}
				findings
			</p>

			{filtered.length === 0 ? (
				<p className="border border-rule border-dashed px-4 py-6 text-ink-soft">
					No findings match these filters. Clear the search or select more
					severities.
				</p>
			) : (
				<ul className="divide-y divide-rule border-rule border-y">
					{filtered.slice(0, limit).map((f) => (
						<FindingItem key={`${f.auditor}:${f.fingerprint}`} finding={f} />
					))}
				</ul>
			)}

			{filtered.length > limit && (
				<Button
					variant="outline"
					className="mt-4 h-9 text-sm"
					onClick={() => setLimit((l) => l + PAGE)}
				>
					Show {Math.min(PAGE, filtered.length - limit)} more
				</Button>
			)}
		</div>
	);
}

function FindingItem({ finding: f }: { finding: Finding }) {
	const loc = f.location;
	const where = loc?.file
		? `${loc.file}${loc.line ? `:${loc.line}` : ""}${loc.column ? `:${loc.column}` : ""}`
		: loc?.url;

	return (
		<li>
			<details className="group">
				<summary className="flex cursor-pointer list-none items-start gap-3 px-1 py-3 hover:bg-muted/60 [&::-webkit-details-marker]:hidden">
					<ChevronRight
						aria-hidden="true"
						className="mt-1 size-4 shrink-0 text-ink-soft transition-transform group-open:rotate-90"
					/>
					<span className="w-16 shrink-0 pt-0.5">
						<SeverityBadge severity={f.severity} />
					</span>
					<span className="min-w-0 flex-1">
						<span className="block font-medium">{f.title}</span>
						<span className="block truncate text-ink-soft text-sm">
							{CATEGORY_LABEL[f.category]}
							{where ? <> in {where}</> : null}
						</span>
					</span>
				</summary>
				<div className="space-y-3 pr-2 pb-5 pl-[6.25rem] text-sm">
					<p className="max-w-[72ch] whitespace-pre-line">{f.message}</p>
					{f.evidence && (
						<pre className="max-w-full overflow-x-auto border border-rule bg-surface p-3 font-mono text-xs">
							<code>{f.evidence}</code>
						</pre>
					)}
					{f.remediation && (
						<div className="max-w-[72ch]">
							<p className="font-semibold">How to fix</p>
							<p className="whitespace-pre-line">{f.remediation}</p>
						</div>
					)}
					{f.references && f.references.length > 0 && (
						<ul className="space-y-0.5">
							{f.references.map((r) => {
								const href = safeHref(r);
								return (
									<li key={r} className="break-all">
										{href ? (
											<a
												href={href}
												target="_blank"
												rel="noopener noreferrer"
												className="text-signal underline underline-offset-2"
											>
												{r}
												<span className="sr-only"> (opens in a new tab)</span>
											</a>
										) : (
											r
										)}
									</li>
								);
							})}
						</ul>
					)}
					<dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-ink-soft text-xs">
						<dt>Rule</dt>
						<dd className="break-all font-mono">{f.ruleId}</dd>
						<dt>Auditor</dt>
						<dd className="font-mono">{f.auditor}</dd>
						{loc?.selector && (
							<>
								<dt>Selector</dt>
								<dd className="break-all font-mono">{loc.selector}</dd>
							</>
						)}
						{f.confidence && (
							<>
								<dt>Confidence</dt>
								<dd>{f.confidence}</dd>
							</>
						)}
						{f.tags && f.tags.length > 0 && (
							<>
								<dt>Tags</dt>
								<dd>{f.tags.join(", ")}</dd>
							</>
						)}
						<dt>Fingerprint</dt>
						<dd className="font-mono">{f.fingerprint}</dd>
					</dl>
				</div>
			</details>
		</li>
	);
}
