import type { Category, Finding, Severity } from "@openaudit/core/model";
import { Button } from "@openaudit/ui/components/button";
import { Input } from "@openaudit/ui/components/input";
import { ChevronRight } from "lucide-react";
import type React from "react";
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

/** What the findings are narrowed to; an empty category, auditor or query allows all. */
interface Filters {
	readonly severities: ReadonlySet<Severity>;
	readonly category: Category | "";
	readonly auditor: string;
	/** Lowercased search text. */
	readonly q: string;
}

const uniqueSorted = <T extends string>(values: ReadonlyArray<T>) =>
	[...new Set(values)].sort();

const countBySeverity = (findings: ReadonlyArray<Finding>) => {
	const counts = new Map<Severity, number>();
	for (const f of findings)
		counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
	return counts;
};

const searchable = (f: Finding) => [
	f.title,
	f.message,
	f.ruleId,
	f.location?.file,
	f.location?.url,
	f.evidence,
];

const matchesQuery = (f: Finding, q: string) =>
	!q || searchable(f).some((v) => v?.toLowerCase().includes(q));

const matches = (f: Finding, filters: Filters) =>
	filters.severities.has(f.severity) &&
	(!filters.category || f.category === filters.category) &&
	(!filters.auditor || f.auditor === filters.auditor) &&
	matchesQuery(f, filters.q);

function SeverityFilter({
	counts,
	selected,
	onToggle,
}: {
	counts: ReadonlyMap<Severity, number>;
	selected: ReadonlySet<Severity>;
	onToggle: (s: Severity) => void;
}) {
	return (
		<fieldset>
			<legend className="mb-1.5 font-medium text-sm">Severity</legend>
			<div className="flex flex-wrap gap-x-3 gap-y-1">
				{SEVERITY_ORDER.filter((s) => counts.has(s)).map((s) => (
					<label
						key={s}
						className="inline-flex cursor-pointer items-center gap-1.5 text-sm"
					>
						<input
							type="checkbox"
							className="size-4 accent-[var(--signal)]"
							checked={selected.has(s)}
							onChange={() => onToggle(s)}
						/>
						{SEVERITY_LABEL[s]}
						<span className="text-ink-soft tabular-nums">
							({counts.get(s)})
						</span>
					</label>
				))}
			</div>
		</fieldset>
	);
}

/** A labelled select of one finding field; "" is the "All …" option. */
function SelectFilter({
	id,
	label,
	all,
	value,
	options,
	onChange,
}: {
	id: string;
	label: string;
	all: string;
	value: string;
	options: ReadonlyArray<{ readonly value: string; readonly label: string }>;
	onChange: (value: string) => void;
}) {
	return (
		<div>
			<label htmlFor={id} className="mb-1.5 block font-medium text-sm">
				{label}
			</label>
			<select
				id={id}
				className={selectClass}
				value={value}
				onChange={(e) => onChange(e.target.value)}
			>
				<option value="">{all}</option>
				{options.map((o) => (
					<option key={o.value} value={o.value}>
						{o.label}
					</option>
				))}
			</select>
		</div>
	);
}

function SearchFilter({
	id,
	value,
	onChange,
}: {
	id: string;
	value: string;
	onChange: (value: string) => void;
}) {
	return (
		<div>
			<label htmlFor={id} className="mb-1.5 block font-medium text-sm">
				Search
			</label>
			<Input
				id={id}
				type="search"
				className="h-9 bg-surface text-sm md:text-sm"
				placeholder="Title, rule, file or URL"
				value={value}
				onChange={(e) => onChange(e.target.value)}
			/>
		</div>
	);
}

function FindingRows({
	filtered,
	limit,
}: {
	filtered: ReadonlyArray<Finding>;
	limit: number;
}) {
	return filtered.length === 0 ? (
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
	);
}

/** The list's filter state; every filter change starts again from the first page. */
function useFindingFilters(findings: ReadonlyArray<Finding>) {
	const [severities, setSeverities] = useState<ReadonlySet<Severity>>(
		() => new Set(SEVERITY_ORDER),
	);
	const [category, setCategory] = useState<Category | "">("");
	const [auditor, setAuditor] = useState("");
	const [query, setQuery] = useState("");
	const [limit, setLimit] = useState(PAGE);

	const filtered = useMemo(() => {
		const filters = {
			severities,
			category,
			auditor,
			q: query.trim().toLowerCase(),
		};
		return findings.filter((f) => matches(f, filters));
	}, [findings, severities, category, auditor, query]);

	const refilter =
		<T,>(set: (value: T) => void) =>
		(value: T) => {
			setLimit(PAGE);
			set(value);
		};

	const toggleSeverity = (s: Severity) => {
		setLimit(PAGE);
		setSeverities((prev) => {
			const next = new Set(prev);
			if (next.has(s)) next.delete(s);
			else next.add(s);
			return next;
		});
	};

	return {
		severities,
		category,
		auditor,
		query,
		limit,
		filtered,
		toggleSeverity,
		setCategory: refilter(setCategory),
		setAuditor: refilter(setAuditor),
		setQuery: refilter(setQuery),
		showMore: () => setLimit((l) => l + PAGE),
	};
}

function FilterBar({
	id,
	headingId,
	findings,
	filters,
}: {
	id: string;
	headingId: string | undefined;
	findings: ReadonlyArray<Finding>;
	filters: ReturnType<typeof useFindingFilters>;
}) {
	const categories = useMemo(
		() => uniqueSorted(findings.map((f) => f.category)),
		[findings],
	);
	const auditors = useMemo(
		() => uniqueSorted(findings.map((f) => f.auditor)),
		[findings],
	);
	const severityCounts = useMemo(() => countBySeverity(findings), [findings]);

	return (
		<search
			aria-labelledby={headingId}
			className="grid gap-4 border border-rule bg-surface p-4 md:grid-cols-[auto_1fr_1fr_1.4fr]"
		>
			<SeverityFilter
				counts={severityCounts}
				selected={filters.severities}
				onToggle={filters.toggleSeverity}
			/>
			<SelectFilter
				id={`${id}-cat`}
				label="Category"
				all="All categories"
				value={filters.category}
				options={categories.map((c) => ({
					value: c,
					label: CATEGORY_LABEL[c],
				}))}
				onChange={(v) => filters.setCategory(v as Category | "")}
			/>
			<SelectFilter
				id={`${id}-aud`}
				label="Auditor"
				all="All auditors"
				value={filters.auditor}
				options={auditors.map((a) => ({ value: a, label: a }))}
				onChange={filters.setAuditor}
			/>
			<SearchFilter
				id={`${id}-q`}
				value={filters.query}
				onChange={filters.setQuery}
			/>
		</search>
	);
}

export function FindingsList({
	findings,
	headingId,
}: {
	findings: ReadonlyArray<Finding>;
	headingId?: string;
}) {
	const id = useId();
	const filters = useFindingFilters(findings);
	const { filtered, limit } = filters;

	if (findings.length === 0)
		return (
			<p className="border border-rule border-dashed px-4 py-6 text-ink-soft">
				No findings. Every auditor that ran came back clean.
			</p>
		);

	return (
		<div>
			<FilterBar
				id={id}
				headingId={headingId}
				findings={findings}
				filters={filters}
			/>

			<p aria-live="polite" className="mt-4 mb-2 text-ink-soft text-sm">
				Showing {Math.min(limit, filtered.length)} of {filtered.length}
				{filtered.length !== findings.length && ` (${findings.length} total)`}{" "}
				findings
			</p>

			<FindingRows filtered={filtered} limit={limit} />

			{filtered.length > limit && (
				<Button
					variant="outline"
					className="mt-4 h-9 text-sm"
					onClick={filters.showMore}
				>
					Show {Math.min(PAGE, filtered.length - limit)} more
				</Button>
			)}
		</div>
	);
}

/** "file:line:column", or the URL for findings on a page. */
const locationText = (loc: Finding["location"]) => {
	if (!loc?.file) return loc?.url;
	return `${loc.file}${loc.line ? `:${loc.line}` : ""}${loc.column ? `:${loc.column}` : ""}`;
};

function Reference({ reference: r }: { reference: string }) {
	const href = safeHref(r);
	return (
		<li className="break-all">
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
}

/** A term and its definition, shown only when there is a definition. */
function OptionalFact({
	term,
	children,
	className,
}: {
	term: string;
	children: React.ReactNode;
	className?: string;
}) {
	return (
		<>
			<dt>{term}</dt>
			<dd className={className}>{children}</dd>
		</>
	);
}

function FindingFacts({ finding: f }: { finding: Finding }) {
	const selector = f.location?.selector;
	return (
		<dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-ink-soft text-xs">
			<dt>Rule</dt>
			<dd className="break-all font-mono">{f.ruleId}</dd>
			<dt>Auditor</dt>
			<dd className="font-mono">{f.auditor}</dd>
			{selector && (
				<OptionalFact term="Selector" className="break-all font-mono">
					{selector}
				</OptionalFact>
			)}
			{f.confidence && (
				<OptionalFact term="Confidence">{f.confidence}</OptionalFact>
			)}
			{f.tags && f.tags.length > 0 && (
				<OptionalFact term="Tags">{f.tags.join(", ")}</OptionalFact>
			)}
			<dt>Fingerprint</dt>
			<dd className="font-mono">{f.fingerprint}</dd>
		</dl>
	);
}

function FindingItem({ finding: f }: { finding: Finding }) {
	const where = locationText(f.location);

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
							{f.references.map((r) => (
								<Reference key={r} reference={r} />
							))}
						</ul>
					)}
					<FindingFacts finding={f} />
				</div>
			</details>
		</li>
	);
}
