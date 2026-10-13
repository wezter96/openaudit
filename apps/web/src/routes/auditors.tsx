import type { AuditorEngine, TargetKind } from "@openaudit/core/model";
import { Input } from "@openaudit/ui/components/input";
import { cn } from "@openaudit/ui/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useId, useMemo, useState } from "react";

import Loader from "@/components/loader";
import {
	CATEGORY_LABEL,
	ENGINE_LABEL,
	TARGET_LABEL,
} from "@/components/report/meta";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/auditors")({
	head: () => ({
		meta: [
			{ title: "Auditors | openaudit" },
			{
				name: "description",
				content:
					"Every openaudit auditor and agent playbook, grouped by what it audits: codebases, URLs, web apps, containers, infrastructure as code and mobile builds.",
			},
		],
	}),
	// Prefetch during SSR so the catalog is in the HTML; failures fall through
	// to the client-side error state instead of breaking the page.
	loader: ({ context }) =>
		Promise.all([
			context.queryClient.ensureQueryData(orpc.auditors.list.queryOptions()),
			context.queryClient.ensureQueryData(orpc.playbooks.list.queryOptions()),
		]).catch(() => undefined),
	component: AuditorsPage,
});

const TARGET_ORDER: ReadonlyArray<TargetKind> = [
	"codebase",
	"url",
	"webapp",
	"container",
	"iac",
	"mobile",
];

const ENGINE_BADGE: Record<AuditorEngine, string> = {
	builtin: "border-signal text-signal",
	external: "border-ink-soft text-ink",
	agentic: "border-tag-edge bg-tag text-tag-ink",
};

function EngineBadge({
	engine,
	tool,
}: {
	engine: AuditorEngine;
	tool?: string;
}) {
	return (
		<span
			className={cn(
				"inline-flex items-center border px-1.5 py-0.5 font-medium text-xs",
				ENGINE_BADGE[engine],
			)}
		>
			{ENGINE_LABEL[engine]}
			{tool ? `: ${tool}` : ""}
		</span>
	);
}

function AuditorsPage() {
	const id = useId();
	const auditors = useQuery(orpc.auditors.list.queryOptions());
	const playbooks = useQuery(orpc.playbooks.list.queryOptions());
	const [engine, setEngine] = useState<AuditorEngine | "all">("all");
	const [query, setQuery] = useState("");

	const filtered = useMemo(() => {
		const q = query.trim().toLowerCase();
		return (auditors.data ?? []).filter(
			(a) =>
				(engine === "all" || a.engine === engine) &&
				(!q ||
					[a.id, a.title, a.description, a.tool ?? "", ...a.categories].some(
						(v) => v.toLowerCase().includes(q),
					)),
		);
	}, [auditors.data, engine, query]);

	const groups = TARGET_ORDER.map((target) => ({
		target,
		items: filtered.filter((a) => a.targets.includes(target)),
	}));

	return (
		<div className="mx-auto max-w-6xl px-4 pt-12 sm:px-6">
			<h1 className="font-extrabold text-4xl tracking-tight sm:text-5xl">
				Auditors
			</h1>
			<p className="mt-3 max-w-[64ch] text-ink-soft">
				Built-in auditors run anywhere with no setup. External-tool auditors
				wrap scanners such as Semgrep or Trivy and are skipped, with an install
				hint, when the tool is missing. Agentic auditors follow a playbook with
				an LLM and only run with{" "}
				<code className="font-mono text-ink">--agentic</code>.
			</p>

			{auditors.isPending ? (
				<Loader />
			) : auditors.isError ? (
				<div
					role="alert"
					className="mt-10 border-sev-critical border-l-4 bg-surface p-4"
				>
					<p className="font-semibold">
						The auditor catalog could not be loaded
					</p>
					<p className="mt-1 text-ink-soft text-sm">
						The API server did not respond ({auditors.error.message}). Run{" "}
						<code className="font-mono">bunx @openaudit/cli list</code> to see
						the same catalog locally.
					</p>
				</div>
			) : (
				<>
					<search
						aria-label="Filter auditors"
						className="mt-10 flex flex-col gap-4 border border-rule bg-surface p-4 md:flex-row md:items-end"
					>
						<fieldset>
							<legend className="mb-1.5 font-medium text-sm">Engine</legend>
							<div className="flex flex-wrap gap-x-4 gap-y-1">
								{(["all", "builtin", "external", "agentic"] as const).map(
									(e) => (
										<label
											key={e}
											className="inline-flex items-center gap-1.5 text-sm"
										>
											<input
												type="radio"
												name={`${id}-engine`}
												value={e}
												checked={engine === e}
												onChange={() => setEngine(e)}
												className="size-4 accent-[var(--signal)]"
											/>
											{e === "all" ? "All" : ENGINE_LABEL[e]}
										</label>
									),
								)}
							</div>
						</fieldset>
						<div className="md:ml-auto md:w-80">
							<label
								htmlFor={`${id}-q`}
								className="mb-1.5 block font-medium text-sm"
							>
								Search
							</label>
							<Input
								id={`${id}-q`}
								type="search"
								value={query}
								onChange={(e) => setQuery(e.target.value)}
								placeholder="Name, tool or category"
								className="h-9 bg-paper text-sm md:text-sm"
							/>
						</div>
					</search>
					<p aria-live="polite" className="mt-3 text-ink-soft text-sm">
						{filtered.length} of {auditors.data.length} auditors
					</p>

					<nav aria-label="Target types" className="mt-6">
						<ul className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
							{groups.map((g) => (
								<li key={g.target}>
									<a
										href={`#${g.target}`}
										className="text-signal underline underline-offset-2"
									>
										{TARGET_LABEL[g.target]}
									</a>{" "}
									<span className="text-ink-soft">({g.items.length})</span>
								</li>
							))}
							<li>
								<a
									href="#playbooks"
									className="text-signal underline underline-offset-2"
								>
									Playbooks
								</a>{" "}
								<span className="text-ink-soft">
									({playbooks.data?.length ?? 0})
								</span>
							</li>
						</ul>
					</nav>

					{groups.map((g) => (
						<section
							key={g.target}
							id={g.target}
							aria-labelledby={`${g.target}-title`}
							className="mt-14 scroll-mt-6"
						>
							<h2
								id={`${g.target}-title`}
								className="border-rule border-b pb-2 font-bold text-2xl tracking-tight"
							>
								{TARGET_LABEL[g.target]}
							</h2>
							{g.items.length === 0 ? (
								<p className="mt-4 text-ink-soft">
									No auditors match for this target type.
								</p>
							) : (
								<ul className="divide-y divide-rule">
									{g.items.map((a) => (
										<li
											key={a.id}
											className="grid gap-x-8 gap-y-1 py-4 md:grid-cols-[18rem_1fr]"
										>
											<div>
												<h3 className="font-semibold">{a.title}</h3>
												<p className="font-mono text-ink-soft text-xs">
													{a.id}
												</p>
											</div>
											<div>
												<p className="max-w-[72ch] text-sm">{a.description}</p>
												<p className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-ink-soft text-xs">
													<EngineBadge engine={a.engine} tool={a.tool} />
													<span>
														{a.categories
															.map((c) => CATEGORY_LABEL[c])
															.join(", ")}
													</span>
													{!a.defaultEnabled && a.engine !== "agentic" && (
														<span>Opt-in (use --only)</span>
													)}
													{a.network && <span>Uses network services</span>}
												</p>
											</div>
										</li>
									))}
								</ul>
							)}
						</section>
					))}

					<section
						id="playbooks"
						aria-labelledby="playbooks-title"
						className="mt-16 scroll-mt-6"
					>
						<h2
							id="playbooks-title"
							className="border-rule border-b pb-2 font-bold text-2xl tracking-tight"
						>
							Playbooks
						</h2>
						<p className="mt-3 max-w-[64ch] text-ink-soft">
							Procedures for checks that need judgment. Agents fetch them over
							MCP with <code className="font-mono text-ink">get_playbook</code>,
							work through the checklist and send results back with{" "}
							<code className="font-mono text-ink">submit_findings</code>.
						</p>
						{playbooks.isError ? (
							<p role="alert" className="mt-4 text-sev-critical">
								Playbooks could not be loaded: {playbooks.error.message}
							</p>
						) : !playbooks.data?.length ? (
							<p className="mt-4 text-ink-soft">
								No playbooks are published yet.
							</p>
						) : (
							<ul className="mt-2 divide-y divide-rule">
								{playbooks.data.map((p) => (
									<li key={p.id} className="py-4">
										<h3 className="font-semibold">{p.title}</h3>
										<p className="font-mono text-ink-soft text-xs">{p.id}</p>
										<p className="mt-1 max-w-[72ch] text-sm">{p.summary}</p>
										<p className="mt-2 text-ink-soft text-xs">
											{p.categories.map((c) => CATEGORY_LABEL[c]).join(", ")}.
											Needs {p.needs.join(", ") || "nothing extra"}.
										</p>
										{p.checklist.length > 0 && (
											<details className="mt-2 text-sm">
												<summary className="cursor-pointer text-signal">
													Checklist ({p.checklist.length} items)
												</summary>
												<ul className="mt-2 max-w-[72ch] list-disc space-y-1 pl-5">
													{p.checklist.map((item) => (
														<li key={item}>{item}</li>
													))}
												</ul>
											</details>
										)}
									</li>
								))}
							</ul>
						)}
					</section>
				</>
			)}
		</div>
	);
}
