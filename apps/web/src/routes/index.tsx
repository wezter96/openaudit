import type { Report } from "@openaudit/core/model";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { AuditUrlForm } from "@/components/audit-url-form";
import { CodeBlock } from "@/components/code-block";
import { CoverageMatrix } from "@/components/coverage-matrix";
import { ReportView } from "@/components/report/report-view";
import { ScoreTag } from "@/components/report/score-tag";
import { sampleReport } from "@/lib/sample-report";

export const Route = createFileRoute("/")({
	component: HomeComponent,
});

const MCP_TOOLS = [
	["run_audit", "audit a directory, URL, image or build and keep the report"],
	["get_report / get_finding", "page through results without flooding context"],
	["list_playbooks / get_playbook", "fetch judgment-heavy procedures to run"],
	["submit_findings", "add what the agent found to the same report"],
	["compare_reports", "show what a change fixed or introduced"],
] as const;

function HomeComponent() {
	const [report, setReport] = useState<Report | undefined>();
	const titleRef = useRef<HTMLHeadingElement>(null);

	useEffect(() => {
		if (report) titleRef.current?.focus();
	}, [report]);

	return (
		<div className="mx-auto max-w-6xl px-4 sm:px-6">
			<section
				aria-labelledby="hero-title"
				className="grid grid-cols-[minmax(0,1fr)] gap-12 pt-14 pb-16 sm:pt-20 lg:grid-cols-[minmax(0,1fr)_22rem] lg:gap-16"
			>
				<div className="min-w-0">
					<h1
						id="hero-title"
						className="max-w-[16ch] text-balance font-extrabold text-[2.75rem] leading-[1.02] tracking-[-0.035em] sm:text-6xl lg:text-7xl"
					>
						Audit everything you ship
					</h1>
					<p className="mt-6 max-w-[56ch] text-ink-soft text-lg sm:text-xl">
						Code, sites, apps, containers, infrastructure and mobile builds —
						from your terminal or your AI agent. One report covering security,
						accessibility, performance, SEO, privacy and the supply chain.
					</p>
					<CodeBlock
						code="bunx @openaudit/cli ."
						prompt
						label="install command"
						className="mt-8 max-w-md"
					/>
					<p className="mt-2 text-ink-soft text-sm">
						Runs in the current directory. No account, no upload: the audit runs
						on your machine.
					</p>
					<div className="mt-10 max-w-2xl">
						<AuditUrlForm onReport={setReport} />
					</div>
				</div>
				<div className="lg:pt-4">
					<ScoreTag
						report={report ?? sampleReport}
						caption={report ? undefined : "Example report"}
						className="mx-auto w-full max-w-[22rem]"
					/>
					{!report && (
						<p className="mx-auto mt-4 max-w-[22rem] text-center text-ink-soft text-sm">
							This tag is from an example audit.{" "}
							<Link
								to="/report"
								search={{ example: true }}
								className="text-signal underline underline-offset-2"
							>
								Open the full example report
							</Link>
						</p>
					)}
				</div>
			</section>

			{report && (
				<section
					aria-label="Audit result"
					className="border-rule border-t py-12"
				>
					<ReportView report={report} showTag={false} titleRef={titleRef} />
				</section>
			)}

			<section
				aria-labelledby="coverage-title"
				className="border-rule border-t py-16"
			>
				<div className="mb-8 max-w-[60ch]">
					<h2 id="coverage-title" className="font-bold text-3xl tracking-tight">
						What it checks, wherever it runs
					</h2>
					<p className="mt-3 text-ink-soft">
						Point openaudit at a folder, a URL, a container image or a mobile
						build. It detects what the target is and runs every auditor that
						applies: fast built-in checks first, external scanners when they are
						installed, and agentic reviews when you ask for them.
					</p>
				</div>
				<CoverageMatrix captionId="coverage-title" />
				<p className="mt-3 text-ink-soft text-sm">
					Each area is backed by several auditors.{" "}
					<Link
						to="/auditors"
						className="text-signal underline underline-offset-2"
					>
						Browse the auditor catalog
					</Link>
					.
				</p>
			</section>

			<section
				aria-labelledby="agents-title"
				className="grid grid-cols-[minmax(0,1fr)] gap-10 border-rule border-t py-16 lg:grid-cols-2 lg:gap-16"
			>
				<div className="max-w-[60ch]">
					<h2 id="agents-title" className="font-bold text-3xl tracking-tight">
						Built for agents too
					</h2>
					<p className="mt-3 text-ink-soft">
						openaudit ships an MCP server, so Claude Code, Cursor and other
						agents can run audits, read findings and fix them in the same
						session. Some checks need judgment rather than rules: reviewing
						authorization logic, walking a checkout flow with a screen reader,
						threat modelling an API. Those are playbooks: written procedures the
						agent follows, returning findings into the same report.
					</p>
					<dl className="mt-6 space-y-3 text-sm">
						{MCP_TOOLS.map(([name, what]) => (
							<div key={name} className="grid gap-x-4 sm:grid-cols-[13rem_1fr]">
								<dt className="font-mono font-semibold">{name}</dt>
								<dd className="text-ink-soft">{what}</dd>
							</div>
						))}
					</dl>
				</div>
				<div className="min-w-0 space-y-6">
					<div>
						<h3 className="mb-2 font-semibold">Add it to Claude Code</h3>
						<CodeBlock
							code="claude mcp add openaudit -- bunx @openaudit/cli mcp"
							prompt
							label="MCP install command"
						/>
					</div>
					<div>
						<h3 className="mb-2 font-semibold">Machine-readable output</h3>
						<CodeBlock
							code={
								"bunx @openaudit/cli . --json > report.json\nbunx @openaudit/cli https://staging.example --format sarif --out audit.sarif"
							}
							prompt
							label="JSON and SARIF commands"
						/>
					</div>
					<div>
						<h3 className="mb-2 font-semibold">Let the agent run playbooks</h3>
						<CodeBlock
							code="bunx @openaudit/cli . --agentic --only agent.authz"
							prompt
							label="agentic audit command"
						/>
					</div>
					<p className="text-sm">
						<Link
							to="/docs"
							hash="agents"
							className="text-signal underline underline-offset-2"
						>
							Read the agents and MCP guide
						</Link>
					</p>
				</div>
			</section>
		</div>
	);
}
