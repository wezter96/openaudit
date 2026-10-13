import { createFileRoute, Link } from "@tanstack/react-router";

import { CodeBlock } from "@/components/code-block";

export const Route = createFileRoute("/docs")({
	head: () => ({
		meta: [
			{ title: "Docs | openaudit" },
			{
				name: "description",
				content:
					"Quick start, CLI reference, configuration, CI with SARIF, agents and MCP, and the openaudit report schema.",
			},
		],
	}),
	component: DocsPage,
});

const TOC = [
	{ id: "quick-start", label: "Quick start" },
	{ id: "cli", label: "CLI reference" },
	{ id: "config", label: "Configuration" },
	{ id: "ci", label: "CI and SARIF" },
	{ id: "agents", label: "Agents and MCP" },
	{ id: "schema", label: "Report schema" },
	{ id: "self-hosting", label: "Self-hosting the API" },
] as const;

const COMMANDS: ReadonlyArray<readonly [string, string]> = [
	[
		"openaudit [target]",
		"Audit a target (same as `audit`). The target is a directory, file, http(s) URL or image:<ref>; default `.`.",
	],
	["openaudit audit [target]", "Audit a target explicitly."],
	[
		"openaudit list",
		"List auditors and playbooks. `--target-kind url` filters, `--json` for machines.",
	],
	[
		"openaudit doctor",
		"Check Bun, external tools, the browser and AI credentials.",
	],
	[
		"openaudit init",
		"Write a starter openaudit.config.json (`--force` overwrites, `--dir` picks the folder).",
	],
	[
		"openaudit mcp",
		"Start the MCP server on stdio for Claude Code, Cursor, Codex and other agents.",
	],
	[
		"openaudit schema [report|config]",
		"Print the JSON Schema of the report or the config file.",
	],
];

const FLAGS: ReadonlyArray<readonly [string, string]> = [
	[
		"--format, -f <fmt>",
		"terminal, json, sarif, markdown or html. Repeat or comma-separate; several formats need --out.",
	],
	[
		"--out, -o <dir>",
		"Write openaudit-report.<ext> for each format into this directory.",
	],
	[
		"--only <pattern>",
		"Run only these auditors: an id (web.headers), prefix (web) or glob (web.*). Repeatable.",
	],
	["--exclude <pattern>", "Skip auditors, same patterns as --only."],
	[
		"--category <name>",
		"Only auditors in these categories, e.g. security,accessibility.",
	],
	[
		"--fail-on <severity>",
		"Exit 1 when a finding is at least this severe: critical, high, medium, low, info or none. Default high.",
	],
	[
		"--offline",
		"No network access except to the target itself (skips advisory lookups).",
	],
	[
		"--browser",
		"Drive a real browser with Playwright for URL targets (rendered accessibility, Web Vitals).",
	],
	["--max-pages <n>", "Pages to crawl for URL targets."],
	[
		'--header, -H "Name: value"',
		"Extra request header for the target origin only, e.g. a staging cookie. Repeatable.",
	],
	[
		"--agentic",
		"Enable agentic auditors that follow playbooks. Needs ANTHROPIC_API_KEY or Claude Code auth.",
	],
	["--ai", "Attach AI insights: a prioritised summary of what to fix first."],
	["--model <id>", "Model for agentic auditors and --ai."],
	[
		"--baseline <report.json>",
		"Suppress findings already present in an earlier report, so only new ones count.",
	],
	["--concurrency <n>", "Auditors run in parallel (default 4)."],
	["--json", "Agent mode: the JSON report on stdout and nothing else."],
	["--quiet, -q", "No progress or notices on stderr."],
	["--verbose", "Terminal output lists every finding with details."],
	[
		"--config <path>",
		"Trusted config file. Without it, openaudit.config.json in the target is read with restrictions.",
	],
	["--no-config", "Ignore openaudit.config.json in the target."],
	[
		"--allow-errors",
		"With --fail-on, accept results even if an auditor errored (otherwise exit 3).",
	],
];

const MCP_TOOLS: ReadonlyArray<readonly [string, string]> = [
	["list_auditors", "Auditors with their categories, targets and engine."],
	[
		"detect_target",
		"What a path or URL is (codebase, container, IaC, mobile…) and which auditors apply.",
	],
	[
		"run_audit",
		"Run an audit and keep the report in the session; returns the summary and a report id.",
	],
	[
		"get_report",
		"Summary and findings of a stored report, paginated and filterable.",
	],
	["get_finding", "Full detail for one finding by fingerprint."],
	["compare_reports", "Findings fixed and introduced between two reports."],
	["list_playbooks", "Judgment-heavy procedures the agent can execute."],
	["get_playbook", "Instructions and checklist for one playbook."],
	[
		"submit_findings",
		"Add the agent's own findings to a report, validated against the schema.",
	],
];

const CONFIG_EXAMPLE = `{
  "exclude": ["code.lint"],
  "categories": ["security", "accessibility", "supply-chain"],
  "failOn": "high",
  "ignore": {
    "rules": ["code.hygiene/ci-missing"],
    "paths": ["test/fixtures/**"],
    "fingerprints": []
  },
  "options": {
    "maxPages": 10,
    "concurrency": 4
  }
}`;

const WORKFLOW = `name: openaudit
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write # upload SARIF to code scanning

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
      - name: Audit
        run: bunx openaudit . --format sarif,json --out audit --fail-on high
      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: audit/openaudit-report.sarif
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: openaudit-report
          path: audit/openaudit-report.json`;

function DefTable({
	caption,
	head,
	rows,
}: {
	caption: string;
	head: readonly [string, string];
	rows: ReadonlyArray<readonly [string, string]>;
}) {
	return (
		<div className="relative mb-6 overflow-x-auto border border-rule">
			<table className="w-full text-left text-sm">
				<caption className="sr-only">{caption}</caption>
				<thead className="bg-muted/70">
					<tr>
						<th scope="col" className="px-3 py-2 font-semibold">
							{head[0]}
						</th>
						<th scope="col" className="px-3 py-2 font-semibold">
							{head[1]}
						</th>
					</tr>
				</thead>
				<tbody className="divide-y divide-rule">
					{rows.map(([k, v]) => (
						<tr key={k} className="align-top">
							<th
								scope="row"
								className="whitespace-nowrap px-3 py-2 font-medium font-mono text-[0.8125rem]"
							>
								{k}
							</th>
							<td className="min-w-[18rem] px-3 py-2">{v}</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

function DocsPage() {
	return (
		<div className="mx-auto grid max-w-6xl gap-10 px-4 pt-12 sm:px-6 lg:grid-cols-[13rem_1fr]">
			<nav
				aria-label="On this page"
				className="lg:sticky lg:top-6 lg:self-start"
			>
				<p className="mb-2 font-semibold text-sm">On this page</p>
				<ul className="space-y-1 text-sm">
					{TOC.map((t) => (
						<li key={t.id}>
							<a
								href={`#${t.id}`}
								className="text-ink-soft hover:text-ink hover:underline"
							>
								{t.label}
							</a>
						</li>
					))}
				</ul>
			</nav>

			<div className="prose-doc min-w-0">
				<h1 className="font-extrabold text-4xl tracking-tight sm:text-5xl">
					Docs
				</h1>
				<p className="mt-3 text-ink-soft">
					openaudit is a single command that audits whatever you point it at and
					writes one report. It runs on <a href="https://bun.sh">Bun</a>.
					External scanners and a browser are optional.
				</p>

				<h2 id="quick-start">Quick start</h2>
				<ol>
					<li>
						Audit the project in the current directory:
						<CodeBlock
							code="bunx openaudit ."
							prompt
							label="audit command"
							className="my-2"
						/>
					</li>
					<li>
						See which optional tools are available to deepen the audit:
						<CodeBlock
							code="bunx openaudit doctor"
							prompt
							label="doctor command"
							className="my-2"
						/>
					</li>
					<li>
						Audit a deployed site, with a real browser for rendered checks:
						<CodeBlock
							code="bunx openaudit https://staging.example.com --browser --max-pages 20"
							prompt
							label="URL audit command"
							className="my-2"
						/>
					</li>
					<li>
						Save a config so CI and teammates run the same audit:
						<CodeBlock
							code="bunx openaudit init"
							prompt
							label="init command"
							className="my-2"
						/>
					</li>
				</ol>
				<p>
					Targets can be a directory, a single file (a Dockerfile, a Terraform
					file, an <code>.apk</code>/<code>.aab</code>/<code>.ipa</code>), an
					http(s) URL or a container image as <code>image:nginx:1.27</code>.
				</p>

				<h2 id="cli">CLI reference</h2>
				<h3>Commands</h3>
				<DefTable
					caption="Commands"
					head={["Command", "What it does"]}
					rows={COMMANDS}
				/>
				<h3>Audit flags</h3>
				<DefTable
					caption="Audit flags"
					head={["Flag", "Effect"]}
					rows={FLAGS}
				/>
				<p>
					Exit codes: <code>0</code> when nothing reaches the{" "}
					<code>--fail-on</code> threshold, <code>1</code> when something does,{" "}
					<code>2</code> for usage or target errors, <code>3</code> when{" "}
					<code>--fail-on</code> is set but an auditor errored (fails closed;{" "}
					<code>--allow-errors</code> accepts partial results).
				</p>

				<h2 id="config">Configuration</h2>
				<p>
					<code>openaudit.config.json</code> sits next to the target. Every key
					is optional and command-line flags override it. Get the full schema
					with <code>openaudit schema config</code>.
				</p>
				<CodeBlock
					code={CONFIG_EXAMPLE}
					label="example configuration"
					className="mb-4"
				/>
				<ul>
					<li>
						<code>only</code>, <code>exclude</code>, <code>categories</code>:
						which auditors run, same patterns as the flags.
					</li>
					<li>
						<code>ignore.rules</code>, <code>ignore.paths</code>,{" "}
						<code>ignore.fingerprints</code>: drop accepted findings by rule id
						pattern, file glob or exact fingerprint.
					</li>
					<li>
						<code>options.settings</code>: per-auditor settings keyed by auditor
						id.
					</li>
				</ul>

				<h2 id="ci">CI and SARIF</h2>
				<p>
					SARIF output plugs into GitHub code scanning, so findings show up as
					annotations on pull requests. This workflow fails the job on high or
					critical findings and keeps the JSON report as an artifact:
				</p>
				<CodeBlock
					code={WORKFLOW}
					label="GitHub Actions workflow"
					className="mb-4"
				/>
				<p>
					To adopt openaudit on an existing project without fixing everything at
					once, commit a report and pass it as <code>--baseline</code>: only new
					findings fail the build.
				</p>

				<h2 id="agents">Agents and MCP</h2>
				<p>
					The MCP server lets an agent run audits, read findings a page at a
					time and fix them in the same session. Add it to Claude Code with:
				</p>
				<CodeBlock
					code="claude mcp add openaudit -- bunx openaudit mcp"
					prompt
					label="MCP install command"
					className="mb-4"
				/>
				<p>
					Other clients take the same command (<code>bunx openaudit mcp</code>,
					stdio transport) in their MCP settings.
				</p>
				<h3>Tools</h3>
				<DefTable
					caption="MCP tools"
					head={["Tool", "Purpose"]}
					rows={MCP_TOOLS}
				/>
				<h3>The audit_project prompt</h3>
				<p>
					The server also publishes an <code>audit_project</code> prompt: it has
					the agent detect the target, run the deterministic audit, work through
					the applicable playbooks, submit what it finds and finish with a
					prioritised fix list.
				</p>
				<h3>Playbooks</h3>
				<p>
					Playbooks cover checks that rules cannot: authorization logic,
					business flows, threat models, an accessibility walkthrough. A host
					agent fetches one with <code>get_playbook</code>, follows the
					checklist with its own tools and returns results with{" "}
					<code>submit_findings</code>. Without a host agent,{" "}
					<code>--agentic</code> runs the same playbooks headless. See the{" "}
					<Link to="/auditors" hash="playbooks">
						playbook catalog
					</Link>
					.
				</p>
				<h3>Without MCP</h3>
				<p>
					Any agent that can run a shell can use{" "}
					<code>bunx openaudit . --json</code>: the report is the only thing on
					stdout, and <code>openaudit schema</code> gives the JSON Schema to
					validate it.
				</p>

				<h2 id="schema">Report schema</h2>
				<p>
					Every output format is rendered from one JSON report with a{" "}
					<code>schemaVersion</code> (currently <code>"1"</code>); fields are
					only added within a version.
				</p>
				<ul>
					<li>
						<code>target</code>: what was audited and the detected kinds and
						technologies.
					</li>
					<li>
						<code>summary</code>: overall <code>score</code> (0–100) and{" "}
						<code>grade</code> (A–F), severity counts, a score per examined
						category and auditor status counts.
					</li>
					<li>
						<code>results</code>: one entry per auditor with its status (
						<code>passed</code>, <code>failed</code>, <code>skipped</code>,{" "}
						<code>error</code>), the reason when skipped or errored, and its
						findings.
					</li>
					<li>
						A finding has a stable <code>ruleId</code>, <code>severity</code>,{" "}
						<code>category</code>, <code>message</code>, optional{" "}
						<code>location</code>, redacted <code>evidence</code>,{" "}
						<code>remediation</code> and <code>references</code>, plus a{" "}
						<code>fingerprint</code> used by baselines and suppressions.
					</li>
				</ul>
				<p>
					Scores fall with accumulated severity: one critical finding halves a
					category score, one high takes it to 73, info findings never count.
					Categories no auditor examined are left out rather than scored 100.
				</p>
				<CodeBlock
					code="bunx openaudit schema > openaudit-report.schema.json"
					prompt
					label="schema command"
					className="mb-4"
				/>
				<p>
					Open any report in the <Link to="/report">report viewer</Link>; it is
					validated against the same schema in your browser.
				</p>

				<h2 id="self-hosting">Self-hosting the API</h2>
				<p>
					The <q>Audit a URL</q> form on the home page calls{" "}
					<code>POST /api-reference/audit/url</code>. The OpenAPI reference is
					served at <code>/api-reference</code> on the API server. Because it
					fetches user-supplied URLs, the endpoint is locked down by default:
				</p>
				<ul>
					<li>
						http and https only, no credentials in URLs, ports 80, 443, 8080 and
						8443.
					</li>
					<li>
						Hostnames are resolved and refused if any address is private,
						loopback, link-local, carrier-grade NAT or reserved (IPv4 and IPv6,
						including IPv4-mapped addresses and cloud metadata at
						169.254.169.254). The connection then goes to the exact address that
						was checked, with the hostname kept for TLS, so a DNS answer that
						changes afterwards cannot redirect it. Every redirect hop is
						resolved, checked and pinned the same way.
					</li>
					<li>
						Only built-in web auditors run: no browser, no subprocesses, no file
						access.
					</li>
					<li>
						At most 5 pages, 60 seconds and 2 MB per response; 10 audits per
						minute per client.
					</li>
				</ul>
				<p>
					To audit internal services from your own deployment, set{" "}
					<code>ALLOW_PRIVATE_TARGETS=true</code>. Behind a reverse proxy, set{" "}
					<code>TRUST_PROXY=true</code> so rate limits apply per client rather
					than per proxy. As defence in depth, also block private ranges for the
					server at the network level.
				</p>
			</div>
		</div>
	);
}
