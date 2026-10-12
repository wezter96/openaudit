import { Check } from "lucide-react";

import { TARGET_LABEL } from "./report/meta";

type Target = "codebase" | "url" | "webapp" | "container" | "iac" | "mobile";

const TARGETS: ReadonlyArray<{ id: Target; short: string }> = [
	{ id: "codebase", short: "Code" },
	{ id: "url", short: "URL" },
	{ id: "webapp", short: "Web app" },
	{ id: "container", short: "Container" },
	{ id: "iac", short: "IaC" },
	{ id: "mobile", short: "Mobile" },
];

const AREAS: ReadonlyArray<{
	area: string;
	checks: string;
	covers: ReadonlyArray<Target>;
}> = [
	{
		area: "Security",
		checks: "Secrets, injection-prone code, headers, TLS, misconfiguration",
		covers: ["codebase", "url", "webapp", "container", "iac", "mobile"],
	},
	{
		area: "Accessibility",
		checks: "WCAG checks on markup, components and rendered pages",
		covers: ["codebase", "url", "webapp", "mobile"],
	},
	{
		area: "Performance",
		checks: "Transfer size, caching, Core Web Vitals, image and bundle weight",
		covers: ["codebase", "url", "webapp", "container", "mobile"],
	},
	{
		area: "SEO",
		checks: "Metadata, crawlability, sitemaps, structured data",
		covers: ["url", "webapp"],
	},
	{
		area: "Privacy",
		checks: "Trackers, cookies, consent, mobile permissions",
		covers: ["codebase", "url", "webapp", "mobile"],
	},
	{
		area: "Best practices",
		checks: "Repository hygiene, deprecated APIs, Dockerfile and IaC lint",
		covers: ["codebase", "url", "webapp", "container", "iac", "mobile"],
	},
	{
		area: "Supply chain",
		checks: "Known-vulnerable dependencies, pinning, unmaintained packages",
		covers: ["codebase", "container", "iac", "mobile"],
	},
	{
		area: "Compliance",
		checks: "Licences, cookie consent, policy checks on infrastructure",
		covers: ["codebase", "url", "webapp", "iac", "mobile"],
	},
];

/** Audit areas × target types. */
export function CoverageMatrix({ captionId }: { captionId: string }) {
	return (
		<section
			aria-labelledby={captionId}
			// biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be keyboard reachable
			tabIndex={0}
			className="relative overflow-x-auto border border-rule bg-surface"
		>
			<table className="w-full min-w-[44rem] border-collapse text-sm">
				<thead>
					<tr className="border-rule border-b">
						<th scope="col" className="px-4 py-3 text-left font-semibold">
							Area
						</th>
						{TARGETS.map((t) => (
							<th
								key={t.id}
								scope="col"
								className="w-20 px-2 py-3 text-center font-semibold"
							>
								<abbr title={TARGET_LABEL[t.id]} className="no-underline">
									{t.short}
								</abbr>
							</th>
						))}
					</tr>
				</thead>
				<tbody className="divide-y divide-rule">
					{AREAS.map((row) => (
						<tr key={row.area}>
							<th scope="row" className="px-4 py-3 text-left font-normal">
								<span className="block font-semibold">{row.area}</span>
								<span className="block text-ink-soft">{row.checks}</span>
							</th>
							{TARGETS.map((t) => (
								<td key={t.id} className="px-2 py-3 text-center">
									{row.covers.includes(t.id) ? (
										<>
											<Check
												aria-hidden="true"
												className="mx-auto size-5 text-signal"
												strokeWidth={2.5}
											/>
											<span className="sr-only">Covered</span>
										</>
									) : (
										<>
											<span aria-hidden="true" className="text-rule">
												·
											</span>
											<span className="sr-only">Not covered</span>
										</>
									)}
								</td>
							))}
						</tr>
					))}
				</tbody>
			</table>
		</section>
	);
}
