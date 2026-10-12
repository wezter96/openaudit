import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AuditorResult,
	type Finding,
	type FindingInput,
	fingerprintOf,
	type Report,
	type Severity,
	severityRank,
	summarize,
	toJson,
} from "@openaudit/core";

/** In-memory LRU of recent reports, mirrored to `.openaudit/reports/` for directory targets. */
export class ReportStore {
	private readonly reports = new Map<string, Report>();
	private readonly paths = new Map<string, string>();

	constructor(private readonly capacity = 20) {}

	static newId(): string {
		const time = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15);
		return `${time}-${crypto.randomUUID().slice(0, 8)}`;
	}

	get(id: string): Report | undefined {
		const report = this.reports.get(id);
		if (report) {
			// refresh recency
			this.reports.delete(id);
			this.reports.set(id, report);
		}
		return report;
	}

	path(id: string): string | undefined {
		return this.paths.get(id);
	}

	ids(): ReadonlyArray<string> {
		return [...this.reports.keys()].reverse();
	}

	/** Stores (or replaces) a report and persists it; returns the JSON path if written. */
	async put(id: string, report: Report): Promise<string | undefined> {
		this.reports.delete(id);
		this.reports.set(id, report);
		while (this.reports.size > this.capacity) {
			const oldest = this.reports.keys().next().value;
			if (oldest === undefined) break;
			this.reports.delete(oldest);
			this.paths.delete(oldest);
		}
		const path = await persist(id, report, "json", toJson(report)).catch(
			() => undefined,
		);
		if (path) this.paths.set(id, path);
		return path;
	}
}

/** Directory where reports for a target are written, if it has one. */
export const reportsDir = (report: Report): string | undefined =>
	report.target.type === "directory" && report.target.root
		? join(report.target.root, ".openaudit", "reports")
		: undefined;

/** Writes `<reportsDir>/<id>.<ext>`; keeps `.openaudit/` out of git. */
export const persist = async (
	id: string,
	report: Report,
	ext: string,
	content: string,
): Promise<string | undefined> => {
	const dir = reportsDir(report);
	if (!dir) return undefined;
	await mkdir(dir, { recursive: true });
	const ignore = join(dir, "..", ".gitignore");
	if (!(await Bun.file(ignore).exists())) await writeFile(ignore, "*\n");
	const path = join(dir, `${id}.${ext}`);
	await writeFile(path, content);
	return path;
};

export const allFindingsOf = (report: Report): Finding[] =>
	report.results
		.flatMap((r) => r.findings)
		.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

export interface ReportDiff {
	readonly new: Finding[];
	readonly fixed: Finding[];
	readonly unchanged: Finding[];
	readonly scoreDelta: number;
}

/** Compares two reports by finding fingerprint. */
export const diffReports = (base: Report, head: Report): ReportDiff => {
	const before = new Map(allFindingsOf(base).map((f) => [f.fingerprint, f]));
	const after = new Map(allFindingsOf(head).map((f) => [f.fingerprint, f]));
	return {
		new: [...after.values()].filter((f) => !before.has(f.fingerprint)),
		fixed: [...before.values()].filter((f) => !after.has(f.fingerprint)),
		unchanged: [...after.values()].filter((f) => before.has(f.fingerprint)),
		scoreDelta: head.summary.score - base.summary.score,
	};
};

/** True when any finding is at least as severe as `threshold`. */
export const breaches = (report: Report, threshold: Severity): boolean =>
	allFindingsOf(report).some(
		(f) => severityRank(f.severity) <= severityRank(threshold),
	);

/**
 * Adds host-agent findings to a report as an `agentic` auditor result named
 * after the playbook. Findings with a known fingerprint are replaced, so
 * resubmitting is idempotent.
 */
export const mergeAgentFindings = (
	report: Report,
	auditor: {
		readonly id: string;
		readonly title: string;
		readonly categories: ReadonlyArray<
			Report["summary"]["categories"][number]["category"]
		>;
	},
	inputs: ReadonlyArray<FindingInput>,
): { report: Report; added: Finding[] } => {
	const added: Finding[] = inputs.map((input) => {
		const ruleId = input.ruleId.startsWith(`${auditor.id}/`)
			? input.ruleId
			: `${auditor.id}/${input.ruleId}`;
		const withRule = { ...input, ruleId };
		return {
			...withRule,
			auditor: auditor.id,
			fingerprint: input.fingerprint ?? fingerprintOf(auditor.id, withRule),
		};
	});
	const existing = report.results.find((r) => r.auditor === auditor.id);
	const byFingerprint = new Map(
		(existing?.findings ?? []).map((f) => [f.fingerprint, f]),
	);
	for (const f of added) byFingerprint.set(f.fingerprint, f);
	const findings = [...byFingerprint.values()].sort(
		(a, b) => severityRank(a.severity) - severityRank(b.severity),
	);
	const categories = [
		...new Set([
			...(existing?.categories ?? auditor.categories),
			...findings.map((f) => f.category),
		]),
	];
	const result: AuditorResult = {
		auditor: auditor.id,
		title: existing?.title ?? auditor.title,
		engine: "agentic",
		categories,
		status: findings.some((f) => f.severity !== "info") ? "failed" : "passed",
		message: "Findings submitted by the host agent via MCP",
		durationMs: existing?.durationMs ?? 0,
		findings,
	};
	const results = existing
		? report.results.map((r) => (r.auditor === auditor.id ? result : r))
		: [...report.results, result];
	return {
		report: {
			...report,
			finishedAt: new Date().toISOString(),
			summary: summarize(results),
			results,
		},
		added,
	};
};
