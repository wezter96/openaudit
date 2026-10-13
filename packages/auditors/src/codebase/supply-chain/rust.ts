import {
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, parseJson, str } from "../../tool";
import { osvSeverity } from "../dependencies";
import { isRecord } from "../util";
import {
	advisoryTags,
	baseOf,
	findFiles,
	fixedFromPatched,
	run,
	vulnFinding,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                 cargo-audit                                */
/* -------------------------------------------------------------------------- */

const CARGO_WARNINGS: Record<
	string,
	{ rule: string; severity: Severity; label: string }
> = {
	unmaintained: {
		rule: "unmaintained-dependency",
		severity: "low",
		label: "is unmaintained",
	},
	unsound: {
		rule: "unsound-dependency",
		severity: "medium",
		label: "has a soundness issue",
	},
	yanked: {
		rule: "yanked-dependency",
		severity: "low",
		label: "was yanked from crates.io",
	},
	notice: {
		rule: "advisory-notice",
		severity: "low",
		label: "has an advisory notice",
	},
};

/** Parses `cargo-audit audit --json`. */
export const parseCargoAuditReport = (
	json: unknown,
	_root: string,
	file = "Cargo.lock",
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const vulns = isRecord(json.vulnerabilities) ? json.vulnerabilities : {};
	for (const item of arr(vulns.list)) {
		if (!isRecord(item)) continue;
		const advisory = isRecord(item.advisory) ? item.advisory : {};
		const pkg = isRecord(item.package) ? item.package : {};
		const versions = isRecord(item.versions) ? item.versions : {};
		const id = str(advisory.id) ?? "unknown";
		const cvss = str(advisory.cvss);
		const severity = cvss
			? osvSeverity({ id, severity: [{ type: "CVSS_V3", score: cvss }] })
			: "medium";
		const url = str(advisory.url);
		findings.push(
			vulnFinding({
				auditor: "code.cargo-audit",
				name: str(pkg.name) ?? "unknown",
				version: str(pkg.version),
				ecosystem: "crates.io",
				id,
				aliases: arr(advisory.aliases).filter(
					(a): a is string => typeof a === "string",
				),
				summary: str(advisory.title) ?? id,
				severity,
				fixed: arr(versions.patched)
					.filter((p): p is string => typeof p === "string")
					.map((p) => fixedFromPatched(p) ?? p),
				file,
				references: [
					`https://rustsec.org/advisories/${id}.html`,
					...(url ? [url] : []),
				],
			}),
		);
	}
	const warnings = isRecord(json.warnings) ? json.warnings : {};
	for (const [kind, list] of Object.entries(warnings)) {
		const meta = CARGO_WARNINGS[kind] ?? CARGO_WARNINGS.notice;
		if (!meta) continue;
		for (const w of arr(list)) {
			if (!isRecord(w)) continue;
			const pkg = isRecord(w.package) ? w.package : {};
			const advisory = isRecord(w.advisory) ? w.advisory : {};
			const name = str(pkg.name) ?? "unknown";
			const version = str(pkg.version);
			const id = str(advisory.id);
			const at = version ? `${name}@${version}` : name;
			findings.push({
				ruleId: `code.cargo-audit/${meta.rule}`,
				title: `${at}: ${str(advisory.title) ?? meta.label}`,
				severity: meta.severity,
				category: "supply-chain",
				message: `${at} ${meta.label}${id ? ` (${id})` : ""}.`,
				location: { file },
				evidence: id ? `${at} ${id}` : at,
				remediation: `Replace or upgrade ${name}; see the advisory for maintained alternatives.`,
				references: id ? [`https://rustsec.org/advisories/${id}.html`] : [],
				confidence: "high",
				tags: [
					"owasp-a06",
					...advisoryTags([
						id ?? "",
						...arr(advisory.aliases).filter(
							(a): a is string => typeof a === "string",
						),
					]),
				],
			});
		}
	}
	return findings;
};

export const cargoAudit = defineAuditor({
	id: "code.cargo-audit",
	title: "cargo-audit (Rust advisories)",
	description:
		"Checks Cargo.lock against the RustSec advisory database with cargo-audit. Reads the lockfile only; nothing is compiled or fetched from the project.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "cargo-audit",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const locks = yield* findFiles(ctx, (p) => baseOf(p) === "Cargo.lock");
			if (!locks.length) return yield* skip("No Cargo.lock found");
			const bin = yield* requireTool(
				ctx,
				"cargo-audit",
				"Install: cargo install cargo-audit --locked (or brew install cargo-audit).",
			);
			const findings: FindingInput[] = [];
			for (const lock of locks) {
				// Exit 1 = vulnerabilities found.
				const res = yield* run(
					ctx,
					[bin, "audit", "--json", "-f", ws.absolute(lock)],
					{ cwd: ws.root, okCodes: [0, 1] },
				);
				findings.push(
					...parseCargoAuditReport(
						yield* parseJson(res.stdout, "cargo-audit"),
						ws.root,
						lock,
					),
				);
			}
			return findings;
		}),
});
