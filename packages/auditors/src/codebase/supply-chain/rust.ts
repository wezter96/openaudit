import {
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, parseJson, str, withTempDir } from "../../tool";
import { osvSeverity } from "../dependencies";
import { isRecord } from "../util";
import {
	type AdvisoryId,
	type FilePath,
	type Json,
	type RootPath,
	strings,
} from "./report";
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

type CargoWarning = (typeof CARGO_WARNINGS)[string];

const recordOf = (value: unknown): Json => (isRecord(value) ? value : {});

const rustsecUrl = (id: AdvisoryId) =>
	`https://rustsec.org/advisories/${id}.html`;

const cargoSeverity = (id: AdvisoryId, cvss: string | undefined): Severity =>
	cvss
		? osvSeverity({ id, severity: [{ type: "CVSS_V3", score: cvss }] })
		: "medium";

const cargoVulnFinding = (item: Json, file: FilePath): FindingInput => {
	const advisory = recordOf(item.advisory);
	const pkg = recordOf(item.package);
	const versions = recordOf(item.versions);
	const id = str(advisory.id) ?? "unknown";
	const url = str(advisory.url);
	return vulnFinding({
		auditor: "code.cargo-audit",
		name: str(pkg.name) ?? "unknown",
		version: str(pkg.version),
		ecosystem: "crates.io",
		id,
		aliases: strings(advisory.aliases),
		summary: str(advisory.title) ?? id,
		severity: cargoSeverity(id, str(advisory.cvss)),
		fixed: strings(versions.patched).map((p) => fixedFromPatched(p) ?? p),
		file,
		references: [rustsecUrl(id), ...(url ? [url] : [])],
	});
};

const cargoWarningFinding = (
	meta: CargoWarning,
	w: Json,
	file: FilePath,
): FindingInput => {
	const pkg = recordOf(w.package);
	const advisory = recordOf(w.advisory);
	const name = str(pkg.name) ?? "unknown";
	const version = str(pkg.version);
	const id = str(advisory.id);
	const at = version ? `${name}@${version}` : name;
	return {
		ruleId: `code.cargo-audit/${meta.rule}`,
		title: `${at}: ${str(advisory.title) ?? meta.label}`,
		severity: meta.severity,
		category: "supply-chain",
		message: `${at} ${meta.label}${id ? ` (${id})` : ""}.`,
		location: { file },
		evidence: id ? `${at} ${id}` : at,
		remediation: `Replace or upgrade ${name}; see the advisory for maintained alternatives.`,
		references: id ? [rustsecUrl(id)] : [],
		confidence: "high",
		tags: [
			"owasp-a06",
			...advisoryTags([id ?? "", ...strings(advisory.aliases)]),
		],
	};
};

/** Warnings (unmaintained, unsound, yanked, ...) of one kind. */
const cargoWarningFindings = (
	[kind, list]: [string, unknown],
	file: FilePath,
): FindingInput[] => {
	const meta = CARGO_WARNINGS[kind] ?? CARGO_WARNINGS.notice;
	if (!meta) return [];
	return arr(list)
		.filter(isRecord)
		.map((w) => cargoWarningFinding(meta, w, file));
};

/** Parses `cargo-audit audit --json`. */
export const parseCargoAuditReport = (
	json: unknown,
	_root: RootPath,
	file: FilePath = "Cargo.lock",
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const vulns = recordOf(json.vulnerabilities);
	return [
		...arr(vulns.list)
			.filter(isRecord)
			.map((item) => cargoVulnFinding(item, file)),
		...Object.entries(recordOf(json.warnings)).flatMap((entry) =>
			cargoWarningFindings(entry, file),
		),
	];
};

export const cargoAudit = defineAuditor({
	id: "code.cargo-audit",
	title: "cargo-audit (Rust advisories)",
	description:
		"Checks Cargo.lock against the RustSec advisory database with cargo-audit. Reads the lockfile only, never the project's .cargo/audit.toml; nothing is compiled or fetched from the project.",
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
				// Exit 1 = vulnerabilities found. cargo-audit reads .cargo/audit.toml
				// from its cwd, where a project could ignore advisories or point the
				// advisory database at its own URL or path, so it runs from a scratch dir.
				const res = yield* withTempDir("openaudit-cargo-audit-", (dir) =>
					run(ctx, [bin, "audit", "--json", "-f", ws.absolute(lock)], {
						cwd: dir,
						okCodes: [0, 1],
					}),
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
