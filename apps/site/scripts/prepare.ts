/**
 * Collects everything the site is built from, so no page hand-copies a fact
 * that lives elsewhere in the repository:
 *
 * - src/generated/*.json: the auditor registry, playbooks, CLI help, config
 *   schema and GitHub Action inputs, read from the real sources.
 * - public/report/: openaudit's audit of this repository, as written by the
 *   CLI (unmodified). Reuses an existing report, e.g. one CI just wrote, or
 *   runs the audit when there is none. `--fresh` always re-runs it.
 * - public/architecture/: docs/architecture.html, copied as-is.
 *
 * `--data-only` writes src/generated and nothing else (for type checks).
 */
import { copyFile, mkdir, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import * as Agent from "../../../packages/agent/src/index";
import type { Finding } from "../../../packages/core/src/model";
import { gradeFor, scoreFor } from "../../../packages/core/src/scoring";
import { allAuditors } from "../../cli/src/audit";
import { DEFAULT_CONFIG, restrictUntrusted } from "../../cli/src/config";

const site = join(import.meta.dir, "..");
const repo = join(site, "..", "..");
const bin = join(repo, "apps", "cli", "src", "bin.ts");
const generated = join(site, "src", "generated");
const reportDir = join(site, "public", "report");
const args = new Set(process.argv.slice(2));

const writeJson = (name: string, value: unknown) =>
	Bun.write(join(generated, name), `${JSON.stringify(value, null, "\t")}\n`);

const cli = async (...argv: string[]): Promise<string> => {
	const proc = Bun.spawn(["bun", bin, ...argv], {
		cwd: repo,
		stdout: "pipe",
		stderr: "pipe",
		env: { ...process.env, NO_COLOR: "1" },
	});
	const [out, code] = await Promise.all([
		new Response(proc.stdout).text(),
		proc.exited,
	]);
	if (code !== 0) throw new Error(`openaudit ${argv.join(" ")} exited ${code}`);
	return out;
};

await mkdir(generated, { recursive: true });

/* ------------------------------ registry ---------------------------------- */

const auditors = allAuditors().map((a) => ({
	id: a.id,
	title: a.title,
	description: a.description,
	engine: a.engine,
	tool: a.tool ?? null,
	categories: [...a.categories],
	targets: [...a.targets],
	network: a.network === true,
	// Agentic auditors only run with --agentic, so they are opt-in too.
	optIn: a.engine === "agentic" || a.defaultEnabled === false,
}));
const playbooks = Agent.playbooks.map((p) => ({
	id: p.id,
	title: p.title,
	summary: p.summary,
	categories: [...p.categories],
	targets: [...p.targets],
	needs: [...p.needs],
}));
await writeJson("registry.json", { auditors, playbooks });

/* ------------------------------- CLI help --------------------------------- */

const subcommands = ["audit", "list", "doctor", "init", "mcp", "schema"];
const help: Record<string, string> = { openaudit: await cli("--help") };
for (const s of subcommands) help[s] = await cli(s, "--help");
await writeJson("cli-help.json", help);

/* ----------------------------- configuration ------------------------------ */

const schema = JSON.parse(await cli("schema", "config"));
const configSource = await Bun.file(
	join(repo, "apps", "cli", "src", "config.ts"),
).text();
/** `/** text *\/` comments directly above `key:` in the config schema. */
const docComments: Record<string, string> = {};
for (const m of configSource.matchAll(
	/\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*\n\s*(\w+):/g,
)) {
	const [, text = "", key = ""] = m;
	docComments[key] = text.replace(/\s*\n\s*\*\s?/g, " ").trim();
}
// Which keys survive when the config is found inside the audited target.
const everything = {
	only: ["x"],
	exclude: ["x"],
	categories: ["security"],
	failOn: "high",
	ignore: { rules: ["x"], paths: ["x"], fingerprints: ["x"] },
	options: Object.fromEntries(
		Object.keys(schema.properties?.options?.properties ?? {}).map((k) => [
			k,
			true,
		]),
	),
} as const;
const { ignored } = restrictUntrusted(
	everything as unknown as Parameters<typeof restrictUntrusted>[0],
);
await writeJson("config.json", {
	schema,
	defaults: DEFAULT_CONFIG,
	comments: docComments,
	trustedOnly: ignored,
});

/* ---------------------------- GitHub Action ------------------------------- */

const action = parseYaml(await Bun.file(join(repo, "action.yml")).text()) as {
	description: string;
	inputs: Record<string, { description: string; default?: string }>;
	outputs: Record<string, { description: string }>;
};
await writeJson("action.json", {
	description: action.description,
	inputs: Object.entries(action.inputs).map(([name, v]) => ({
		name,
		description: v.description.trim(),
		default: v.default ?? "",
	})),
	outputs: Object.entries(action.outputs).map(([name, v]) => ({
		name,
		description: v.description.trim(),
	})),
});

/* -------------------------------- scoring --------------------------------- */

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const fake = (severity: (typeof SEVERITIES)[number], n = 1) =>
	Array.from({ length: n }, () => ({ severity }) as unknown as Finding);
const bands: { grade: string; min: number }[] = [];
for (let s = 100; s >= 0; s--) {
	const g = gradeFor(s);
	const last = bands.at(-1);
	if (last?.grade === g) last.min = s;
	else bands.push({ grade: g, min: s });
}
// The penalty per severity, read from the source so the docs quote it exactly.
const scoringSource = await Bun.file(
	join(repo, "packages", "core", "src", "scoring.ts"),
).text();
const weightsBlock =
	/const WEIGHTS[^{]*\{([^}]*)\}/.exec(scoringSource)?.[1] ?? "";
const weights = Object.fromEntries(
	[...weightsBlock.matchAll(/(\w+):\s*(\d+)/g)].map((m) => [
		m[1],
		Number(m[2]),
	]),
);
await writeJson("scoring.json", {
	weights,
	examples: [
		...SEVERITIES.map((s) => ({ severity: s, n: 1 })),
		{ severity: "low" as const, n: 10 },
		{ severity: "high" as const, n: 3 },
	].map(({ severity, n }) => {
		const score = scoreFor(fake(severity, n));
		return { severity, n, score, grade: gradeFor(score) };
	}),
	bands,
});

/* ------------------------------ self-audit -------------------------------- */

const reportJson = join(reportDir, "openaudit-report.json");
const summaryOf = async () => {
	const file = Bun.file(reportJson);
	if (!(await file.exists())) return { available: false as const };
	const r = await file.json();
	return {
		available: true as const,
		version: r.tool.version as string,
		finishedAt: r.finishedAt as string,
		durationMs: r.durationMs as number,
		kinds: r.target.kinds as string[],
		score: r.summary.score as number,
		grade: r.summary.grade as string,
		counts: r.summary.counts as Record<string, number>,
		auditors: r.summary.auditors as Record<string, number>,
		categories: (
			r.summary.categories as {
				category: string;
				score: number;
				grade: string;
				counts: Record<string, number>;
			}[]
		).map(({ category, score, grade, counts }) => ({
			category,
			score,
			grade,
			counts,
		})),
	};
};

if (!args.has("--data-only")) {
	const exists = await Bun.file(reportJson).exists();
	if (args.has("--fresh") || !exists) {
		await rm(reportDir, { recursive: true, force: true });
		console.log("site: auditing the repository for /report/ …");
		const proc = Bun.spawn(
			[
				"bun",
				bin,
				".",
				"--format",
				"html,json,sarif,markdown",
				"--out",
				reportDir,
				"--fail-on",
				"none",
				"--quiet",
			],
			{ cwd: repo, stdout: "inherit", stderr: "inherit" },
		);
		if ((await proc.exited) !== 0) throw new Error("self-audit failed");
	}
	// Served at /report/ as well as under its own name, byte for byte.
	await copyFile(
		join(reportDir, "openaudit-report.html"),
		join(reportDir, "index.html"),
	);

	const arch = join(site, "public", "architecture");
	await mkdir(arch, { recursive: true });
	await copyFile(
		join(repo, "docs", "architecture.html"),
		join(arch, "index.html"),
	);

	const shots = join(site, "public", "img");
	await mkdir(shots, { recursive: true });
	for (const f of await readdir(join(repo, "docs", "assets"))) {
		if (f.startsWith("report-")) {
			await copyFile(join(repo, "docs", "assets", f), join(shots, f));
		}
	}
}
await writeJson("self-audit.json", await summaryOf());

console.log(
	`site: ${auditors.length} auditors, ${playbooks.length} playbooks, ${Object.keys(help).length} help pages`,
);
