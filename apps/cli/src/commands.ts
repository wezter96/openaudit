import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import * as Agent from "@openaudit/agent";
import {
	type Auditor,
	reportJsonSchema,
	type TargetKind,
	VERSION,
} from "@openaudit/core";

import { allAuditors, EXIT, type Io, processIo } from "./audit";
import {
	CONFIG_FILES,
	ConfigError,
	configJsonSchema,
	findConfig,
} from "./config";
import { detectProject, initConfig } from "./init";

const TARGET_KINDS: ReadonlyArray<TargetKind> = [
	"codebase",
	"url",
	"webapp",
	"container",
	"iac",
	"mobile",
	"cloud",
];

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

const pad = (s: string, n: number) =>
	s.length >= n ? s : s + " ".repeat(n - s.length);

/* ---------------------------------- list ---------------------------------- */

export const listCommand = (
	flags: { readonly json: boolean; readonly targetKind?: string },
	io: Io = processIo(),
	auditors: ReadonlyArray<Auditor> = allAuditors(),
): number => {
	const kind = flags.targetKind;
	if (kind && !(TARGET_KINDS as ReadonlyArray<string>).includes(kind)) {
		io.stderr(
			`openaudit: unknown target kind "${kind}". Use: ${TARGET_KINDS.join(", ")}.\n`,
		);
		return EXIT.usage;
	}
	const matches = (targets: ReadonlyArray<TargetKind>) =>
		!kind || targets.includes(kind as TargetKind);
	const list = auditors
		.filter((a) => matches(a.targets))
		.map((a) => ({
			id: a.id,
			title: a.title,
			engine: a.engine,
			categories: [...a.categories],
			targets: [...a.targets],
			...(a.tool ? { tool: a.tool } : {}),
			network: a.network === true,
			defaultEnabled:
				a.engine === "agentic" ? false : a.defaultEnabled !== false,
		}));
	const playbooks = Agent.playbooks
		.filter((p) => matches(p.targets))
		.map((p) => ({
			id: p.id,
			title: p.title,
			summary: p.summary,
			categories: [...p.categories],
			targets: [...p.targets],
			needs: [...p.needs],
		}));

	if (flags.json) {
		io.stdout(json({ auditors: list, playbooks }));
		return EXIT.ok;
	}
	const width = Math.max(10, ...list.map((a) => a.id.length)) + 2;
	const lines = [`Auditors (${list.length})`];
	for (const a of list) {
		const tags = [
			a.engine,
			a.tool ? `needs ${a.tool}` : "",
			a.network ? "network" : "",
			a.defaultEnabled ? "" : "opt-in",
		]
			.filter(Boolean)
			.join(", ");
		lines.push(
			`  ${pad(a.id, width)}${a.title}  [${tags}]`,
			`  ${pad("", width)}targets: ${a.targets.join(", ")} · ${a.categories.join(", ")}`,
		);
	}
	lines.push(
		"",
		`Playbooks (${playbooks.length}) for agent-in-the-loop audits via MCP`,
	);
	for (const p of playbooks)
		lines.push(`  ${pad(p.id, width)}${p.title} (${p.targets.join(", ")})`);
	lines.push(
		"",
		"Select with --only <id|prefix|prefix.*>, --exclude, --category. Agentic auditors need --agentic; opt-in auditors run only when selected with --only.",
	);
	io.stdout(`${lines.join("\n")}\n`);
	return EXIT.ok;
};

/* --------------------------------- doctor --------------------------------- */

/** Alternative binary names some tools install under. */
const TOOL_ALIASES: Record<string, ReadonlyArray<string>> = {
	"testssl.sh": ["testssl"],
};

const whichTool = (name: string): string | undefined => {
	for (const bin of [name, ...(TOOL_ALIASES[name] ?? [])]) {
		const path = Bun.which(bin);
		if (path) return path;
	}
	return undefined;
};

const resolveFrom = (pkg: string, from: string): string | undefined => {
	try {
		return Bun.resolveSync(pkg, from);
	} catch {
		return undefined;
	}
};

const playwrightBrowsers = (): string[] => {
	const dirs = [
		process.env.PLAYWRIGHT_BROWSERS_PATH,
		join(homedir(), "Library", "Caches", "ms-playwright"),
		join(homedir(), ".cache", "ms-playwright"),
		process.env.LOCALAPPDATA
			? join(process.env.LOCALAPPDATA, "ms-playwright")
			: undefined,
	].filter((d): d is string => Boolean(d) && d !== "0");
	for (const dir of dirs) {
		try {
			const found = readdirSync(dir).filter((n) =>
				/^(chromium|chromium_headless_shell)-/.test(n),
			);
			if (found.length) return found.map((n) => join(dir, n));
		} catch {}
	}
	return [];
};

const systemChrome = (): string | undefined =>
	Bun.which("google-chrome") ??
	Bun.which("chromium") ??
	Bun.which("chromium-browser") ??
	["/Applications/Google Chrome.app", "/Applications/Chromium.app"].find((p) =>
		existsSync(p),
	);

export const doctorReport = (
	auditors: ReadonlyArray<Auditor> = allAuditors(),
) => {
	// Every binary an auditor wraps, plus docker (image pulls and saves).
	const names = [
		...new Set([
			...auditors.flatMap((a) => (a.tool ? [a.tool] : [])),
			"docker",
		]),
	];
	const tools = names.map((name) => {
		const path = whichTool(name);
		return {
			name,
			found: Boolean(path),
			...(path ? { path } : {}),
			usedBy: auditors.filter((a) => a.tool === name).map((a) => a.id),
		};
	});
	const auditorsDir = (() => {
		const entry = resolveFrom("@openaudit/auditors", import.meta.dir);
		return entry ? dirname(entry) : import.meta.dir;
	})();
	const playwright = resolveFrom("playwright-core", auditorsDir);
	const axe = resolveFrom("axe-core", auditorsDir);
	const browsers = playwrightBrowsers();
	const chrome = systemChrome();
	const claude = Bun.which("claude") ?? undefined;
	const agentic = {
		anthropicApiKey: Boolean(process.env.ANTHROPIC_API_KEY),
		claudeCodeOAuthToken: Boolean(process.env.CLAUDE_CODE_OAUTH_TOKEN),
		claudeCli: Boolean(claude),
		claudeConfigDir: existsSync(join(homedir(), ".claude")),
	};
	return {
		version: VERSION,
		bun: {
			version: Bun.version,
			ok: Bun.semver.satisfies(Bun.version, ">=1.2.0"),
		},
		platform: `${process.platform}-${process.arch}`,
		tools,
		browser: {
			playwrightCore: Boolean(playwright),
			axeCore: Boolean(axe),
			playwrightBrowsers: browsers,
			systemChrome: chrome,
			ready: Boolean(playwright) && (browsers.length > 0 || Boolean(chrome)),
		},
		agentic: {
			...agentic,
			ready:
				agentic.anthropicApiKey ||
				agentic.claudeCodeOAuthToken ||
				(agentic.claudeCli && agentic.claudeConfigDir),
		},
	};
};

export const doctorCommand = (
	flags: { readonly json: boolean },
	io: Io = processIo(),
): number => {
	const r = doctorReport();
	if (flags.json) {
		io.stdout(json(r));
		return EXIT.ok;
	}
	const ok = (b: boolean) => (b ? "✓" : "✗");
	const lines = [
		`openaudit ${r.version} on ${r.platform}`,
		`${ok(r.bun.ok)} Bun ${r.bun.version}${r.bun.ok ? "" : " (1.2+ recommended)"}`,
		"",
		"External tools (optional; auditors skip with a hint when missing)",
		...r.tools.map(
			(t) =>
				`  ${ok(t.found)} ${pad(t.name, 14)}${t.found ? t.path : "not found"}${t.usedBy.length ? `  → ${t.usedBy.join(", ")}` : ""}`,
		),
		"",
		"Browser (for --browser and accessibility checks)",
		`  ${ok(r.browser.playwrightCore)} playwright-core`,
		`  ${ok(r.browser.axeCore)} axe-core`,
		`  ${ok(r.browser.playwrightBrowsers.length > 0 || Boolean(r.browser.systemChrome))} Chromium ${r.browser.playwrightBrowsers[0] ?? r.browser.systemChrome ?? "not found (bunx playwright install chromium)"}`,
		"",
		"Agentic features (--agentic, --ai)",
		`  ${ok(r.agentic.anthropicApiKey)} ANTHROPIC_API_KEY ${r.agentic.anthropicApiKey ? "set" : "not set"}`,
		`  ${ok(r.agentic.claudeCli)} Claude Code CLI ${r.agentic.claudeCli ? "on PATH" : "not found"}${r.agentic.claudeConfigDir ? " (~/.claude present)" : ""}`,
		r.agentic.ready
			? "  Ready for agentic auditors."
			: "  Not configured. Without a key, run `openaudit mcp` and let your agent execute the playbooks.",
	];
	io.stdout(`${lines.join("\n")}\n`);
	return EXIT.ok;
};

/* ---------------------------------- init ---------------------------------- */

export const initCommand = async (
	flags: {
		readonly force: boolean;
		readonly dir?: string;
		/** Print the config instead of writing it. */
		readonly print?: boolean;
	},
	io: Io = processIo(),
	auditors: ReadonlyArray<Auditor> = allAuditors(),
): Promise<number> => {
	const dir = resolve(io.cwd, flags.dir ?? ".");
	let existing: string | undefined;
	try {
		existing = await findConfig(dir);
	} catch (error) {
		if (!(error instanceof ConfigError)) throw error;
		io.stderr(`openaudit: ${error.message}\n`);
		return EXIT.usage;
	}
	if (existing && !flags.force && !flags.print) {
		io.stderr(
			`openaudit: ${existing} already exists (use --force to overwrite, or --print)\n`,
		);
		return EXIT.usage;
	}
	const text = initConfig(await detectProject(dir), auditors);
	if (flags.print) {
		io.stdout(text);
		return EXIT.ok;
	}
	// With comments the file is JSONC; the .jsonc name keeps editors and
	// linters from flagging them. An existing file keeps its name.
	const path = existing ?? join(dir, CONFIG_FILES[1]);
	await Bun.write(path, text);
	io.stdout(`Created ${path}\n`);
	return EXIT.ok;
};

/* --------------------------------- schema --------------------------------- */

export const schemaCommand = (
	flags: { readonly name: "report" | "config" },
	io: Io = processIo(),
): number => {
	io.stdout(
		json(flags.name === "config" ? configJsonSchema() : reportJsonSchema()),
	);
	return EXIT.ok;
};
