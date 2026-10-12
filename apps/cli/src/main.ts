import { VERSION } from "@openaudit/core";
import {
	Effect,
	FileSystem,
	Layer,
	Option,
	Path,
	Stdio,
	Terminal,
} from "effect";
import {
	Argument,
	CliConfig,
	CliOutput,
	Command,
	Flag,
	GlobalFlag,
} from "effect/cli";
import { ChildProcessSpawner } from "effect/process";

import { type AuditFlags, auditCommand, EXIT } from "./audit";
import {
	doctorCommand,
	initCommand,
	listCommand,
	schemaCommand,
} from "./commands";

/*
 * effect/cli needs a platform environment (normally from @effect/platform-*).
 * Our commands do their own I/O through Bun, so the parser only needs inert
 * implementations; help and errors go through the default Console.
 */
const CliEnvironment = Layer.mergeAll(
	FileSystem.layerNoop({}),
	Path.layer,
	Stdio.layerTest({}),
	Layer.succeed(
		Terminal.Terminal,
		Terminal.make({
			columns: Effect.sync(() => process.stdout.columns ?? 100),
			rows: Effect.sync(() => process.stdout.rows ?? 30),
			readInput: Effect.die("interactive input is not supported"),
			readLine: Effect.die("interactive input is not supported"),
			display: (text) => Effect.sync(() => void process.stdout.write(text)),
		}),
	),
	Layer.succeed(
		ChildProcessSpawner.ChildProcessSpawner,
		ChildProcessSpawner.make(() => Effect.die("not supported")),
	),
	CliConfig.layer({
		builtIns: [GlobalFlag.Help, GlobalFlag.Version, GlobalFlag.Completions],
	}),
	CliOutput.layer(
		CliOutput.defaultFormatter({
			colors: !process.env.NO_COLOR && process.stdout.isTTY === true,
		}),
	),
);

const list = (name: string, description: string) =>
	Flag.String(name).pipe(Flag.withDescription(description), Flag.atLeast(0));
const bool = (name: string, description: string) =>
	Flag.Boolean(name).pipe(
		Flag.withDescription(description),
		Flag.withDefault(false),
	);
const opt = <A>(flag: Flag.Flag<A>, description: string) =>
	flag.pipe(Flag.withDescription(description), Flag.optional);

const auditParams = {
	target: Argument.String("target").pipe(
		Argument.withDescription(
			"Directory, file, http(s) URL or image:<ref> (default: .)",
		),
		Argument.withDefault("."),
	),
	format: list(
		"format",
		"Output format(s): terminal, json, sarif, markdown, html. Repeat or comma-separate; several need --out",
	).pipe(Flag.withAlias("f")),
	out: opt(
		Flag.String("out").pipe(Flag.withAlias("o")),
		"Write openaudit-report.<ext> per format into this directory",
	),
	only: list(
		"only",
		"Only these auditors: id, prefix or prefix.* (repeatable, comma list)",
	),
	exclude: list("exclude", "Skip these auditors (same patterns as --only)"),
	category: list(
		"category",
		"Only auditors in these categories, e.g. security,accessibility",
	),
	failOn: opt(
		Flag.String("fail-on"),
		"Exit 1 if any finding is at least this severe: critical, high, medium, low, info, none",
	),
	offline: bool("offline", "No network access except to the target itself"),
	browser: bool("browser", "Drive a real browser (Playwright) for URL targets"),
	maxPages: opt(Flag.Int("max-pages"), "Max pages to crawl for URL targets"),
	header: list(
		"header",
		'Extra request header for the target origin, "Name: value" (repeatable)',
	).pipe(Flag.withAlias("H")),
	agentic: bool(
		"agentic",
		"Enable agentic (LLM) auditors; needs ANTHROPIC_API_KEY or Claude Code auth",
	),
	ai: bool("ai", "Attach AI insights (prioritised summary) to the report"),
	model: opt(Flag.String("model"), "Model id for agentic auditors and --ai"),
	baseline: opt(
		Flag.String("baseline"),
		"Earlier JSON report; its findings are suppressed (only new findings count)",
	),
	concurrency: opt(
		Flag.Int("concurrency"),
		"Auditors run in parallel (default 4)",
	),
	json: bool(
		"json",
		"Agent mode: JSON report on stdout, nothing else on stdout or stderr progress",
	),
	quiet: bool("quiet", "No progress or notices on stderr").pipe(
		Flag.withAlias("q"),
	),
	verbose: bool("verbose", "Terminal output lists every finding with details"),
	config: opt(
		Flag.String("config"),
		"Trusted config file. Without it, openaudit.config.json in the target is read with restrictions",
	),
	noConfig: bool("no-config", "Ignore openaudit.config.json in the target"),
};

type ParsedAudit = {
	readonly [K in keyof typeof auditParams]: (typeof auditParams)[K] extends
		| Flag.Flag<infer A>
		| Argument.Argument<infer A>
		? A
		: never;
};

const toAuditFlags = (p: ParsedAudit): AuditFlags => ({
	target: p.target,
	format: p.format,
	out: Option.getOrUndefined(p.out),
	only: p.only,
	exclude: p.exclude,
	category: p.category,
	failOn: Option.getOrUndefined(p.failOn),
	offline: p.offline,
	browser: p.browser,
	maxPages: Option.getOrUndefined(p.maxPages),
	header: p.header,
	agentic: p.agentic,
	ai: p.ai,
	model: Option.getOrUndefined(p.model),
	baseline: Option.getOrUndefined(p.baseline),
	concurrency: Option.getOrUndefined(p.concurrency),
	json: p.json,
	quiet: p.quiet,
	verbose: p.verbose,
	config: Option.getOrUndefined(p.config),
	noConfig: p.noConfig,
});

const EXAMPLES = [
	{ command: "openaudit", description: "Audit the current directory" },
	{
		command: "openaudit https://example.com --browser --max-pages 20",
		description: "Audit a live site with a real browser",
	},
	{
		command: "openaudit . --json --fail-on high",
		description: "Agent/CI mode: JSON on stdout, exit 1 on high+ findings",
	},
	{
		command: "openaudit . -f sarif,html -o reports",
		description: "Write reports/openaudit-report.sarif and .html",
	},
	{
		command: "openaudit image:nginx:1.27 --only container",
		description: "Audit a container image",
	},
	{
		command: "openaudit . --baseline main-report.json --fail-on medium",
		description: "Fail only on findings that are new since the baseline",
	},
	{
		command: "claude mcp add openaudit -- bunx openaudit mcp",
		description: "Use openaudit from Claude Code over MCP",
	},
];

/** Parses argv, runs the command and resolves to the process exit code. */
export const main = async (argv: ReadonlyArray<string>): Promise<number> => {
	let code: number = EXIT.ok;
	const exit = (promise: Promise<number> | number) =>
		Effect.promise(async () => {
			code = await promise;
		});

	const audit = Command.make("audit", auditParams, (p) =>
		exit(auditCommand(toAuditFlags(p))),
	).pipe(
		Command.withDescription("Audit a target (the default command)"),
		Command.withExamples(EXAMPLES.slice(0, 5)),
	);

	const listCmd = Command.make(
		"list",
		{
			json: bool("json", "Machine-readable output"),
			targetKind: opt(
				Flag.String("target-kind"),
				"Filter: codebase, url, webapp, container, iac, mobile",
			),
		},
		(p) =>
			exit(
				listCommand({
					json: p.json,
					targetKind: Option.getOrUndefined(p.targetKind),
				}),
			),
	).pipe(Command.withDescription("List auditors and playbooks"));

	const doctor = Command.make(
		"doctor",
		{ json: bool("json", "Machine-readable output") },
		(p) => exit(doctorCommand({ json: p.json })),
	).pipe(
		Command.withDescription(
			"Check Bun, external tools, browser and AI credentials",
		),
	);

	const init = Command.make(
		"init",
		{
			force: bool("force", "Overwrite an existing config"),
			dir: opt(Flag.String("dir"), "Directory to write into (default: .)"),
		},
		(p) =>
			exit(initCommand({ force: p.force, dir: Option.getOrUndefined(p.dir) })),
	).pipe(Command.withDescription("Create openaudit.config.json"));

	const mcp = Command.make("mcp", {}, () =>
		Effect.promise(async () => {
			const { startStdioServer } = await import("@openaudit/mcp");
			await startStdioServer();
			code = -1; // keep the process alive while the client is connected
		}),
	).pipe(
		Command.withDescription(
			"Start the MCP server on stdio (for Claude Code, Cursor, Codex, ...)",
		),
	);

	const schema = Command.make(
		"schema",
		{
			name: Argument.Literals("name", ["report", "config"] as const).pipe(
				Argument.withDescription("Which schema (default: report)"),
				Argument.withDefault("report" as const),
			),
		},
		(p) => exit(schemaCommand({ name: p.name })),
	).pipe(
		Command.withDescription(
			"Print the JSON Schema of the report (or config) so agents can validate output",
		),
	);

	const root = Command.make("openaudit", auditParams, (p) =>
		exit(auditCommand(toAuditFlags(p))),
	).pipe(
		Command.withDescription(
			"Audit codebases, URLs, web apps, containers, IaC and mobile builds for security, accessibility, performance, SEO, privacy and more. Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage or target error.",
		),
		Command.withExamples(EXAMPLES),
		Command.withSubcommands([audit, listCmd, doctor, init, mcp, schema]),
	);

	const result = await Effect.runPromise(
		Effect.result(
			Command.runWith(root, { version: VERSION })(argv).pipe(
				Effect.provide(CliEnvironment),
			),
		),
	);
	if (result._tag === "Failure") return EXIT.usage;
	return code;
};
