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
		"Output format(s): terminal, json, sarif, markdown, html, csv. Repeat or comma-separate; several need --out",
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
	diff: opt(
		Flag.String("diff"),
		"Only report findings in files changed since this git ref (e.g. origin/main), for pull requests",
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
	allowErrors: bool(
		"allow-errors",
		"With --fail-on, do not fail when an auditor errors or times out",
	),
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
	diff: Option.getOrUndefined(p.diff),
	concurrency: Option.getOrUndefined(p.concurrency),
	json: p.json,
	quiet: p.quiet,
	verbose: p.verbose,
	config: Option.getOrUndefined(p.config),
	noConfig: p.noConfig,
	allowErrors: p.allowErrors,
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
		command: "claude mcp add openaudit -- bunx @openaudit/cli mcp",
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

	const mcp = Command.make(
		"mcp",
		{
			http: bool(
				"http",
				"Serve MCP over Streamable HTTP instead of stdio (loopback by default)",
			),
			host: opt(Flag.String("host"), "HTTP bind address (default 127.0.0.1)"),
			port: opt(Flag.Int("port"), "HTTP port (default 7337)"),
			token: opt(
				Flag.String("token"),
				"HTTP bearer token (or OPENAUDIT_MCP_TOKEN); generated on loopback if omitted, required off loopback",
			),
			root: list(
				"root",
				"HTTP: directory that local targets must resolve inside (repeatable)",
			),
			allowOrigin: list(
				"allow-origin",
				"HTTP: browser Origin allowed to connect (repeatable)",
			),
			allowHost: list(
				"allow-host",
				"HTTP: extra Host header value accepted (repeatable)",
			),
			persistReports: bool(
				"persist-reports",
				"HTTP: save reports under <root>/.openaudit/reports (off by default over HTTP)",
			),
			allowCloud: bool(
				"allow-cloud",
				"HTTP: accept cloud:<provider> targets (uses the server's credentials)",
			),
			allowImages: bool(
				"allow-images",
				"HTTP: accept image:<ref> targets on non-loopback binds (registry host is still checked)",
			),
			allowAgentic: bool(
				"allow-agentic",
				"HTTP: let clients run agentic auditors (spends the server's ANTHROPIC_API_KEY)",
			),
			allowPrivateTargets: bool(
				"allow-private-targets",
				"HTTP: allow URL targets on private/loopback/metadata addresses (non-loopback binds only block them by default)",
			),
		},
		(p) =>
			Effect.promise(async () => {
				const mcpModule = await import("@openaudit/mcp");
				const httpOnly =
					Option.isSome(p.host) ||
					Option.isSome(p.port) ||
					Option.isSome(p.token);
				if (!p.http) {
					if (
						httpOnly ||
						p.root.length ||
						p.allowOrigin.length ||
						p.allowHost.length ||
						p.allowCloud ||
						p.persistReports ||
						p.allowImages ||
						p.allowAgentic ||
						p.allowPrivateTargets
					) {
						process.stderr.write(
							"These options need --http (stdio has no network settings).\n",
						);
						code = EXIT.usage;
						return;
					}
					await mcpModule.startStdioServer();
					code = -1; // keep the process alive while the client is connected
					return;
				}
				const port = Option.getOrUndefined(p.port);
				if (port !== undefined && !(port >= 0 && port <= 65535)) {
					process.stderr.write("--port must be between 0 and 65535.\n");
					code = EXIT.usage;
					return;
				}
				try {
					const handle = await mcpModule.startHttpServer({
						host: Option.getOrUndefined(p.host),
						port,
						token:
							Option.getOrUndefined(p.token) ?? process.env.OPENAUDIT_MCP_TOKEN,
						roots: p.root,
						allowOrigins: p.allowOrigin,
						allowHosts: p.allowHost,
						allowCloud: p.allowCloud,
						persistReports: p.persistReports,
						allowImages: p.allowImages,
						allowAgentic: p.allowAgentic,
						allowPrivateTargets: p.allowPrivateTargets,
					});
					// Never print the token.
					process.stderr.write(
						`openaudit MCP listening on ${handle.url}\n${
							handle.roots.length
								? `Local targets allowed in: ${handle.roots.join(", ")}`
								: "Local paths disabled (no --root); URL and image: targets only."
						}\n`,
					);
					if (handle.generatedToken) {
						// Shown once; the file lets clients read it later.
						const token = handle.generatedToken;
						let where: string;
						try {
							where = `Saved to ${await mcpModule.writeTokenFile(token)} (readable by you only).`;
						} catch (error) {
							where = `Could not save it to a file (${error instanceof Error ? error.message : String(error)}).`;
						}
						process.stderr.write(
							`No token was given, so one was generated: ${token}\n${where}\nClaude Code: claude mcp add --transport http openaudit ${handle.url} --header "Authorization: Bearer ${token}"\nOther clients: send the header Authorization: Bearer <token>.\n`,
						);
					}
					const shutdown = () => {
						void handle.close().finally(() => process.exit(0));
					};
					process.once("SIGINT", shutdown);
					process.once("SIGTERM", shutdown);
					code = -1;
				} catch (error) {
					process.stderr.write(
						`${error instanceof Error ? error.message : String(error)}\n`,
					);
					code = EXIT.usage;
				}
			}),
	).pipe(
		Command.withDescription(
			"Start the MCP server: stdio by default (Claude Code, Cursor, Codex, ...), or --http for remote agents",
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
