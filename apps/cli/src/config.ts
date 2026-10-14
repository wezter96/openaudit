import { dirname, isAbsolute, join, resolve } from "node:path";
import {
	Category,
	jsonSchemaOf,
	Severity,
	type SuppressionEntry,
	stripJsonc,
} from "@openaudit/core";
import { Data, Schema } from "effect";

export const CONFIG_FILE = "openaudit.config.json";
/** Names a config may have, in lookup order. Both may hold comments. */
export const CONFIG_FILES = [CONFIG_FILE, "openaudit.config.jsonc"] as const;

/**
 * Where the config's JSON Schema is published (built by apps/site). It names
 * the project's own domain rather than the current host, because configs
 * that point at it are committed to other repositories and kept for years.
 */
export const CONFIG_SCHEMA_URL = "https://openaudit.se/schema/config.json";

const describe = <S extends Schema.Top>(schema: S, description: string) =>
	schema.annotate({ description }) as S;

const Strings = (description: string) =>
	describe(Schema.Array(Schema.String), description);

export const FailOn = Schema.Union([Severity, Schema.Literal("none")]);
export type FailOn = typeof FailOn.Type;

const Reason = describe(
	Schema.String,
	"Why this is suppressed. Reports show it next to the findings it removed.",
);
const Until = describe(
	Schema.String.check(
		Schema.isPattern(/^\d{4}-\d{2}-\d{2}$/u, {
			message: "Expected a date as YYYY-MM-DD",
		}),
	),
	"Last day the suppression applies (YYYY-MM-DD, UTC). After it the findings are reported again and openaudit warns.",
);

/** `"pattern"` or `{ "<key>": "pattern", "reason": "…", "until": "…" }`. */
const Entries = <K extends SuppressionEntry["kind"]>(
	key: K,
	value: string,
	description: string,
) =>
	describe(
		Schema.Array(
			Schema.Union([
				describe(Schema.String, value),
				Schema.Struct({
					[key]: describe(Schema.String, value),
					reason: Schema.optional(Reason),
					until: Schema.optional(Until),
				} as { [P in K]: Schema.String } & {
					reason: Schema.optional<typeof Reason>;
					until: Schema.optional<typeof Until>;
				}),
			]),
		),
		`${description} Each entry is a string, or an object with "${key}", "reason" and "until".`,
	);

/** `openaudit.config.json`. Every key is optional; CLI flags override it. */
export const Config = Schema.Struct({
	$schema: Schema.optional(
		describe(Schema.String, "JSON Schema for editor completion and checks."),
	),
	only: Schema.optional(
		Strings(
			"Auditor ids or patterns to run exclusively (`code.secrets`, `web.*`). In a config inside the audited target this only narrows the default set: it never enables opt-in or agentic auditors.",
		),
	),
	exclude: Schema.optional(Strings("Auditor ids or patterns to skip.")),
	categories: Schema.optional(
		describe(Schema.Array(Category), "Run only auditors in these categories."),
	),
	failOn: Schema.optional(
		describe(
			FailOn,
			'Exit with code 1 when a finding is at least this severe. `--fail-on` overrides it. A config inside the audited target cannot set "none".',
		),
	),
	ignore: Schema.optional(
		describe(
			Schema.Struct({
				rules: Schema.optional(
					Entries(
						"rule",
						"Rule id or pattern, e.g. `code.hygiene/ci-missing` or `web.seo/*`.",
						"Suppress findings by rule.",
					),
				),
				paths: Schema.optional(
					Entries(
						"path",
						"File glob relative to the target, e.g. `test/fixtures/**`.",
						"Suppress findings in matching files.",
					),
				),
				fingerprints: Schema.optional(
					Entries(
						"fingerprint",
						"A finding's `fingerprint` from a report.",
						"Suppress single findings.",
					),
				),
			}),
			"Suppressions. Suppressed findings are left out of the report and the score, and every report says how many each source removed.",
		),
	),
	options: Schema.optional(
		describe(
			Schema.Struct({
				/*
				 * Only `maxPages` is honoured from a config found in the target. The
				 * rest sends data, spends money or widens access, so it is read only
				 * from an explicit `--config <path>` (see `untrustedKeys`).
				 */
				offline: Schema.optional(
					describe(
						Schema.Boolean,
						"Skip auditors that need the network (`--offline`).",
					),
				),
				browser: Schema.optional(
					describe(
						Schema.Boolean,
						"Audit URLs in a real browser (`--browser`).",
					),
				),
				// A described Number loses its description in the JSON Schema.
				maxPages: describe(
					Schema.optional(Schema.Number),
					"Pages to crawl per URL (`--max-pages`).",
				),
				agentic: Schema.optional(
					describe(
						Schema.Boolean,
						"Run the agentic auditors (`--agentic`). Costs tokens.",
					),
				),
				ai: Schema.optional(
					describe(Schema.Boolean, "Attach AI insights (`--ai`)."),
				),
				model: Schema.optional(
					describe(Schema.String, "Claude model for `agentic` and `ai`."),
				),
				headers: Schema.optional(
					describe(
						Schema.Record(Schema.String, Schema.String),
						"Extra headers sent to URL targets (`--header`).",
					),
				),
				concurrency: describe(
					Schema.optional(Schema.Number),
					"Auditors run in parallel (`--concurrency`).",
				),
				settings: Schema.optional(
					describe(
						Schema.Record(
							Schema.String,
							Schema.Record(Schema.String, Schema.Unknown),
						),
						'Per-auditor settings keyed by auditor id, e.g. a licence policy under `"code.licenses"`.',
					),
				),
			}),
			'Run options. A config inside the audited target may set only `maxPages` and `settings["code.licenses"]`; the rest needs `--config <path>`.',
		),
	),
});
export type Config = typeof Config.Type;

export const DEFAULT_CONFIG = {
	only: [],
	exclude: [],
	categories: [],
	failOn: "high",
	ignore: { rules: [], paths: [], fingerprints: [] },
	options: { maxPages: 10 },
} satisfies Config;

export class ConfigError extends Data.TaggedError("ConfigError")<{
	readonly message: string;
}> {}

const IGNORE_KEYS = [
	["rules", "rule"],
	["paths", "path"],
	["fingerprints", "fingerprint"],
] as const;

/** Rejects a misspelt `until` or `reason`, which would silently never expire. */
const checkEntries = (json: unknown): string | undefined => {
	const ignore = (json as { ignore?: Record<string, unknown> } | null)?.ignore;
	if (!ignore || typeof ignore !== "object") return undefined;
	for (const [list, key] of IGNORE_KEYS) {
		const entries = ignore[list];
		if (!Array.isArray(entries)) continue;
		for (const [i, entry] of entries.entries()) {
			if (!entry || typeof entry !== "object") continue;
			const allowed = [key, "reason", "until"];
			const extra = Object.keys(entry).find((k) => !allowed.includes(k));
			if (extra)
				return `ignore.${list}[${i}] has an unknown key "${extra}" (use ${allowed.map((k) => `"${k}"`).join(", ")})`;
			const until = (entry as { until?: unknown }).until;
			if (
				typeof until === "string" &&
				/^\d{4}-\d{2}-\d{2}$/.test(until) &&
				new Date(`${until}T00:00:00Z`).toISOString().slice(0, 10) !== until
			)
				return `ignore.${list}[${i}].until is not a real date: ${until}`;
		}
	}
	return undefined;
};

/** Parses and validates config text. Comments and trailing commas are allowed. */
export const parseConfig = (text: string, path: string): Config => {
	let json: unknown;
	try {
		json = JSON.parse(stripJsonc(text));
	} catch (cause) {
		throw new ConfigError({
			message: `${path} is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
		});
	}
	const invalid = (detail: string) =>
		new ConfigError({ message: `${path} is invalid: ${detail}` });
	let config: Config;
	try {
		config = Schema.decodeUnknownSync(Config)(json);
	} catch (cause) {
		throw invalid(cause instanceof Error ? cause.message : String(cause));
	}
	const entryProblem = checkEntries(json);
	if (entryProblem) throw invalid(entryProblem);
	return config;
};

/** One suppression from `ignore`, normalised from either entry form. */
export type IgnoreEntry = SuppressionEntry;

/** Today's date in UTC as `YYYY-MM-DD`, the form `until` is compared in. */
export const isoDay = (now: Date): string => now.toISOString().slice(0, 10);

/**
 * Normalises `ignore` and splits it into entries that apply on `today`
 * (`YYYY-MM-DD`) and entries past their `until` date. `until` is inclusive.
 */
export const resolveIgnores = (
	ignore: Config["ignore"],
	today: string,
): { active: IgnoreEntry[]; expired: IgnoreEntry[] } => {
	const active: IgnoreEntry[] = [];
	const expired: IgnoreEntry[] = [];
	for (const [list, kind] of IGNORE_KEYS) {
		for (const raw of ignore?.[list] ?? []) {
			const entry: IgnoreEntry =
				typeof raw === "string"
					? { kind, value: raw }
					: {
							kind,
							value: (raw as Record<string, string>)[kind] ?? "",
							...(raw.reason !== undefined ? { reason: raw.reason } : {}),
							...(raw.until !== undefined ? { until: raw.until } : {}),
						};
			(entry.until !== undefined && entry.until < today
				? expired
				: active
			).push(entry);
		}
	}
	return { active, expired };
};

/** Directory whose config applies to a target; URLs and images use the cwd. */
export const configDirFor = async (target: string, cwd: string) => {
	if (/^https?:\/\/|^image:/i.test(target)) return cwd;
	const abs = isAbsolute(target) ? target : resolve(cwd, target);
	const stat = await Bun.file(abs)
		.stat()
		.catch(() => undefined);
	if (!stat) return cwd;
	return stat.isDirectory() ? abs : dirname(abs);
};

export interface LoadedConfig {
	readonly config: Config;
	/** File the config came from, if any. */
	readonly path?: string;
	/** True for `--config <path>`; false for a config found in the target. */
	readonly trusted: boolean;
	/** Keys present in an untrusted config that were ignored. */
	readonly ignored: ReadonlyArray<string>;
}

/**
 * Per-auditor settings a target may set for itself. A licence policy only adds
 * findings: without one, `code.licenses` is skipped.
 */
export const TARGET_SETTINGS: ReadonlyArray<string> = ["code.licenses"];

/**
 * A config inside the audited target is written by whoever controls the
 * target. It may narrow the audit and suppress findings (both disclosed in the
 * output) and add checks of its own (`TARGET_SETTINGS`), but nothing that
 * sends data, costs money, adds credentials or turns off `failOn`. CI on
 * untrusted changes should pass `--fail-on` and `--no-config` explicitly.
 */
export const restrictUntrusted = (
	config: Config,
): { config: Config; ignored: string[] } => {
	const { options, $schema: _, failOn, ...rest } = config;
	const ignored = Object.keys(options ?? {})
		.filter((k) => k !== "maxPages" && k !== "settings")
		.map((k) => `options.${k}`);
	const raw: unknown = options?.settings;
	const entries = raw && typeof raw === "object" ? Object.entries(raw) : [];
	if (raw !== undefined && !entries.length) ignored.push("options.settings");
	for (const [id] of entries)
		if (!TARGET_SETTINGS.includes(id))
			ignored.push(`options.settings[${JSON.stringify(id)}]`);
	const settings = Object.fromEntries(
		entries.filter(([id]) => TARGET_SETTINGS.includes(id)),
	);
	// The target may tighten the CI gate but never switch it off.
	if (failOn === "none") ignored.push("failOn: none");
	const kept = {
		...(options?.maxPages !== undefined ? { maxPages: options.maxPages } : {}),
		...(Object.keys(settings).length ? { settings } : {}),
	};
	return {
		config: {
			...rest,
			...(failOn !== undefined && failOn !== "none" ? { failOn } : {}),
			...(Object.keys(kept).length ? { options: kept } : {}),
		},
		ignored,
	};
};

/**
 * The config file in `dir`, if any. Having both names is an error rather than
 * a silent pick, so nobody edits the file that is not used.
 */
export const findConfig = async (dir: string): Promise<string | undefined> => {
	const found: string[] = [];
	for (const name of CONFIG_FILES) {
		const path = join(dir, name);
		if (await Bun.file(path).exists()) found.push(path);
	}
	if (found.length > 1)
		throw new ConfigError({
			message: `Both ${CONFIG_FILES.join(" and ")} exist in ${dir}. Keep one.`,
		});
	return found[0];
};

/**
 * Loads `--config <path>` (must exist, fully trusted) or, unless `noConfig`,
 * `openaudit.config.json(c)` next to the target (optional, restricted).
 */
export const loadConfig = async (options: {
	readonly explicit?: string;
	readonly noConfig?: boolean;
	readonly target: string;
	readonly cwd: string;
}): Promise<LoadedConfig> => {
	if (options.explicit) {
		const path = resolve(options.cwd, options.explicit);
		const file = Bun.file(path);
		if (!(await file.exists()))
			throw new ConfigError({ message: `Config file not found: ${path}` });
		return {
			config: parseConfig(await file.text(), path),
			path,
			trusted: true,
			ignored: [],
		};
	}
	if (options.noConfig) return { config: {}, trusted: true, ignored: [] };
	const path = await findConfig(
		await configDirFor(options.target, options.cwd),
	);
	if (!path) return { config: {}, trusted: true, ignored: [] };
	const restricted = restrictUntrusted(
		parseConfig(await Bun.file(path).text(), path),
	);
	return { ...restricted, path, trusted: false };
};

/** JSON Schema of the config file, for editors and agents. */
export const configJsonSchema = (): Record<string, unknown> => {
	const schema = jsonSchemaOf(Config, {
		$id: CONFIG_SCHEMA_URL,
		title: "openaudit config",
	});
	// Flag a misspelt "until" in editors too (parseConfig rejects it).
	const ignore = (
		schema.properties as Record<
			string,
			{ properties?: Record<string, { items?: { anyOf?: object[] } }> }
		>
	).ignore;
	for (const list of Object.values(ignore?.properties ?? {}))
		for (const member of list.items?.anyOf ?? [])
			if ("properties" in member)
				Object.assign(member, { additionalProperties: false });
	return schema;
};
