import { dirname, isAbsolute, join, resolve } from "node:path";
import { Category, jsonSchemaOf, Severity } from "@openaudit/core";
import { Data, Schema } from "effect";

export const CONFIG_FILE = "openaudit.config.json";

const Strings = Schema.Array(Schema.String);

export const FailOn = Schema.Union([Severity, Schema.Literal("none")]);
export type FailOn = typeof FailOn.Type;

/** `openaudit.config.json`. Every key is optional; CLI flags override it. */
export const Config = Schema.Struct({
	$schema: Schema.optional(Schema.String),
	/** Auditor ids or patterns to run exclusively (`web.*`, `code.secrets`). */
	only: Schema.optional(Strings),
	exclude: Schema.optional(Strings),
	categories: Schema.optional(Schema.Array(Category)),
	/** Exit with code 1 when a finding is at least this severe. */
	failOn: Schema.optional(FailOn),
	ignore: Schema.optional(
		Schema.Struct({
			/** Rule ids or patterns, e.g. `code.hygiene/ci-missing`, `web.seo/*`. */
			rules: Schema.optional(Strings),
			/** File globs, e.g. `test/fixtures/**`. */
			paths: Schema.optional(Strings),
			fingerprints: Schema.optional(Strings),
		}),
	),
	options: Schema.optional(
		Schema.Struct({
			offline: Schema.optional(Schema.Boolean),
			browser: Schema.optional(Schema.Boolean),
			maxPages: Schema.optional(Schema.Number),
			agentic: Schema.optional(Schema.Boolean),
			model: Schema.optional(Schema.String),
			concurrency: Schema.optional(Schema.Number),
			/** Per-auditor settings keyed by auditor id. */
			settings: Schema.optional(
				Schema.Record(
					Schema.String,
					Schema.Record(Schema.String, Schema.Unknown),
				),
			),
		}),
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

/** Parses and validates config JSON text. */
export const parseConfig = (text: string, path: string): Config => {
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch (cause) {
		throw new ConfigError({
			message: `${path} is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
		});
	}
	try {
		return Schema.decodeUnknownSync(Config)(json);
	} catch (cause) {
		throw new ConfigError({
			message: `${path} is invalid: ${cause instanceof Error ? cause.message : String(cause)}`,
		});
	}
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

/**
 * Loads `--config <path>` (must exist) or `openaudit.config.json` next to the
 * target (optional). Returns the config and the path it came from.
 */
export const loadConfig = async (options: {
	readonly explicit?: string;
	readonly target: string;
	readonly cwd: string;
}): Promise<{ config: Config; path?: string }> => {
	if (options.explicit) {
		const path = resolve(options.cwd, options.explicit);
		const file = Bun.file(path);
		if (!(await file.exists()))
			throw new ConfigError({ message: `Config file not found: ${path}` });
		return { config: parseConfig(await file.text(), path), path };
	}
	const path = join(
		await configDirFor(options.target, options.cwd),
		CONFIG_FILE,
	);
	const file = Bun.file(path);
	if (!(await file.exists())) return { config: {} };
	return { config: parseConfig(await file.text(), path), path };
};

/** JSON Schema of the config file, for editors and agents. */
export const configJsonSchema = (): Record<string, unknown> =>
	jsonSchemaOf(Config, { title: "openaudit config" });
