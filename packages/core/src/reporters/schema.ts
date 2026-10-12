import { Schema } from "effect";

import { Report } from "../model";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

const isObject = (v: Json): v is { [k: string]: Json } =>
	typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Effect emits the schema of its JSON codec, which also accepts `null` for
 * optional keys and `"NaN"`/`"Infinity"` strings for numbers. Reports never
 * contain either, so collapse those unions for a schema agents can read.
 */
const simplify = (node: Json): Json => {
	if (Array.isArray(node)) return node.map(simplify);
	if (!isObject(node)) return node;
	const anyOf = node.anyOf;
	if (Array.isArray(anyOf)) {
		const kept = anyOf.filter(
			(s) =>
				!(
					isObject(s) &&
					(s.type === "null" ||
						(s.type === "string" &&
							Array.isArray(s.enum) &&
							s.enum.every((v) =>
								["NaN", "Infinity", "-Infinity"].includes(String(v)),
							)))
				),
		);
		if (kept.length === 1 && isObject(kept[0] as Json)) {
			const { anyOf: _, ...rest } = node;
			return simplify({ ...rest, ...(kept[0] as { [k: string]: Json }) });
		}
	}
	const out: { [k: string]: Json } = {};
	for (const [k, v] of Object.entries(node)) out[k] = simplify(v);
	return out;
};

/** Standalone, simplified JSON Schema (draft 2020-12) for an Effect schema. */
export const jsonSchemaOf = (
	schema: Parameters<typeof Schema.toJsonSchemaDocument>[0],
	meta: { readonly $id?: string; readonly title?: string } = {},
): Record<string, unknown> => {
	const doc = Schema.toJsonSchemaDocument(schema);
	const defs = doc.definitions as unknown as Json;
	return {
		$schema: "https://json-schema.org/draft/2020-12/schema",
		...meta,
		...(simplify(doc.schema as unknown as Json) as Record<string, unknown>),
		...(isObject(defs) && Object.keys(defs).length
			? { $defs: simplify(defs) }
			: {}),
	};
};

/** JSON Schema of the report that `--json` / `run_audit` emit. */
export const reportJsonSchema = (): Record<string, unknown> =>
	jsonSchemaOf(Report, {
		$id: "https://openaudit.dev/schema/report-v1.json",
		title: "openaudit report",
	});
