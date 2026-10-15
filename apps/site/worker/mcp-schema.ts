/** The subset of JSON Schema the MCP tools use; validate() checks exactly this. */
export interface Schema {
	readonly type: "object" | "string" | "integer";
	readonly description?: string;
	readonly properties?: Readonly<Record<string, Schema>>;
	readonly required?: ReadonlyArray<string>;
	readonly additionalProperties?: false;
	readonly minLength?: number;
	readonly maxLength?: number;
	readonly pattern?: string;
	readonly minimum?: number;
	readonly maximum?: number;
}

/** Where in the arguments a value sits, e.g. `arguments.limit`. */
type Path = string;

export const isObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);

/** The first way `value` breaks `schema`, or undefined when it conforms. */
export const validate = (
	schema: Schema,
	value: unknown,
	at: Path = "arguments",
): string | undefined => {
	if (schema.type === "object") return validateObject(schema, value, at);
	if (schema.type === "string") return validateString(schema, value, at);
	return validateInteger(schema, value, at);
};

const validateObject = (
	schema: Schema,
	value: unknown,
	at: Path,
): string | undefined => {
	if (!isObject(value)) return `${at} must be an object`;
	const missing = (schema.required ?? []).find(
		(key) => value[key] === undefined,
	);
	if (missing !== undefined) return `${at}.${missing} is required`;
	for (const entry of Object.entries(value)) {
		const problem = validateProperty(schema, entry, at);
		if (problem) return problem;
	}
	return undefined;
};

const validateProperty = (
	schema: Schema,
	[key, value]: [string, unknown],
	at: Path,
): string | undefined => {
	const props = schema.properties ?? {};
	const prop = props[key];
	if (prop) return validate(prop, value, `${at}.${key}`);
	if (schema.additionalProperties === false)
		return `${at} has an unknown property "${key.slice(0, 40)}"; allowed: ${Object.keys(props).join(", ") || "none"}`;
	return undefined;
};

const validateString = (
	schema: Schema,
	value: unknown,
	at: Path,
): string | undefined => {
	if (typeof value !== "string") return `${at} must be a string`;
	if (schema.minLength !== undefined && value.length < schema.minLength)
		return `${at} must be at least ${schema.minLength} characters`;
	if (schema.maxLength !== undefined && value.length > schema.maxLength)
		return `${at} must be at most ${schema.maxLength} characters`;
	// The patterns are this module's own literals.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	if (schema.pattern && !new RegExp(schema.pattern).test(value))
		return `${at} must match ${schema.pattern}`;
	return undefined;
};

const validateInteger = (
	schema: Schema,
	value: unknown,
	at: Path,
): string | undefined => {
	if (typeof value !== "number" || !Number.isInteger(value))
		return `${at} must be an integer`;
	if (schema.minimum !== undefined && value < schema.minimum)
		return `${at} must be at least ${schema.minimum}`;
	if (schema.maximum !== undefined && value > schema.maximum)
		return `${at} must be at most ${schema.maximum}`;
	return undefined;
};
