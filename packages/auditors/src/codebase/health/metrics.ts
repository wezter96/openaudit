/** A function parameter, as far as its declared type tells. */
export interface Param {
	readonly primitive: boolean;
	readonly string: boolean;
}

export interface Conditional {
	readonly line: number;
	readonly endLine: number;
	/** Logical operators (`&&`, `||`) in the condition. */
	readonly branches: number;
}

export interface Bump {
	readonly lines: number;
}

export interface FunctionMetrics {
	readonly name: string;
	readonly startLine: number;
	readonly endLine: number;
	/** Code lines, without blank lines, comments or inner functions. */
	readonly loc: number;
	readonly cc: number;
	readonly params: ReadonlyArray<Param>;
	readonly isConstructor: boolean;
	/** An arrow function whose body is a single expression. */
	readonly expressionBody: boolean;
	/** Deepest nesting of conditionals and loops. */
	readonly nesting: number;
	readonly bumps: ReadonlyArray<Bump>;
	readonly conditionals: ReadonlyArray<Conditional>;
	/** Tokens of the function's own code, for spotting copies. */
	readonly tokens: ReadonlyArray<string>;
	/** Smells switched off by a directive comment (`*` for all). */
	readonly disabled: ReadonlyArray<string>;
}

export interface FileMetrics {
	readonly lines: number;
	readonly codeLines: number;
	readonly functions: ReadonlyArray<FunctionMetrics>;
}
