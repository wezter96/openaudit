import { exeName } from "./mcp-launch";

/* -------------------------------------------------------------------------- */
/*                               Launch commands                              */
/* -------------------------------------------------------------------------- */

/** A config string and where it starts in the file. */
export interface Located {
	readonly value: string;
	readonly offset: number;
}

/** How many `sh -c` scripts deep a command sits. */
type ScriptDepth = number;

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);
const WRAPPERS = new Set(["env", "cmd"]);
const ASSIGNMENT = /^[A-Za-z_]\w*=/;
/** Options and assignments after `env` or `cmd`. */
const WRAPPER_OPTION = /^(?:-|\/[a-z]$|[A-Za-z_]\w*=)/i;

export const split = (loc: Located): Located[] =>
	loc.value
		.trim()
		.split(/\s+/)
		.filter(Boolean)
		.map((value) => ({ value, offset: loc.offset }));

const withoutWrapperOptions = (t: ReadonlyArray<Located>): Located[] => {
	let i = 0;
	while (WRAPPER_OPTION.test(t[i]?.value ?? "")) i++;
	return t.slice(i);
};

/** `sh -c "…"` and friends. */
const isShellScript = (t: ReadonlyArray<Located>) =>
	SHELLS.has(exeName(t[0]?.value ?? "")) && /^-\w*c$/.test(t[1]?.value ?? "");

/**
 * The launcher behind the wrappers MCP configs use: leading `KEY=value`
 * assignments, `env`, `cmd /c` and `sh -c "…"`.
 */
export const unwrap = (
	tokens: ReadonlyArray<Located>,
	depth: ScriptDepth = 0,
): Located[] => {
	let t = [...tokens];
	for (let guard = 0; guard < 16 && t.length > 0; guard++) {
		const first = t[0]?.value ?? "";
		if (ASSIGNMENT.test(first)) t = t.slice(1);
		else if (WRAPPERS.has(exeName(first)))
			t = withoutWrapperOptions(t.slice(1));
		else return isShellScript(t) ? shellScript(t, depth) : t;
	}
	return t;
};

/** The command an `sh -c` script runs, up to two scripts deep. */
const shellScript = (
	t: ReadonlyArray<Located>,
	depth: ScriptDepth,
): Located[] => {
	const script = t[2];
	return script && depth < 2 ? unwrap(split(script), depth + 1) : [];
};
