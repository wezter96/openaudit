import type { FindingInput } from "@openaudit/core";

export const ID = "code.agent-config";

export const MCP_SECURITY =
	"https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices";
export const CLAUDE_PERMISSIONS = "https://code.claude.com/docs/en/permissions";
export const GEMINI_CONFIG =
	"https://geminicli.com/docs/reference/configuration";
export const CODEX_CONFIG_DOCS =
	"https://developers.openai.com/codex/config-reference";

export const PROMPT_INJECTION_TAGS = ["cwe-1427", "owasp-llm01"];

/** Fills in the fields every finding of this auditor shares. */
export const finding = (
	rule: string,
	file: string,
	line: number,
	f: Omit<FindingInput, "ruleId" | "location">,
): FindingInput => ({
	ruleId: `${ID}/${rule}`,
	location: { file, line },
	...f,
});

/** Offset of `value` as written in the file, searched from `from`. */
export const locate = (text: string, value: string, from: number): number => {
	for (const needle of [JSON.stringify(value), `'${value}'`, value]) {
		const i = text.indexOf(needle, from);
		if (i !== -1) return i;
	}
	return from;
};
