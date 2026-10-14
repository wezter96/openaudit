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

/**
 * A config file that could not be read or parsed. Never silent: the file
 * may still load in a lenient client, so its strings are scanned
 * best-effort and this finding says so. The reason never quotes content.
 */
export const unparsed = (
	file: string,
	line: number,
	what: string,
): FindingInput =>
	finding("config-unparsed", file, line, {
		title: "Agent config could not be fully parsed",
		severity: "low",
		category: "security",
		message: `${file} ${what}, so openaudit could not read its structure and checked its strings best-effort instead. A lenient client may still load it.`,
		remediation:
			"Fix the file so it parses as strict JSON (or TOML), then check that it contains only the servers and settings you expect.",
		references: [MCP_SECURITY],
		confidence: "high",
		tags: [],
	});

/** Findings from a best-effort scan are less certain than parsed ones. */
export const bestEffort = (findings: ReadonlyArray<FindingInput>) =>
	findings.map((f) =>
		f.confidence === "high" ? { ...f, confidence: "medium" as const } : f,
	);
