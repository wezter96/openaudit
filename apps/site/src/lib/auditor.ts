/**
 * What an auditor's page says about it, shared by the HTML page and its
 * Markdown version.
 */
import { type Auditor, auditors, playbooks, TARGET_LABEL } from "./site";

const TARGET_ARG: Record<string, string> = {
	codebase: ".",
	url: "https://example.com",
	webapp: "https://example.com --browser",
	container: "image:nginx:1.27",
	iac: ".",
	mobile: "./app-release.apk",
	cloud: "cloud:aws",
};

const howItRuns = (a: Auditor) => {
	if (a.engine === "builtin")
		return "Built into openaudit; nothing to install.";
	if (a.engine === "external")
		return `Wraps ${a.tool ?? "an external tool"}. When it isn't installed, the auditor is skipped with an install hint and the rest of the audit runs.`;
	return "Runs a playbook with the Claude Agent SDK. Needs ANTHROPIC_API_KEY or a Claude Code login; host agents can run the same playbook over MCP without a key.";
};

/** Another auditor in the same main area that audits a target `a` audits. */
const isRelated = (a: Auditor, o: Auditor) =>
	o.id !== a.id &&
	o.categories[0] === a.categories[0] &&
	o.targets.some((t) => a.targets.includes(t));

export const auditorView = (a: Auditor) => {
	// Two auditors can share a title (a static and a live check); the target tells them apart.
	const shared = auditors.some((o) => o.id !== a.id && o.title === a.title);
	const first = a.targets[0] ?? "codebase";
	return {
		pageTitle: shared ? `${a.title}, ${TARGET_LABEL[first] ?? a.id}` : a.title,
		playbook: playbooks.find((p) => p.id === a.id),
		command: `bunx @openaudit/cli ${TARGET_ARG[first] ?? "."} --only ${a.id}${a.engine === "agentic" && !a.optIn ? " --agentic" : ""}`,
		how: howItRuns(a),
		related: auditors.filter((o) => isRelated(a, o)).slice(0, 8),
		runs: a.optIn
			? "Opt-in: only when selected with --only"
			: "By default, when the target applies",
		network: a.network
			? "Contacts services beyond the target"
			: "Only the target itself",
	};
};
