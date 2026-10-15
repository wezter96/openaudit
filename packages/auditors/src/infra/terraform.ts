import { defineAuditor, type FindingInput, skip } from "@openaudit/core";
import { Effect } from "effect";

import { readOptional, targetFiles } from "./shared";
import { type HclText, parseBlocks } from "./terraform-hcl";
import { blockFindings } from "./terraform-rules";

const TF_RE = /\.tf$|\.tfstate(\.backup)?$/;
const STATE_RE = /\.tfstate(\.backup)?$/;

export { type HclBlock, parseBlocks } from "./terraform-hcl";

/** Path of a Terraform file within the target. */
type FilePath = string;

/** Audits one Terraform file. `allText` is every .tf file joined (for cross-file lookups). */
export const auditTerraform = (
	file: FilePath,
	text: HclText,
	allText: HclText = text,
): ReadonlyArray<FindingInput> =>
	parseBlocks(text).flatMap((block) =>
		blockFindings({
			block,
			type: block.labels[0] ?? "",
			name: block.labels.join("."),
			text,
			allText,
		}).map(({ line, ...rest }) => ({ ...rest, location: { file, line } })),
	);

const stateCommitted = (file: FilePath): FindingInput => ({
	ruleId: "iac.terraform/state-committed",
	title: "Terraform state file committed",
	severity: "critical",
	category: "security",
	message: `\`${file}\` is a Terraform state file. State stores every resource attribute in plaintext, including generated passwords, keys and connection strings.`,
	remediation:
		"Delete it from the repository (and history), rotate any secrets it contains, add `*.tfstate*` to .gitignore and use an encrypted remote backend.",
	location: { file, line: 1 },
	references: [
		"https://developer.hashicorp.com/terraform/language/state/sensitive-data",
		"https://cwe.mitre.org/data/definitions/312.html",
	],
	tags: ["cwe-312", "secrets"],
	confidence: "high",
});

/** Terraform misconfiguration heuristics (no HCL parser required). */
export const terraform = defineAuditor({
	id: "iac.terraform",
	title: "Terraform configuration",
	description:
		"Flags public S3/GCS/Azure storage, open security groups, unencrypted storage, public databases, wildcard IAM, hardcoded credentials, disabled logging and committed state files.",
	categories: ["security"],
	targets: ["iac"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, TF_RE);
			if (files.length === 0) return yield* skip("No Terraform files found");
			const findings: FindingInput[] = [];
			const sources: Array<[string, string]> = [];
			for (const file of files) {
				if (STATE_RE.test(file)) {
					findings.push(stateCommitted(file));
					continue;
				}
				const text = yield* readOptional(ws, file);
				if (text !== undefined) sources.push([file, text]);
			}
			const allText = sources.map(([, t]) => t).join("\n");
			for (const [file, text] of sources)
				findings.push(...auditTerraform(file, text, allText));
			return findings;
		}),
});
