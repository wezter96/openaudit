import {
	defineAuditor,
	type FindingInput,
	lineOf,
	redact,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { readOptional, targetFiles } from "./shared";

const TF_RE = /\.tf$|\.tfstate(\.backup)?$/;

/** A top-level or nested HCL block located by brace matching. */
export interface HclBlock {
	/** `resource`, `provider`, `ingress`, ... */
	readonly keyword: string;
	/** Quoted labels, e.g. `["aws_s3_bucket", "logs"]`. */
	readonly labels: ReadonlyArray<string>;
	/** Text between the braces. */
	readonly body: string;
	/** 1-based line of the block header within the file. */
	readonly line: number;
	/** Offset of the body start within the file text. */
	readonly offset: number;
}

/** Index of the brace closing the one at `open`, skipping strings, comments and heredocs. */
const matchBrace = (text: string, open: number): number => {
	let depth = 0;
	for (let i = open; i < text.length; i++) {
		const ch = text[i];
		if (ch === '"') {
			for (i++; i < text.length && text[i] !== '"'; i++) {
				if (text[i] === "\\") i++;
			}
		} else if (ch === "#" || (ch === "/" && text[i + 1] === "/")) {
			const nl = text.indexOf("\n", i);
			i = nl === -1 ? text.length : nl;
		} else if (ch === "/" && text[i + 1] === "*") {
			const end = text.indexOf("*/", i + 2);
			i = end === -1 ? text.length : end + 1;
		} else if (ch === "<" && text[i + 1] === "<") {
			const m = /^<<-?([A-Za-z_]\w*)\s*\n/.exec(text.slice(i));
			if (m) {
				const end = new RegExp(`^\\s*${m[1]}\\s*$`, "m").exec(
					text.slice(i + m[0].length),
				);
				i = end ? i + m[0].length + end.index + end[0].length - 1 : text.length;
			}
		} else if (ch === "{") depth++;
		else if (ch === "}") {
			depth--;
			if (depth === 0) return i;
		}
	}
	return text.length;
};

const BLOCK_SOURCE = /^[ \t]*([A-Za-z_][\w-]*)((?:[ \t]+"[^"\n]*")*)[ \t]*\{/
	.source;

/**
 * Blocks directly inside `text` (no recursion into their bodies).
 * `base` translates offsets back into `fileText`, the enclosing file.
 */
export const parseBlocks = (
	text: string,
	base = 0,
	fileText = text,
): ReadonlyArray<HclBlock> => {
	const blocks: HclBlock[] = [];
	const re = new RegExp(BLOCK_SOURCE, "gm");
	let m: RegExpExecArray | null = re.exec(text);
	while (m) {
		const open = m.index + m[0].length - 1;
		const close = matchBrace(text, open);
		blocks.push({
			keyword: m[1] ?? "",
			labels: [...(m[2] ?? "").matchAll(/"([^"]*)"/g)].map((l) => l[1] ?? ""),
			body: text.slice(open + 1, close),
			line: lineOf(
				fileText,
				base + m.index + (m[0].length - m[0].trimStart().length),
			),
			offset: base + open + 1,
		});
		re.lastIndex = close + 1;
		m = re.exec(text);
	}
	return blocks;
};

/** Nested blocks of `block` named `keyword`. */
const subBlocks = (block: HclBlock, keyword: string, fileText: string) =>
	parseBlocks(block.body, block.offset, fileText).filter(
		(b) => b.keyword === keyword,
	);

/** Text of `body` with nested blocks removed, so attribute lookups stay at this level. */
const ownAttributes = (body: string): string => {
	let out = "";
	let last = 0;
	for (const b of parseBlocks(body)) {
		out += body.slice(last, b.offset) + " ".repeat(b.body.length);
		last = b.offset + b.body.length;
	}
	return out + body.slice(last);
};

interface Attr {
	readonly raw: string;
	/** Unquoted string value when the attribute is a string literal. */
	readonly str: string | undefined;
	readonly line: number;
}

const attr = (
	block: HclBlock,
	name: string,
	fileText: string,
): Attr | undefined => {
	const own = ownAttributes(block.body);
	const m = new RegExp(`^[ \\t]*${name}[ \\t]*=[ \\t]*(.+)$`, "m").exec(own);
	if (!m) return undefined;
	const raw = (m[1] ?? "").replace(/\s+(#|\/\/).*$/, "").trim();
	const str = /^"([^"]*)"$/.exec(raw)?.[1];
	return { raw, str, line: lineOf(fileText, block.offset + m.index) };
};

const isFalse = (a: Attr | undefined) => a?.raw === "false";
const isTrue = (a: Attr | undefined) => a?.raw === "true";

const WORLD = /"(0\.0\.0\.0\/0|::\/0)"/;
const TF_REGISTRY = "https://registry.terraform.io/providers/hashicorp";

const portsCover = (from: number, to: number, port: number) =>
	from <= port && port <= to;

/** Audits one Terraform file. `allText` is every .tf file joined (for cross-file lookups). */
export const auditTerraform = (
	file: string,
	text: string,
	allText: string = text,
): ReadonlyArray<FindingInput> => {
	const findings: FindingInput[] = [];
	const blocks = parseBlocks(text);
	const push = (f: Omit<FindingInput, "location"> & { line: number }) => {
		const { line, ...rest } = f;
		findings.push({ ...rest, location: { file, line } });
	};
	const name = (b: HclBlock) => b.labels.join(".");

	for (const b of blocks) {
		const type = b.labels[0] ?? "";

		if (b.keyword === "provider") {
			for (const key of ["access_key", "secret_key", "token", "password"]) {
				const a = attr(b, key, text);
				if (!a?.str || a.str.includes("${")) continue;
				push({
					ruleId: "iac.terraform/hardcoded-provider-credentials",
					title: "Hardcoded credentials in provider block",
					severity: "critical",
					category: "security",
					message: `Provider \`${type}\` sets \`${key}\` to a literal value. Anyone with repository access can use these credentials.`,
					remediation:
						"Remove the credential, rotate it, and supply it via environment variables, a shared credentials profile or OIDC.",
					line: a.line,
					evidence: `${key} = "${redact(a.str)}"`,
					references: [
						`${TF_REGISTRY}/aws/latest/docs#authentication-and-configuration`,
						"https://cwe.mitre.org/data/definitions/798.html",
					],
					tags: ["cwe-798", "secrets"],
					confidence: "high",
				});
			}
			continue;
		}
		if (b.keyword !== "resource" && b.keyword !== "data") continue;

		// Literal passwords on resources (RDS, VMs, ...).
		if (b.keyword === "resource") {
			for (const key of ["password", "master_password", "admin_password"]) {
				const a = attr(b, key, text);
				if (!a?.str || a.str.includes("${") || a.str.length < 4) continue;
				push({
					ruleId: "iac.terraform/hardcoded-password",
					title: "Hardcoded password in resource",
					severity: "high",
					category: "security",
					message: `\`${name(b)}\` sets \`${key}\` to a literal; it ends up in VCS and in plaintext state.`,
					remediation:
						"Use a variable marked `sensitive`, a secrets manager data source, or `manage_master_user_password = true`.",
					line: a.line,
					evidence: `${key} = "${redact(a.str)}"`,
					references: ["https://cwe.mitre.org/data/definitions/798.html"],
					tags: ["cwe-798", "secrets"],
					confidence: "high",
				});
			}
		}

		// S3 public ACLs.
		if (type === "aws_s3_bucket" || type === "aws_s3_bucket_acl") {
			const acl = attr(b, "acl", text);
			if (
				acl?.str &&
				/^(public-read|public-read-write|authenticated-read)$/.test(acl.str)
			)
				push({
					ruleId: "iac.terraform/s3-public-acl",
					title: "S3 bucket has a public ACL",
					severity: acl.str === "public-read-write" ? "critical" : "high",
					category: "security",
					message: `\`${name(b)}\` uses the canned ACL \`${acl.str}\`, exposing objects to ${acl.str === "authenticated-read" ? "any AWS account" : "the internet"}.`,
					remediation:
						"Use `private` ACLs (or BucketOwnerEnforced object ownership) and serve public content through CloudFront with OAC.",
					line: acl.line,
					evidence: `acl = "${acl.str}"`,
					references: [
						"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
						"https://www.cisecurity.org/benchmark/amazon_web_services",
					],
					tags: ["cwe-284", "cis-aws-2.1.5"],
					confidence: "high",
				});
		}

		if (type === "aws_s3_bucket_public_access_block") {
			for (const key of [
				"block_public_acls",
				"block_public_policy",
				"ignore_public_acls",
				"restrict_public_buckets",
			]) {
				const a = attr(b, key, text);
				if (!isFalse(a) || !a) continue;
				push({
					ruleId: "iac.terraform/s3-public-access-block-disabled",
					title: "S3 public access block setting disabled",
					severity: "medium",
					category: "security",
					message: `\`${name(b)}\` sets \`${key} = false\`, weakening protection against public buckets.`,
					remediation: `Set \`${key} = true\`.`,
					line: a.line,
					evidence: `${key} = false`,
					references: [
						"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
					],
					tags: ["cwe-284"],
					confidence: "high",
				});
			}
		}

		if (type === "aws_s3_bucket") {
			const hasBlock =
				/resource\s+"aws_s3_bucket_public_access_block"|resource\s+"aws_s3_account_public_access_block"/.test(
					allText,
				);
			if (!hasBlock)
				push({
					ruleId: "iac.terraform/s3-public-access-block-missing",
					title: "S3 bucket without public access block",
					severity: "medium",
					category: "security",
					message: `\`${name(b)}\` has no aws_s3_bucket_public_access_block, so a later ACL or policy change can make it public.`,
					remediation:
						"Add an `aws_s3_bucket_public_access_block` with all four settings true (or an account-level block).",
					line: b.line,
					references: [
						`${TF_REGISTRY}/aws/latest/docs/resources/s3_bucket_public_access_block`,
						"https://www.cisecurity.org/benchmark/amazon_web_services",
					],
					tags: ["cwe-284"],
					confidence: "medium",
				});
		}

		// Security groups open to the world on admin/all ports.
		const ingressRules: Array<{ rule: HclBlock; cidrs: string }> = [];
		if (type === "aws_security_group")
			for (const ing of subBlocks(b, "ingress", text))
				ingressRules.push({ rule: ing, cidrs: ing.body });
		if (
			type === "aws_security_group_rule" &&
			attr(b, "type", text)?.str === "ingress"
		)
			ingressRules.push({ rule: b, cidrs: b.body });
		if (type === "aws_vpc_security_group_ingress_rule")
			ingressRules.push({ rule: b, cidrs: b.body });
		for (const { rule, cidrs } of ingressRules) {
			const world = WORLD.exec(cidrs);
			if (!world) continue;
			const proto = attr(rule, "(?:ip_)?protocol", text)?.str ?? "tcp";
			const from = Number(attr(rule, "from_port", text)?.raw ?? 0);
			const to = Number(attr(rule, "to_port", text)?.raw ?? 65535);
			const allPorts =
				proto === "-1" || proto === "all" || (from <= 0 && to >= 65535);
			const admin = [22, 3389].filter((p) => portsCover(from, to, p));
			if (!allPorts && admin.length === 0) continue;
			push({
				ruleId: "iac.terraform/security-group-open",
				title: allPorts
					? "Security group allows all traffic from the internet"
					: `Security group exposes ${admin.map((p) => (p === 22 ? "SSH" : "RDP")).join("/")} to the internet`,
				severity: "high",
				category: "security",
				message: `\`${name(b)}\` allows ingress from ${world[1]} on ${allPorts ? "all ports" : `port ${admin.join(", ")}`}.`,
				remediation:
					"Restrict ingress to known CIDRs or a bastion/VPN security group; use SSM Session Manager instead of open SSH/RDP.",
				line: rule.line,
				evidence: `${world[1]} ${allPorts ? "all ports" : `${from}-${to}`}`,
				references: [
					"https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html",
					"https://www.cisecurity.org/benchmark/amazon_web_services",
				],
				tags: ["cwe-284", "cis-aws-5.2"],
				confidence: "high",
			});
		}

		// GCP firewall.
		if (type === "google_compute_firewall") {
			const ranges = attr(b, "source_ranges", text);
			const dir = attr(b, "direction", text)?.str ?? "INGRESS";
			if (ranges && /"0\.0\.0\.0\/0"/.test(ranges.raw) && dir === "INGRESS") {
				const allows = subBlocks(b, "allow", text);
				const exposed = allows.some((a) => {
					const ports = attr(a, "ports", text)?.raw;
					const proto = attr(a, "protocol", text)?.str;
					return (
						!ports || proto === "all" || /"(22|3389)"|"0-65535"/.test(ports)
					);
				});
				if (exposed)
					push({
						ruleId: "iac.terraform/firewall-open",
						title: "Firewall exposes admin/all ports to the internet",
						severity: "high",
						category: "security",
						message: `\`${name(b)}\` allows 0.0.0.0/0 to reach SSH/RDP or all ports.`,
						remediation:
							"Restrict `source_ranges` and use IAP TCP forwarding for administrative access.",
						line: ranges.line,
						evidence: `source_ranges = ${ranges.raw}`,
						references: [
							"https://cloud.google.com/firewall/docs/firewalls",
							"https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
						],
						tags: ["cwe-284"],
						confidence: "high",
					});
			}
		}

		// Azure NSG rules (standalone or inline).
		const nsgRules =
			type === "azurerm_network_security_rule"
				? [b]
				: type === "azurerm_network_security_group"
					? subBlocks(b, "security_rule", text)
					: [];
		for (const r of nsgRules) {
			const src = attr(r, "source_address_prefix", text)?.str;
			const port = attr(r, "destination_port_range", text)?.str;
			if (
				attr(r, "direction", text)?.str === "Inbound" &&
				attr(r, "access", text)?.str === "Allow" &&
				src !== undefined &&
				/^(\*|0\.0\.0\.0\/0|Internet|Any)$/i.test(src) &&
				port !== undefined &&
				/^(\*|22|3389)$/.test(port)
			)
				push({
					ruleId: "iac.terraform/nsg-open",
					title: "NSG rule exposes admin/all ports to the internet",
					severity: "high",
					category: "security",
					message: `\`${name(b)}\` allows inbound ${port === "*" ? "all ports" : `port ${port}`} from ${src}.`,
					remediation:
						"Restrict the source prefix and use Azure Bastion or Just-In-Time VM access.",
					line: r.line,
					evidence: `source_address_prefix = "${src}", destination_port_range = "${port}"`,
					references: [
						"https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
					],
					tags: ["cwe-284"],
					confidence: "high",
				});
		}

		// Encryption at rest.
		const encrypted = attr(b, "encrypted", text);
		if (isFalse(encrypted) && encrypted)
			push({
				ruleId: "iac.terraform/storage-unencrypted",
				title: "Storage encryption disabled",
				severity: "medium",
				category: "security",
				message: `\`${name(b)}\` sets \`encrypted = false\`.`,
				remediation:
					"Set `encrypted = true` (optionally with a customer-managed `kms_key_id`).",
				line: encrypted.line,
				evidence: "encrypted = false",
				references: ["https://cwe.mitre.org/data/definitions/311.html"],
				tags: ["cwe-311"],
				confidence: "high",
			});
		if (
			(type === "aws_db_instance" || type === "aws_rds_cluster") &&
			!attr(b, "replicate_source_db", text)
		) {
			const se = attr(b, "storage_encrypted", text);
			if (!se || isFalse(se))
				push({
					ruleId: "iac.terraform/rds-unencrypted",
					title: "RDS storage not encrypted",
					severity: "medium",
					category: "security",
					message: `\`${name(b)}\` ${se ? "sets `storage_encrypted = false`" : "does not set `storage_encrypted`, which defaults to false"}.`,
					remediation:
						"Set `storage_encrypted = true` (encryption cannot be enabled in place later without a snapshot restore).",
					line: se?.line ?? b.line,
					references: [
						"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
					],
					tags: ["cwe-311"],
					confidence: "high",
				});
		}
		if (type === "aws_ebs_volume" && !encrypted)
			push({
				ruleId: "iac.terraform/storage-unencrypted",
				title: "EBS volume encryption not enabled",
				severity: "low",
				category: "security",
				message: `\`${name(b)}\` does not set \`encrypted = true\`; it is only encrypted if account-level EBS encryption by default is on.`,
				remediation:
					"Set `encrypted = true` or enable EBS encryption by default.",
				line: b.line,
				references: [
					"https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
				],
				tags: ["cwe-311"],
				confidence: "medium",
			});

		const publicDb = attr(b, "publicly_accessible", text);
		if (isTrue(publicDb) && publicDb)
			push({
				ruleId: "iac.terraform/db-publicly-accessible",
				title: "Database is publicly accessible",
				severity: "high",
				category: "security",
				message: `\`${name(b)}\` sets \`publicly_accessible = true\`, giving the instance a public endpoint.`,
				remediation:
					"Set `publicly_accessible = false` and reach the database from inside the VPC.",
				line: publicDb.line,
				evidence: "publicly_accessible = true",
				references: [
					"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
				],
				tags: ["cwe-284"],
				confidence: "high",
			});

		// IAM wildcard admin policies.
		if (
			/^aws_iam_(policy|role_policy|user_policy|group_policy|policy_document)$/.test(
				type,
			)
		) {
			const body = b.body;
			const actionStar =
				/["']?Action["']?\s*[:=]\s*\[?\s*["']\*["']/i.test(body) ||
				/\bactions\s*=\s*\[\s*"\*"\s*\]/.test(body);
			const resourceStar =
				/["']?Resource["']?\s*[:=]\s*\[?\s*["']\*["']/i.test(body) ||
				/\bresources\s*=\s*\[\s*"\*"\s*\]/.test(body);
			if (actionStar && resourceStar && !/"Deny"/.test(body)) {
				const idx = body.search(/Action|actions/);
				push({
					ruleId: "iac.terraform/iam-wildcard-policy",
					title: "IAM policy grants * on *",
					severity: "high",
					category: "security",
					message: `\`${name(b)}\` allows every action on every resource (full administrator).`,
					remediation:
						"Scope Action and Resource to what the principal needs; use AWS managed job-function policies or IAM Access Analyzer policy generation.",
					line: lineOf(text, b.offset + Math.max(0, idx)),
					evidence: '"Action": "*", "Resource": "*"',
					references: [
						"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
						"https://www.cisecurity.org/benchmark/amazon_web_services",
					],
					tags: ["cwe-269", "least-privilege", "cis-aws-1.16"],
					confidence: "high",
				});
			}
		}

		// GCS public members.
		if (
			/^google_storage_bucket_(iam_member|iam_binding|access_control|acl)$/.test(
				type,
			)
		) {
			const m =
				/"(allUsers|allAuthenticatedUsers)"|\b(allUsers|allAuthenticatedUsers)\b/.exec(
					b.body,
				);
			if (m)
				push({
					ruleId: "iac.terraform/gcs-public",
					title: "Cloud Storage bucket is public",
					severity: "high",
					category: "security",
					message: `\`${name(b)}\` grants access to \`${m[1] ?? m[2]}\`.`,
					remediation:
						'Remove allUsers/allAuthenticatedUsers and enable `public_access_prevention = "enforced"` on the bucket.',
					line: lineOf(text, b.offset + m.index),
					evidence: m[0],
					references: [
						"https://cloud.google.com/storage/docs/public-access-prevention",
					],
					tags: ["cwe-284"],
					confidence: "high",
				});
		}

		// Azure storage public blobs.
		for (const key of [
			"allow_blob_public_access",
			"allow_nested_items_to_be_public",
		]) {
			const a = attr(b, key, text);
			if (!isTrue(a) || !a) continue;
			push({
				ruleId: "iac.terraform/azure-blob-public",
				title: "Azure storage allows public blob access",
				severity: "high",
				category: "security",
				message: `\`${name(b)}\` sets \`${key} = true\`, so containers can be made anonymously readable.`,
				remediation: `Set \`${key} = false\`.`,
				line: a.line,
				evidence: `${key} = true`,
				references: [
					"https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
				],
				tags: ["cwe-284"],
				confidence: "high",
			});
		}
		if (type === "azurerm_storage_container") {
			const a = attr(b, "container_access_type", text);
			if (a?.str === "blob" || a?.str === "container")
				push({
					ruleId: "iac.terraform/azure-blob-public",
					title: "Azure storage container is public",
					severity: "high",
					category: "security",
					message: `\`${name(b)}\` uses container_access_type \`${a.str}\`, allowing anonymous reads.`,
					remediation: 'Set `container_access_type = "private"`.',
					line: a.line,
					evidence: `container_access_type = "${a.str}"`,
					references: [
						"https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
					],
					tags: ["cwe-284"],
					confidence: "high",
				});
		}

		// Logging explicitly disabled.
		const loggingOff: Attr[] = [];
		for (const key of ["enable_logging", "enable_log_file_validation"]) {
			const a = attr(b, key, text);
			if (a && isFalse(a)) loggingOff.push(a);
		}
		for (const nested of ["logging", "access_logs", "log_config"]) {
			for (const sb of subBlocks(b, nested, text)) {
				const a = attr(sb, "enabled", text) ?? attr(sb, "enable", text);
				if (a && isFalse(a)) loggingOff.push(a);
			}
		}
		for (const a of loggingOff)
			push({
				ruleId: "iac.terraform/logging-disabled",
				title: "Logging disabled",
				severity: "low",
				category: "security",
				message: `\`${name(b)}\` explicitly disables logging (\`${lineTextAt(text, a.line)}\`), hindering incident response.`,
				remediation:
					"Enable access/audit logging and ship logs to a protected bucket or workspace.",
				line: a.line,
				evidence: lineTextAt(text, a.line),
				references: [
					"https://cwe.mitre.org/data/definitions/778.html",
					"https://www.cisecurity.org/benchmark/amazon_web_services",
				],
				tags: ["cwe-778", "logging"],
				confidence: "high",
			});
	}
	return findings;
};

const lineTextAt = (text: string, line: number) =>
	(text.split("\n")[line - 1] ?? "").trim().slice(0, 160);

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
				if (/\.tfstate(\.backup)?$/.test(file)) {
					findings.push({
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
