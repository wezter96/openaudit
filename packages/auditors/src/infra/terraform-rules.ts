import { type FindingInput, lineOf, redact } from "@openaudit/core";

import {
	type Attr,
	type AttrName,
	attr,
	type HclBlock,
	type HclText,
	isFalse,
	isTrue,
	type Keyword,
	type Line,
	lineTextAt,
	subBlocks,
} from "./terraform-hcl";

/** First block label, e.g. `aws_s3_bucket`. */
type ResourceType = string;
/** Literal string value of an attribute. */
type AttrValue = string;
type Protocol = string;
type Port = number;

/** A `resource`, `data` or `provider` block with what its rules look up. */
export interface BlockScope {
	readonly block: HclBlock;
	/** First label (resource type or provider name). */
	readonly type: ResourceType;
	/** All labels joined with dots, e.g. `aws_s3_bucket.logs`. */
	readonly name: string;
	/** Text of the file the block is in. */
	readonly text: HclText;
	/** Every .tf file joined, for cross-file lookups. */
	readonly allText: HclText;
}

/** A finding whose location is a line in the audited file. */
export type Located = Omit<FindingInput, "location"> & { line: Line };

type BlockRule = (scope: BlockScope) => ReadonlyArray<Located>;

const TF_REGISTRY = "https://registry.terraform.io/providers/hashicorp";
const S3_BLOCK_PUBLIC_ACCESS =
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html";
const CIS_AWS = "https://www.cisecurity.org/benchmark/amazon_web_services";
const AZURE_ANONYMOUS_READ =
	"https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent";
const CWE_798 = "https://cwe.mitre.org/data/definitions/798.html";

const attrOf = (scope: BlockScope, name: AttrName) =>
	attr(scope.block, name, scope.text);

/**
 * A rule giving one finding per attribute in `keys` whose value `matches`.
 * The finding shape is shared; only its texts differ per rule.
 */
interface AttrRule<A extends Attr> {
	readonly ruleId: string;
	readonly title: string;
	readonly severity: FindingInput["severity"];
	/** Narrows the blocks the rule looks at; every block when absent. */
	readonly appliesTo?: (scope: BlockScope) => boolean;
	readonly keys: ReadonlyArray<AttrName>;
	readonly matches: (a: Attr | undefined) => a is A;
	readonly message: (scope: BlockScope, key: AttrName) => string;
	readonly remediation: (key: AttrName) => string;
	readonly evidence: (key: AttrName, a: A) => string;
	readonly references: ReadonlyArray<string>;
	readonly tags: ReadonlyArray<string>;
}

const attrFinding = <A extends Attr>(
	rule: AttrRule<A>,
	scope: BlockScope,
	key: AttrName,
	a: A,
): Located => ({
	ruleId: rule.ruleId,
	title: rule.title,
	severity: rule.severity,
	category: "security",
	message: rule.message(scope, key),
	remediation: rule.remediation(key),
	line: a.line,
	evidence: rule.evidence(key, a),
	references: [...rule.references],
	tags: [...rule.tags],
	confidence: "high",
});

const everyBlock = () => true;

const attrRule =
	<A extends Attr>(rule: AttrRule<A>): BlockRule =>
	(scope) => {
		if (!(rule.appliesTo ?? everyBlock)(scope)) return [];
		return rule.keys.flatMap((key) => {
			const a = attrOf(scope, key);
			return rule.matches(a) ? [attrFinding(rule, scope, key, a)] : [];
		});
	};

type LiteralAttr = Attr & { readonly str: AttrValue };

/** A non-empty string literal without interpolation. */
const isLiteral = (a: Attr | undefined): a is LiteralAttr => {
	if (!a?.str) return false;
	return !a.str.includes("${");
};

/** A literal long enough to be a real password. */
const isPasswordLiteral = (a: Attr | undefined): a is LiteralAttr => {
	if (!isLiteral(a)) return false;
	return a.str.length >= 4;
};

const redactedEvidence = (key: AttrName, a: LiteralAttr) =>
	`${key} = "${redact(a.str)}"`;

const providerCredentials = attrRule({
	ruleId: "iac.terraform/hardcoded-provider-credentials",
	title: "Hardcoded credentials in provider block",
	severity: "critical",
	keys: ["access_key", "secret_key", "token", "password"],
	matches: isLiteral,
	message: (scope, key) =>
		`Provider \`${scope.type}\` sets \`${key}\` to a literal value. Anyone with repository access can use these credentials.`,
	remediation: () =>
		"Remove the credential, rotate it, and supply it via environment variables, a shared credentials profile or OIDC.",
	evidence: redactedEvidence,
	references: [
		`${TF_REGISTRY}/aws/latest/docs#authentication-and-configuration`,
		CWE_798,
	],
	tags: ["cwe-798", "secrets"],
});

/** Literal passwords on resources (RDS, VMs, ...). */
const hardcodedPassword = attrRule({
	ruleId: "iac.terraform/hardcoded-password",
	title: "Hardcoded password in resource",
	severity: "high",
	appliesTo: (scope) => scope.block.keyword === "resource",
	keys: ["password", "master_password", "admin_password"],
	matches: isPasswordLiteral,
	message: (scope, key) =>
		`\`${scope.name}\` sets \`${key}\` to a literal; it ends up in VCS and in plaintext state.`,
	remediation: () =>
		"Use a variable marked `sensitive`, a secrets manager data source, or `manage_master_user_password = true`.",
	evidence: redactedEvidence,
	references: [CWE_798],
	tags: ["cwe-798", "secrets"],
});

const S3_ACL_TYPES = new Set(["aws_s3_bucket", "aws_s3_bucket_acl"]);
const PUBLIC_ACL_RE = /^(public-read|public-read-write|authenticated-read)$/;

const s3PublicAcl: BlockRule = (scope) => {
	if (!S3_ACL_TYPES.has(scope.type)) return [];
	const acl = attrOf(scope, "acl");
	if (!isLiteral(acl) || !PUBLIC_ACL_RE.test(acl.str)) return [];
	return [
		{
			ruleId: "iac.terraform/s3-public-acl",
			title: "S3 bucket has a public ACL",
			severity: acl.str === "public-read-write" ? "critical" : "high",
			category: "security",
			message: `\`${scope.name}\` uses the canned ACL \`${acl.str}\`, exposing objects to ${acl.str === "authenticated-read" ? "any AWS account" : "the internet"}.`,
			remediation:
				"Use `private` ACLs (or BucketOwnerEnforced object ownership) and serve public content through CloudFront with OAC.",
			line: acl.line,
			evidence: `acl = "${acl.str}"`,
			references: [S3_BLOCK_PUBLIC_ACCESS, CIS_AWS],
			tags: ["cwe-284", "cis-aws-2.1.5"],
			confidence: "high",
		},
	];
};

const s3PublicAccessBlockDisabled = attrRule({
	ruleId: "iac.terraform/s3-public-access-block-disabled",
	title: "S3 public access block setting disabled",
	severity: "medium",
	appliesTo: (scope) => scope.type === "aws_s3_bucket_public_access_block",
	keys: [
		"block_public_acls",
		"block_public_policy",
		"ignore_public_acls",
		"restrict_public_buckets",
	],
	matches: isFalse,
	message: (scope, key) =>
		`\`${scope.name}\` sets \`${key} = false\`, weakening protection against public buckets.`,
	remediation: (key) => `Set \`${key} = true\`.`,
	evidence: (key) => `${key} = false`,
	references: [S3_BLOCK_PUBLIC_ACCESS],
	tags: ["cwe-284"],
});

const PUBLIC_ACCESS_BLOCK_RE =
	/resource\s+"aws_s3_bucket_public_access_block"|resource\s+"aws_s3_account_public_access_block"/;

const s3PublicAccessBlockMissing: BlockRule = (scope) => {
	if (scope.type !== "aws_s3_bucket") return [];
	if (PUBLIC_ACCESS_BLOCK_RE.test(scope.allText)) return [];
	return [
		{
			ruleId: "iac.terraform/s3-public-access-block-missing",
			title: "S3 bucket without public access block",
			severity: "medium",
			category: "security",
			message: `\`${scope.name}\` has no aws_s3_bucket_public_access_block, so a later ACL or policy change can make it public.`,
			remediation:
				"Add an `aws_s3_bucket_public_access_block` with all four settings true (or an account-level block).",
			line: scope.block.line,
			references: [
				`${TF_REGISTRY}/aws/latest/docs/resources/s3_bucket_public_access_block`,
				CIS_AWS,
			],
			tags: ["cwe-284"],
			confidence: "medium",
		},
	];
};

/** Ingress rule blocks of a security group resource, by resource type. */
const INGRESS_RULES = new Map<
	ResourceType,
	(scope: BlockScope) => ReadonlyArray<HclBlock>
>([
	["aws_security_group", (s) => subBlocks(s.block, "ingress", s.text)],
	[
		"aws_security_group_rule",
		(s) => (attrOf(s, "type")?.str === "ingress" ? [s.block] : []),
	],
	["aws_vpc_security_group_ingress_rule", (s) => [s.block]],
]);

const WORLD = /"(0\.0\.0\.0\/0|::\/0)"/;
const ADMIN_PORTS: ReadonlyArray<Port> = [22, 3389];
const ALL_PROTOCOLS = new Set(["-1", "all"]);

interface PortRange {
	readonly proto: Protocol;
	readonly from: Port;
	readonly to: Port;
}

const ingressPorts = (rule: HclBlock, text: HclText): PortRange => ({
	proto: attr(rule, "(?:ip_)?protocol", text)?.str ?? "tcp",
	from: Number(attr(rule, "from_port", text)?.raw ?? 0),
	to: Number(attr(rule, "to_port", text)?.raw ?? 65535),
});

const portsCover = (range: PortRange, port: Port) =>
	range.from <= port && port <= range.to;

const spansEveryPort = (range: PortRange) =>
	range.from <= 0 && range.to >= 65535;

const coversAllPorts = (range: PortRange) =>
	ALL_PROTOCOLS.has(range.proto) || spansEveryPort(range);

const openIngress = (
	scope: BlockScope,
	rule: HclBlock,
): ReadonlyArray<Located> => {
	const world = WORLD.exec(rule.body);
	if (!world) return [];
	const range = ingressPorts(rule, scope.text);
	const allPorts = coversAllPorts(range);
	const admin = ADMIN_PORTS.filter((p) => portsCover(range, p));
	if (!allPorts && admin.length === 0) return [];
	return [
		{
			ruleId: "iac.terraform/security-group-open",
			title: allPorts
				? "Security group allows all traffic from the internet"
				: `Security group exposes ${admin.map((p) => (p === 22 ? "SSH" : "RDP")).join("/")} to the internet`,
			severity: "high",
			category: "security",
			message: `\`${scope.name}\` allows ingress from ${world[1]} on ${allPorts ? "all ports" : `port ${admin.join(", ")}`}.`,
			remediation:
				"Restrict ingress to known CIDRs or a bastion/VPN security group; use SSM Session Manager instead of open SSH/RDP.",
			line: rule.line,
			evidence: `${world[1]} ${allPorts ? "all ports" : `${range.from}-${range.to}`}`,
			references: [
				"https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html",
				CIS_AWS,
			],
			tags: ["cwe-284", "cis-aws-5.2"],
			confidence: "high",
		},
	];
};

/** Security groups open to the world on admin/all ports. */
const securityGroupOpen: BlockRule = (scope) =>
	(INGRESS_RULES.get(scope.type)?.(scope) ?? []).flatMap((rule) =>
		openIngress(scope, rule),
	);

const WORLD_V4_RE = /"0\.0\.0\.0\/0"/;
const ADMIN_OR_ALL_PORTS_RE = /"(22|3389)"|"0-65535"/;

const isWorldIngress = (
	ranges: Attr | undefined,
	direction: AttrValue,
): ranges is Attr => {
	if (direction !== "INGRESS") return false;
	return ranges !== undefined && WORLD_V4_RE.test(ranges.raw);
};

/** An `allow` block with no port list, all protocols, or SSH/RDP/all ports. */
const exposesAdminPorts = (allow: HclBlock, text: HclText) => {
	const ports = attr(allow, "ports", text)?.raw;
	if (!ports) return true;
	return (
		attr(allow, "protocol", text)?.str === "all" ||
		ADMIN_OR_ALL_PORTS_RE.test(ports)
	);
};

/** GCP firewall. */
const gcpFirewallOpen: BlockRule = (scope) => {
	if (scope.type !== "google_compute_firewall") return [];
	const ranges = attrOf(scope, "source_ranges");
	const dir = attrOf(scope, "direction")?.str ?? "INGRESS";
	if (!isWorldIngress(ranges, dir)) return [];
	const allows = subBlocks(scope.block, "allow", scope.text);
	if (!allows.some((a) => exposesAdminPorts(a, scope.text))) return [];
	return [
		{
			ruleId: "iac.terraform/firewall-open",
			title: "Firewall exposes admin/all ports to the internet",
			severity: "high",
			category: "security",
			message: `\`${scope.name}\` allows 0.0.0.0/0 to reach SSH/RDP or all ports.`,
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
		},
	];
};

/** Azure NSG rule blocks (standalone or inline), by resource type. */
const NSG_RULES = new Map<
	ResourceType,
	(scope: BlockScope) => ReadonlyArray<HclBlock>
>([
	["azurerm_network_security_rule", (s) => [s.block]],
	[
		"azurerm_network_security_group",
		(s) => subBlocks(s.block, "security_rule", s.text),
	],
]);

const OPEN_SOURCE_RE = /^(\*|0\.0\.0\.0\/0|Internet|Any)$/i;
const ADMIN_PORT_RE = /^(\*|22|3389)$/;

interface NsgExposure {
	readonly src: AttrValue;
	readonly port: AttrValue;
}

const matchesRe = (
	value: AttrValue | undefined,
	re: RegExp,
): value is AttrValue => value !== undefined && re.test(value);

const allowsInbound = (rule: HclBlock, text: HclText) =>
	attr(rule, "direction", text)?.str === "Inbound" &&
	attr(rule, "access", text)?.str === "Allow";

/** Source and port of an inbound allow rule open to the internet on admin/all ports. */
const nsgExposure = (
	rule: HclBlock,
	text: HclText,
): NsgExposure | undefined => {
	if (!allowsInbound(rule, text)) return undefined;
	const src = attr(rule, "source_address_prefix", text)?.str;
	const port = attr(rule, "destination_port_range", text)?.str;
	if (!matchesRe(src, OPEN_SOURCE_RE)) return undefined;
	return matchesRe(port, ADMIN_PORT_RE) ? { src, port } : undefined;
};

const nsgFinding = (
	scope: BlockScope,
	rule: HclBlock,
	{ src, port }: NsgExposure,
): Located => ({
	ruleId: "iac.terraform/nsg-open",
	title: "NSG rule exposes admin/all ports to the internet",
	severity: "high",
	category: "security",
	message: `\`${scope.name}\` allows inbound ${port === "*" ? "all ports" : `port ${port}`} from ${src}.`,
	remediation:
		"Restrict the source prefix and use Azure Bastion or Just-In-Time VM access.",
	line: rule.line,
	evidence: `source_address_prefix = "${src}", destination_port_range = "${port}"`,
	references: [
		"https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
	],
	tags: ["cwe-284"],
	confidence: "high",
});

const nsgOpen: BlockRule = (scope) =>
	(NSG_RULES.get(scope.type)?.(scope) ?? []).flatMap((rule) => {
		const exposure = nsgExposure(rule, scope.text);
		return exposure ? [nsgFinding(scope, rule, exposure)] : [];
	});

/** Encryption at rest. */
const storageEncryptionDisabled = attrRule({
	ruleId: "iac.terraform/storage-unencrypted",
	title: "Storage encryption disabled",
	severity: "medium",
	keys: ["encrypted"],
	matches: isFalse,
	message: (scope) => `\`${scope.name}\` sets \`encrypted = false\`.`,
	remediation: () =>
		"Set `encrypted = true` (optionally with a customer-managed `kms_key_id`).",
	evidence: () => "encrypted = false",
	references: ["https://cwe.mitre.org/data/definitions/311.html"],
	tags: ["cwe-311"],
});

const RDS_TYPES = new Set(["aws_db_instance", "aws_rds_cluster"]);

const rdsUnencrypted: BlockRule = (scope) => {
	if (!RDS_TYPES.has(scope.type)) return [];
	if (attrOf(scope, "replicate_source_db")) return [];
	const se = attrOf(scope, "storage_encrypted");
	if (se && !isFalse(se)) return [];
	return [
		{
			ruleId: "iac.terraform/rds-unencrypted",
			title: "RDS storage not encrypted",
			severity: "medium",
			category: "security",
			message: `\`${scope.name}\` ${se ? "sets `storage_encrypted = false`" : "does not set `storage_encrypted`, which defaults to false"}.`,
			remediation:
				"Set `storage_encrypted = true` (encryption cannot be enabled in place later without a snapshot restore).",
			line: se?.line ?? scope.block.line,
			references: [
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			],
			tags: ["cwe-311"],
			confidence: "high",
		},
	];
};

const ebsUnencrypted: BlockRule = (scope) => {
	if (scope.type !== "aws_ebs_volume") return [];
	if (attrOf(scope, "encrypted")) return [];
	return [
		{
			ruleId: "iac.terraform/storage-unencrypted",
			title: "EBS volume encryption not enabled",
			severity: "low",
			category: "security",
			message: `\`${scope.name}\` does not set \`encrypted = true\`; it is only encrypted if account-level EBS encryption by default is on.`,
			remediation:
				"Set `encrypted = true` or enable EBS encryption by default.",
			line: scope.block.line,
			references: [
				"https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
			],
			tags: ["cwe-311"],
			confidence: "medium",
		},
	];
};

const dbPubliclyAccessible = attrRule({
	ruleId: "iac.terraform/db-publicly-accessible",
	title: "Database is publicly accessible",
	severity: "high",
	keys: ["publicly_accessible"],
	matches: isTrue,
	message: (scope) =>
		`\`${scope.name}\` sets \`publicly_accessible = true\`, giving the instance a public endpoint.`,
	remediation: () =>
		"Set `publicly_accessible = false` and reach the database from inside the VPC.",
	evidence: () => "publicly_accessible = true",
	references: [
		"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
	],
	tags: ["cwe-284"],
});

const IAM_POLICY_RE =
	/^aws_iam_(policy|role_policy|user_policy|group_policy|policy_document)$/;
const ACTION_STAR: ReadonlyArray<RegExp> = [
	/["']?Action["']?\s*[:=]\s*\[?\s*["']\*["']/i,
	/\bactions\s*=\s*\[\s*"\*"\s*\]/,
];
const RESOURCE_STAR: ReadonlyArray<RegExp> = [
	/["']?Resource["']?\s*[:=]\s*\[?\s*["']\*["']/i,
	/\bresources\s*=\s*\[\s*"\*"\s*\]/,
];

const anyMatch = (patterns: ReadonlyArray<RegExp>, body: HclText) =>
	patterns.some((re) => re.test(body));

/** Allows `*` actions on `*` resources, with no Deny statement. */
const grantsAllOnAll = (body: HclText) => {
	if (/"Deny"/.test(body)) return false;
	return anyMatch(ACTION_STAR, body) && anyMatch(RESOURCE_STAR, body);
};

/** IAM wildcard admin policies. */
const iamWildcardPolicy: BlockRule = (scope) => {
	if (!IAM_POLICY_RE.test(scope.type)) return [];
	const { body, offset } = scope.block;
	if (!grantsAllOnAll(body)) return [];
	const idx = body.search(/Action|actions/);
	return [
		{
			ruleId: "iac.terraform/iam-wildcard-policy",
			title: "IAM policy grants * on *",
			severity: "high",
			category: "security",
			message: `\`${scope.name}\` allows every action on every resource (full administrator).`,
			remediation:
				"Scope Action and Resource to what the principal needs; use AWS managed job-function policies or IAM Access Analyzer policy generation.",
			line: lineOf(scope.text, offset + Math.max(0, idx)),
			evidence: '"Action": "*", "Resource": "*"',
			references: [
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
				CIS_AWS,
			],
			tags: ["cwe-269", "least-privilege", "cis-aws-1.16"],
			confidence: "high",
		},
	];
};

const GCS_ACCESS_RE =
	/^google_storage_bucket_(iam_member|iam_binding|access_control|acl)$/;
const PUBLIC_MEMBER_RE =
	/"(allUsers|allAuthenticatedUsers)"|\b(allUsers|allAuthenticatedUsers)\b/;

/** GCS public members. */
const gcsPublic: BlockRule = (scope) => {
	if (!GCS_ACCESS_RE.test(scope.type)) return [];
	const m = PUBLIC_MEMBER_RE.exec(scope.block.body);
	if (!m) return [];
	return [
		{
			ruleId: "iac.terraform/gcs-public",
			title: "Cloud Storage bucket is public",
			severity: "high",
			category: "security",
			message: `\`${scope.name}\` grants access to \`${m[1] ?? m[2]}\`.`,
			remediation:
				'Remove allUsers/allAuthenticatedUsers and enable `public_access_prevention = "enforced"` on the bucket.',
			line: lineOf(scope.text, scope.block.offset + m.index),
			evidence: m[0],
			references: [
				"https://cloud.google.com/storage/docs/public-access-prevention",
			],
			tags: ["cwe-284"],
			confidence: "high",
		},
	];
};

/** Azure storage public blobs. */
const azureBlobPublic = attrRule({
	ruleId: "iac.terraform/azure-blob-public",
	title: "Azure storage allows public blob access",
	severity: "high",
	keys: ["allow_blob_public_access", "allow_nested_items_to_be_public"],
	matches: isTrue,
	message: (scope, key) =>
		`\`${scope.name}\` sets \`${key} = true\`, so containers can be made anonymously readable.`,
	remediation: (key) => `Set \`${key} = false\`.`,
	evidence: (key) => `${key} = true`,
	references: [AZURE_ANONYMOUS_READ],
	tags: ["cwe-284"],
});

const PUBLIC_CONTAINER_ACCESS = new Set(["blob", "container"]);

const azureContainerPublic: BlockRule = (scope) => {
	if (scope.type !== "azurerm_storage_container") return [];
	const a = attrOf(scope, "container_access_type");
	if (!isLiteral(a) || !PUBLIC_CONTAINER_ACCESS.has(a.str)) return [];
	return [
		{
			ruleId: "iac.terraform/azure-blob-public",
			title: "Azure storage container is public",
			severity: "high",
			category: "security",
			message: `\`${scope.name}\` uses container_access_type \`${a.str}\`, allowing anonymous reads.`,
			remediation: 'Set `container_access_type = "private"`.',
			line: a.line,
			evidence: `container_access_type = "${a.str}"`,
			references: [AZURE_ANONYMOUS_READ],
			tags: ["cwe-284"],
			confidence: "high",
		},
	];
};

const LOGGING_KEYS: ReadonlyArray<AttrName> = [
	"enable_logging",
	"enable_log_file_validation",
];
const LOGGING_BLOCKS: ReadonlyArray<Keyword> = [
	"logging",
	"access_logs",
	"log_config",
];

const loggingSwitch = (block: HclBlock, text: HclText) =>
	attr(block, "enabled", text) ?? attr(block, "enable", text);

/** Attributes that explicitly turn logging off, on the block or its logging blocks. */
const disabledLogging = (scope: BlockScope): ReadonlyArray<Attr> =>
	[
		...LOGGING_KEYS.map((key) => attrOf(scope, key)),
		...LOGGING_BLOCKS.flatMap((keyword) =>
			subBlocks(scope.block, keyword, scope.text),
		).map((block) => loggingSwitch(block, scope.text)),
	].filter(isFalse);

/** Logging explicitly disabled. */
const loggingDisabled: BlockRule = (scope) =>
	disabledLogging(scope).map(
		(a): Located => ({
			ruleId: "iac.terraform/logging-disabled",
			title: "Logging disabled",
			severity: "low",
			category: "security",
			message: `\`${scope.name}\` explicitly disables logging (\`${lineTextAt(scope.text, a.line)}\`), hindering incident response.`,
			remediation:
				"Enable access/audit logging and ship logs to a protected bucket or workspace.",
			line: a.line,
			evidence: lineTextAt(scope.text, a.line),
			references: ["https://cwe.mitre.org/data/definitions/778.html", CIS_AWS],
			tags: ["cwe-778", "logging"],
			confidence: "high",
		}),
	);

/** Rules for `resource` and `data` blocks, in report order. */
const RESOURCE_RULES: ReadonlyArray<BlockRule> = [
	hardcodedPassword,
	s3PublicAcl,
	s3PublicAccessBlockDisabled,
	s3PublicAccessBlockMissing,
	securityGroupOpen,
	gcpFirewallOpen,
	nsgOpen,
	storageEncryptionDisabled,
	rdsUnencrypted,
	ebsUnencrypted,
	dbPubliclyAccessible,
	iamWildcardPolicy,
	gcsPublic,
	azureBlobPublic,
	azureContainerPublic,
	loggingDisabled,
];

const RULES_BY_KEYWORD = new Map<Keyword, ReadonlyArray<BlockRule>>([
	["provider", [providerCredentials]],
	["resource", RESOURCE_RULES],
	["data", RESOURCE_RULES],
]);

/** Findings of every rule that applies to the block's keyword. */
export const blockFindings = (scope: BlockScope): ReadonlyArray<Located> =>
	(RULES_BY_KEYWORD.get(scope.block.keyword) ?? []).flatMap((rule) =>
		rule(scope),
	);
