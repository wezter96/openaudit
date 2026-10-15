import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	redact,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	asArray,
	asRecord,
	parseYaml,
	readOptional,
	targetFiles,
	type YamlDoc,
	type YamlPath,
} from "./shared";

const YAML_RE = /\.ya?ml$/;
/** YAML that is clearly not a Kubernetes manifest. */
const NOT_K8S_RE =
	/(^|\/)(\.github\/|\.gitlab-ci|(docker-)?compose[^/]*\.ya?ml$|pnpm-lock|\.pre-commit|mkdocs|openapi|swagger)/;

const PSS =
	"https://kubernetes.io/docs/concepts/security/pod-security-standards/";
const SECURITY_CONTEXT =
	"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/";
const CIS = "https://www.cisecurity.org/benchmark/kubernetes";

const WORKLOADS: Record<string, YamlPath> = {
	Pod: ["spec"],
	Deployment: ["spec", "template", "spec"],
	StatefulSet: ["spec", "template", "spec"],
	DaemonSet: ["spec", "template", "spec"],
	ReplicaSet: ["spec", "template", "spec"],
	ReplicationController: ["spec", "template", "spec"],
	Job: ["spec", "template", "spec"],
	CronJob: ["spec", "jobTemplate", "spec", "template", "spec"],
};

const BATCH = new Set(["Job", "CronJob", "Pod"]);

const SECRET_ENV_RE =
	/pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth/i;

const SENSITIVE_HOST_PATHS =
	/^\/(?:$|etc|root|proc|sys|var\/run\/docker\.sock|var\/run|run\/containerd|var\/lib\/kubelet)/;

const DANGEROUS_CAPS = new Set([
	"ALL",
	"SYS_ADMIN",
	"NET_ADMIN",
	"SYS_PTRACE",
	"SYS_MODULE",
	"DAC_READ_SEARCH",
	"NET_RAW",
]);

/** A workspace-relative manifest path. */
type FilePath = string;

const isObject = (value: unknown): value is object =>
	value !== null && typeof value === "object";

const hasOwnKey = (
	value: unknown,
	key: string | number,
): value is Record<string | number, unknown> =>
	isObject(value) && Object.hasOwn(value, key);

const getIn = (value: unknown, path: YamlPath): unknown => {
	let cur = value;
	for (const key of path) {
		if (!hasOwnKey(cur, key)) return undefined;
		// Reads own properties only; nothing is assigned into the object.
		// nosemgrep: javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop
		cur = cur[key];
	}
	return cur;
};

/** Image reference without a tag (or with `:latest`) and without a digest. */
const mutableImage = (image: string): boolean => {
	if (image.includes("@sha256:")) return false;
	const lastSegment = image.slice(image.lastIndexOf("/") + 1);
	const colon = lastSegment.indexOf(":");
	return colon === -1 || lastSegment.slice(colon + 1) === "latest";
};

/** A named resource document in a manifest file. */
interface ManifestDoc {
	readonly file: FilePath;
	readonly doc: YamlDoc;
	readonly kind: string;
	readonly name: string;
}

/** The pod spec of a workload, with what its findings need. */
interface Workload {
	readonly file: FilePath;
	readonly kind: string;
	/** "Kind `name`", for messages. */
	readonly subject: string;
	readonly spec: Record<string, unknown>;
	readonly specPath: YamlPath;
	readonly podSc: Record<string, unknown>;
	readonly line: (path: YamlPath) => number;
}

/** One container of a workload's pod spec. */
interface Container {
	readonly workload: Workload;
	readonly spec: Record<string, unknown>;
	readonly isInit: boolean;
	readonly path: YamlPath;
	/** "Container `name` in Kind `name`", for messages. */
	readonly where: string;
	readonly sc: Record<string, unknown>;
	readonly scPath: YamlPath;
	readonly caps: Record<string, unknown>;
}

const at = (w: Workload, path: YamlPath) => ({
	file: w.file,
	line: w.line(path),
});

const HOST_NAMESPACES = ["hostNetwork", "hostPID", "hostIPC"] as const;

const hostNamespaceFindings = (w: Workload): FindingInput[] =>
	HOST_NAMESPACES.filter((host) => w.spec[host] === true).map((host) => ({
		ruleId: `iac.kubernetes/${host.replace(/[A-Z]+/g, (m) => `-${m.toLowerCase()}`)}`,
		title: `Pod shares the host's ${host.slice(4)} namespace`,
		severity: "high",
		category: "security",
		message: `${w.subject} sets \`${host}: true\`, breaking isolation between the pod and the node.`,
		remediation: `Remove \`${host}\` unless the workload is a trusted node agent.`,
		location: at(w, [...w.specPath, host]),
		evidence: `${host}: true`,
		references: [PSS, CIS],
		tags: ["cwe-250", "pss-baseline"],
		confidence: "high",
	}));

const hostPathFindings = (w: Workload): FindingInput[] =>
	asArray(w.spec.volumes).flatMap((v, i): FindingInput[] => {
		const hostPath = asRecord(asRecord(v)?.hostPath);
		if (!hostPath) return [];
		const path = typeof hostPath.path === "string" ? hostPath.path : "";
		const sensitive = SENSITIVE_HOST_PATHS.test(path);
		return [
			{
				ruleId: "iac.kubernetes/host-path-volume",
				title: "hostPath volume mounted",
				severity: sensitive ? "high" : "medium",
				category: "security",
				message: `${w.subject} mounts the node path \`${path}\`. hostPath volumes allow escaping to the node${sensitive ? "; this path is especially sensitive" : ""}.`,
				remediation:
					"Use a PersistentVolumeClaim, ConfigMap or emptyDir instead of hostPath.",
				location: at(w, [...w.specPath, "volumes", i, "hostPath"]),
				evidence: `hostPath: ${path}`,
				references: [PSS, CIS],
				tags: ["cwe-668", "pss-baseline"],
				confidence: "high",
			},
		];
	});

const tokenAutomountFindings = (w: Workload): FindingInput[] => {
	if (w.spec.automountServiceAccountToken === false) return [];
	return [
		{
			ruleId: "iac.kubernetes/service-account-token-automount",
			title: "Service account token is auto-mounted",
			severity: "low",
			category: "security",
			message: `${w.subject} does not set \`automountServiceAccountToken: false\`, so a compromised container gets an API token.`,
			remediation:
				"Set `automountServiceAccountToken: false` on the pod spec (or service account) unless the app calls the Kubernetes API.",
			location: at(w, w.specPath),
			references: [
				"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting",
				CIS,
			],
			tags: ["cwe-250"],
			confidence: "medium",
		},
	];
};

const privilegedFindings = (c: Container): FindingInput[] => {
	if (c.sc.privileged !== true) return [];
	return [
		{
			ruleId: "iac.kubernetes/privileged-container",
			title: "Privileged container",
			severity: "high",
			category: "security",
			message: `${c.where} runs privileged, with full access to the node's devices and kernel.`,
			remediation:
				"Remove `privileged: true`; grant only the specific capabilities required.",
			location: at(c.workload, [...c.scPath, "privileged"]),
			evidence: "privileged: true",
			references: [PSS, SECURITY_CONTEXT, CIS],
			tags: ["cwe-250", "pss-baseline"],
			confidence: "high",
		},
	];
};

const isNonRootUid = (uid: unknown): boolean =>
	typeof uid === "number" && uid > 0;

/** Container settings override the pod's. */
const enforcesNonRoot = (c: Container): boolean => {
	const podSc = c.workload.podSc;
	if ((c.sc.runAsNonRoot ?? podSc.runAsNonRoot) === true) return true;
	return isNonRootUid(c.sc.runAsUser ?? podSc.runAsUser);
};

const dropsAllCapabilities = (c: Container): boolean =>
	asArray(c.caps.drop)
		.map((d) => String(d).toUpperCase())
		.includes("ALL");

/** A hardening setting missing from a container's securityContext. */
interface SecurityContextRule {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly message: (where: string) => string;
	readonly remediation: string;
	readonly references: ReadonlyArray<string>;
	readonly tags: ReadonlyArray<string>;
	readonly hardened: (c: Container) => boolean;
}

/** In report order. Each finding points at the container's securityContext. */
const SECURITY_CONTEXT_RULES: ReadonlyArray<SecurityContextRule> = [
	{
		id: "privilege-escalation-allowed",
		title: "Privilege escalation not disabled",
		severity: "medium",
		message: (where) =>
			`${where} does not set \`allowPrivilegeEscalation: false\`, so setuid binaries can gain more privileges.`,
		remediation:
			"Set `securityContext.allowPrivilegeEscalation: false` on every container.",
		references: [PSS, SECURITY_CONTEXT],
		tags: ["cwe-250", "pss-restricted"],
		hardened: (c) => c.sc.allowPrivilegeEscalation === false,
	},
	{
		id: "run-as-root",
		title: "Container may run as root",
		severity: "medium",
		message: (where) =>
			`${where} does not enforce \`runAsNonRoot: true\` (or a non-zero runAsUser), so it runs as root if the image does.`,
		remediation:
			"Set `securityContext.runAsNonRoot: true` and a non-zero `runAsUser` on the pod or container.",
		references: [PSS, SECURITY_CONTEXT, CIS],
		tags: ["cwe-250", "pss-restricted"],
		hardened: enforcesNonRoot,
	},
	{
		id: "writable-root-filesystem",
		title: "Root filesystem is writable",
		severity: "low",
		message: (where) =>
			`${where} does not set \`readOnlyRootFilesystem: true\`; an attacker can modify binaries or drop tools.`,
		remediation:
			"Set `securityContext.readOnlyRootFilesystem: true` and mount emptyDir volumes for paths that need writes.",
		references: [SECURITY_CONTEXT, CIS],
		tags: ["cwe-732"],
		hardened: (c) => c.sc.readOnlyRootFilesystem === true,
	},
	{
		id: "capabilities-not-dropped",
		title: "Linux capabilities not dropped",
		severity: "low",
		message: (where) =>
			`${where} keeps the runtime's default capabilities (e.g. NET_RAW).`,
		remediation:
			'Set `securityContext.capabilities.drop: ["ALL"]` and add back only what is needed.',
		references: [PSS, SECURITY_CONTEXT],
		tags: ["cwe-250", "pss-restricted"],
		hardened: dropsAllCapabilities,
	},
];

const securityContextFindings = (c: Container): FindingInput[] =>
	SECURITY_CONTEXT_RULES.filter((rule) => !rule.hardened(c)).map((rule) => ({
		ruleId: `iac.kubernetes/${rule.id}`,
		title: rule.title,
		severity: rule.severity,
		category: "security",
		message: rule.message(c.where),
		remediation: rule.remediation,
		location: at(c.workload, c.scPath),
		references: [...rule.references],
		tags: [...rule.tags],
		confidence: "high",
	}));

const dangerousCapabilityFindings = (c: Container): FindingInput[] =>
	asArray(c.caps.add)
		.map((cap) => String(cap).toUpperCase().replace(/^CAP_/, ""))
		.filter((name) => DANGEROUS_CAPS.has(name))
		.map((name) => ({
			ruleId: "iac.kubernetes/dangerous-capability",
			title: `Dangerous capability ${name} added`,
			severity: "high",
			category: "security",
			message: `${c.where} adds the ${name} capability, which allows container escape or network manipulation.`,
			remediation: `Remove ${name} from capabilities.add.`,
			location: at(c.workload, [...c.scPath, "capabilities", "add"]),
			evidence: `add: ${name}`,
			references: [PSS],
			tags: ["cwe-250", "pss-baseline"],
			confidence: "high",
		}));

const mutableImageFindings = (c: Container): FindingInput[] => {
	const image = typeof c.spec.image === "string" ? c.spec.image : undefined;
	if (!image || !mutableImage(image)) return [];
	return [
		{
			ruleId: "iac.kubernetes/image-mutable-tag",
			title: "Image uses latest or no tag",
			severity: "medium",
			category: "supply-chain",
			message: `${c.where} uses \`${image}\`, which can change under you and makes rollbacks unreliable.`,
			remediation:
				"Pin images to a specific version tag, ideally with a digest (`image:1.2.3@sha256:...`).",
			location: at(c.workload, [...c.path, "image"]),
			evidence: `image: ${image}`,
			references: [
				"https://kubernetes.io/docs/concepts/containers/images/#image-names",
			],
			tags: ["supply-chain"],
			confidence: "high",
		},
	];
};

const resourcesMissingFindings = (c: Container): FindingInput[] => {
	const resources = asRecord(c.spec.resources) ?? {};
	const missing = (["requests", "limits"] as const).filter(
		(k) => !asRecord(resources[k]),
	);
	if (missing.length === 0) return [];
	return [
		{
			ruleId: "iac.kubernetes/resources-missing",
			title: "Resource requests/limits missing",
			severity: "low",
			category: "reliability",
			message: `${c.where} has no resource ${missing.join(" or ")}; it can starve neighbours or be evicted unpredictably.`,
			remediation:
				"Set `resources.requests` and `resources.limits` for CPU and memory.",
			location: at(c.workload, c.path),
			references: [
				"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
			],
			tags: ["dos"],
			confidence: "high",
		},
	];
};

/** Init containers and batch workloads run to completion, so need no probes. */
const isLongRunning = (c: Container): boolean =>
	!c.isInit && !BATCH.has(c.workload.kind);

const probesMissingFindings = (c: Container): FindingInput[] => {
	if (!isLongRunning(c)) return [];
	const probes = (["livenessProbe", "readinessProbe"] as const).filter(
		(p) => !c.spec[p],
	);
	if (probes.length === 0) return [];
	return [
		{
			ruleId: "iac.kubernetes/probes-missing",
			title: "Health probes missing",
			severity: "low",
			category: "reliability",
			message: `${c.where} has no ${probes.join(" or ")}; Kubernetes cannot detect a hung or unready process.`,
			remediation:
				"Add livenessProbe and readinessProbe (HTTP, TCP or exec) for long-running containers.",
			location: at(c.workload, c.path),
			references: [
				"https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
			],
			tags: ["availability"],
			confidence: "high",
		},
	];
};

/** `$(VAR)` and `${VAR}` reference other variables rather than holding a value. */
const isEnvReference = (value: string): boolean => /^\$\(|^\$\{/.test(value);

const isLiteralValue = (value: unknown): value is string =>
	typeof value === "string" && value.length >= 4 && !isEnvReference(value);

/** An env var with a secret-looking name and a literal value. */
const literalSecretEnv = (
	raw: unknown,
): { readonly name: string; readonly value: string } | undefined => {
	const env = asRecord(raw);
	if (typeof env?.name !== "string") return undefined;
	if (!SECRET_ENV_RE.test(env.name)) return undefined;
	const value = env.value;
	return isLiteralValue(value) ? { name: env.name, value } : undefined;
};

const secretInEnvFindings = (c: Container): FindingInput[] =>
	asArray(c.spec.env).flatMap((rawEnv, j): FindingInput[] => {
		const env = literalSecretEnv(rawEnv);
		if (!env) return [];
		return [
			{
				ruleId: "iac.kubernetes/secret-in-env",
				title: "Secret hardcoded in environment variable",
				severity: "high",
				category: "security",
				message: `${c.where} sets \`${env.name}\` to a literal value in the manifest; anyone with read access to the manifest or the pod spec sees it.`,
				remediation:
					"Store the value in a Secret (or external secret manager) and reference it via `valueFrom.secretKeyRef`.",
				location: at(c.workload, [...c.path, "env", j, "value"]),
				evidence: `${env.name}=${redact(env.value)}`,
				references: [
					"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables",
					"https://cwe.mitre.org/data/definitions/798.html",
				],
				tags: ["cwe-798", "secrets"],
				confidence: "medium",
			},
		];
	});

/** Container checks, in report order. */
const CONTAINER_RULES: ReadonlyArray<(c: Container) => FindingInput[]> = [
	privilegedFindings,
	securityContextFindings,
	dangerousCapabilityFindings,
	mutableImageFindings,
	resourcesMissingFindings,
	probesMissingFindings,
	secretInEnvFindings,
];

const CONTAINER_LISTS = [
	["containers", false],
	["initContainers", true],
] as const;

const containerFindings = (
	w: Workload,
	[listKey, isInit]: (typeof CONTAINER_LISTS)[number],
): FindingInput[] =>
	asArray(w.spec[listKey]).flatMap((raw, i): FindingInput[] => {
		const spec = asRecord(raw);
		if (!spec) return [];
		const path: YamlPath = [...w.specPath, listKey, i];
		const name = typeof spec.name === "string" ? spec.name : `#${i}`;
		const sc = asRecord(spec.securityContext) ?? {};
		const container: Container = {
			workload: w,
			spec,
			isInit,
			path,
			where: `Container \`${name}\` in ${w.subject}`,
			sc,
			scPath: [...path, "securityContext"],
			caps: asRecord(sc.capabilities) ?? {},
		};
		return CONTAINER_RULES.flatMap((rule) => rule(container));
	});

const auditWorkload = (
	{ file, doc, kind, name }: ManifestDoc,
	specPath: YamlPath,
): FindingInput[] => {
	const spec = asRecord(getIn(doc.value, specPath));
	if (!spec) return [];
	const workload: Workload = {
		file,
		kind,
		subject: `${kind} \`${name}\``,
		spec,
		specPath,
		podSc: asRecord(spec.securityContext) ?? {},
		line: (path) => doc.lineOf(path) ?? 1,
	};
	return [
		...hostNamespaceFindings(workload),
		...hostPathFindings(workload),
		...tokenAutomountFindings(workload),
		...CONTAINER_LISTS.flatMap((list) => containerFindings(workload, list)),
	];
};

/** Wildcards on verbs or resources grant full control; on apiGroups alone they do not. */
const grantsWildcard = (wild: ReadonlyArray<string>): boolean =>
	wild.includes("verbs") || wild.includes("resources");

const auditRbac = ({ file, doc, kind, name }: ManifestDoc): FindingInput[] => {
	const value = asRecord(doc.value) ?? {};
	return asArray(value.rules).flatMap((raw, i): FindingInput[] => {
		const rule = asRecord(raw);
		if (!rule) return [];
		const wild = (["verbs", "resources", "apiGroups"] as const).filter((k) =>
			asArray(rule[k]).includes("*"),
		);
		if (!grantsWildcard(wild)) return [];
		return [
			{
				ruleId: "iac.kubernetes/rbac-wildcard",
				title: "RBAC rule uses wildcards",
				severity: "high",
				category: "security",
				message: `${kind} \`${name}\` grants \`*\` on ${wild.join(", ")}, effectively full control over those APIs (including future resources).`,
				remediation:
					"List the explicit verbs and resources the subject needs; avoid `*`.",
				location: { file, line: doc.lineOf(["rules", i]) ?? 1 },
				evidence: wild.map((k) => `${k}: ["*"]`).join(", "),
				references: [
					"https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
					CIS,
				],
				tags: ["cwe-269", "least-privilege"],
				confidence: "high",
			},
		];
	});
};

const EXPOSED_SERVICE_TYPES = new Set<unknown>(["LoadBalancer", "NodePort"]);

const auditService = (
	{ file, doc, name }: ManifestDoc,
	value: Record<string, unknown>,
): FindingInput[] => {
	const type = asRecord(value.spec)?.type;
	if (!EXPOSED_SERVICE_TYPES.has(type)) return [];
	return [
		{
			ruleId: "iac.kubernetes/service-exposed",
			title: `Service exposed via ${type}`,
			severity: "info",
			category: "security",
			message: `Service \`${name}\` is of type ${type} and reachable from outside the cluster. Confirm the exposure is intended.`,
			remediation:
				"Prefer ClusterIP behind an Ingress/Gateway with TLS and auth; restrict `loadBalancerSourceRanges` when a LoadBalancer is required.",
			location: { file, line: doc.lineOf(["spec", "type"]) ?? 1 },
			evidence: `type: ${type}`,
			references: [
				"https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types",
			],
			tags: ["attack-surface"],
			confidence: "high",
		},
	];
};

const RBAC_KINDS = new Set(["Role", "ClusterRole"]);

const auditDoc = (file: FilePath, doc: YamlDoc): FindingInput[] => {
	const value = asRecord(doc.value);
	if (typeof value?.kind !== "string") return [];
	const kind = value.kind;
	// Kubernetes `List` wrappers are rare in source; skip rather than recurse.
	if (kind === "List") return [];
	const name =
		(asRecord(value.metadata)?.name as string | undefined) ?? "unnamed";
	const manifest: ManifestDoc = { file, doc, kind, name };
	const specPath = WORKLOADS[kind];
	if (specPath) return auditWorkload(manifest, specPath);
	if (RBAC_KINDS.has(kind)) return auditRbac(manifest);
	if (kind === "Service") return auditService(manifest, value);
	return [];
};

/** Audits a manifest file (possibly multi-document). Pure; exported for tests. */
export const auditManifest = (
	file: FilePath,
	text: string,
): ReadonlyArray<FindingInput> => {
	// Helm/Go templates are not valid YAML until rendered.
	if (text.includes("{{")) return [];
	return parseYaml(text).docs.flatMap((doc) => auditDoc(file, doc));
};

const looksLikeManifest = (text: string): boolean =>
	/^apiVersion:\s*\S/m.test(text) && /^kind:\s*\S/m.test(text);

/** The text of `file` when it looks like a Kubernetes manifest. */
const manifestText = (ctx: AuditContext, ws: Workspace, file: FilePath) =>
	Effect.gen(function* () {
		if (ctx.target.type !== "file" && NOT_K8S_RE.test(file)) return undefined;
		const text = yield* readOptional(ws, file);
		if (text === undefined || !looksLikeManifest(text)) return undefined;
		return text;
	});

/** Kubernetes manifest security and reliability checks. */
export const kubernetes = defineAuditor({
	id: "iac.kubernetes",
	title: "Kubernetes manifests",
	description:
		"Checks workloads for privileged/root containers, host namespaces, hostPath, missing limits and probes, mutable images, plaintext secrets, exposed Services and RBAC wildcards.",
	categories: ["security", "reliability", "supply-chain"],
	targets: ["iac"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, YAML_RE);
			const findings: FindingInput[] = [];
			let audited = 0;
			for (const file of files) {
				const text = yield* manifestText(ctx, ws, file);
				if (text === undefined) continue;
				if (text.includes("{{")) {
					yield* ctx.log(`iac.kubernetes: skipping template ${file}`);
					continue;
				}
				audited++;
				findings.push(...auditManifest(file, text));
			}
			if (audited === 0) return yield* skip("No Kubernetes manifests found");
			return findings;
		}),
});
