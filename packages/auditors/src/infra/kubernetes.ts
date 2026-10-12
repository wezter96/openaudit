import {
	defineAuditor,
	type FindingInput,
	redact,
	skip,
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

const getIn = (value: unknown, path: YamlPath): unknown => {
	let cur = value;
	for (const key of path) {
		if (cur === null || typeof cur !== "object") return undefined;
		cur = (cur as Record<string | number, unknown>)[key];
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

const auditWorkload = (
	file: string,
	doc: YamlDoc,
	kind: string,
	name: string,
	specPath: YamlPath,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const spec = asRecord(getIn(doc.value, specPath));
	if (!spec) return findings;
	const line = (path: YamlPath) => doc.lineOf(path) ?? 1;
	const subject = `${kind} \`${name}\``;
	const podSc = asRecord(spec.securityContext) ?? {};

	for (const host of ["hostNetwork", "hostPID", "hostIPC"] as const) {
		if (spec[host] === true)
			findings.push({
				ruleId: `iac.kubernetes/${host.replace(/[A-Z]+/g, (m) => `-${m.toLowerCase()}`)}`,
				title: `Pod shares the host's ${host.slice(4)} namespace`,
				severity: "high",
				category: "security",
				message: `${subject} sets \`${host}: true\`, breaking isolation between the pod and the node.`,
				remediation: `Remove \`${host}\` unless the workload is a trusted node agent.`,
				location: { file, line: line([...specPath, host]) },
				evidence: `${host}: true`,
				references: [PSS, CIS],
				tags: ["cwe-250", "pss-baseline"],
				confidence: "high",
			});
	}

	asArray(spec.volumes).forEach((v, i) => {
		const hostPath = asRecord(asRecord(v)?.hostPath);
		if (!hostPath) return;
		const path = typeof hostPath.path === "string" ? hostPath.path : "";
		const sensitive = SENSITIVE_HOST_PATHS.test(path);
		findings.push({
			ruleId: "iac.kubernetes/host-path-volume",
			title: "hostPath volume mounted",
			severity: sensitive ? "high" : "medium",
			category: "security",
			message: `${subject} mounts the node path \`${path}\`. hostPath volumes allow escaping to the node${sensitive ? "; this path is especially sensitive" : ""}.`,
			remediation:
				"Use a PersistentVolumeClaim, ConfigMap or emptyDir instead of hostPath.",
			location: { file, line: line([...specPath, "volumes", i, "hostPath"]) },
			evidence: `hostPath: ${path}`,
			references: [PSS, CIS],
			tags: ["cwe-668", "pss-baseline"],
			confidence: "high",
		});
	});

	if (spec.automountServiceAccountToken !== false)
		findings.push({
			ruleId: "iac.kubernetes/service-account-token-automount",
			title: "Service account token is auto-mounted",
			severity: "low",
			category: "security",
			message: `${subject} does not set \`automountServiceAccountToken: false\`, so a compromised container gets an API token.`,
			remediation:
				"Set `automountServiceAccountToken: false` on the pod spec (or service account) unless the app calls the Kubernetes API.",
			location: { file, line: line(specPath) },
			references: [
				"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting",
				CIS,
			],
			tags: ["cwe-250"],
			confidence: "medium",
		});

	const containerLists = [
		["containers", false],
		["initContainers", true],
	] as const;
	for (const [listKey, isInit] of containerLists) {
		asArray(spec[listKey]).forEach((raw, i) => {
			const c = asRecord(raw);
			if (!c) return;
			const cPath: YamlPath = [...specPath, listKey, i];
			const cName = typeof c.name === "string" ? c.name : `#${i}`;
			const where = `Container \`${cName}\` in ${subject}`;
			const sc = asRecord(c.securityContext) ?? {};
			const scPath: YamlPath = [...cPath, "securityContext"];
			const caps = asRecord(sc.capabilities) ?? {};

			if (sc.privileged === true)
				findings.push({
					ruleId: "iac.kubernetes/privileged-container",
					title: "Privileged container",
					severity: "high",
					category: "security",
					message: `${where} runs privileged, with full access to the node's devices and kernel.`,
					remediation:
						"Remove `privileged: true`; grant only the specific capabilities required.",
					location: { file, line: line([...scPath, "privileged"]) },
					evidence: "privileged: true",
					references: [PSS, SECURITY_CONTEXT, CIS],
					tags: ["cwe-250", "pss-baseline"],
					confidence: "high",
				});

			if (sc.allowPrivilegeEscalation !== false)
				findings.push({
					ruleId: "iac.kubernetes/privilege-escalation-allowed",
					title: "Privilege escalation not disabled",
					severity: "medium",
					category: "security",
					message: `${where} does not set \`allowPrivilegeEscalation: false\`, so setuid binaries can gain more privileges.`,
					remediation:
						"Set `securityContext.allowPrivilegeEscalation: false` on every container.",
					location: { file, line: line(scPath) },
					references: [PSS, SECURITY_CONTEXT],
					tags: ["cwe-250", "pss-restricted"],
					confidence: "high",
				});

			const runAsNonRoot = sc.runAsNonRoot ?? podSc.runAsNonRoot;
			const runAsUser = sc.runAsUser ?? podSc.runAsUser;
			if (
				runAsNonRoot !== true &&
				!(typeof runAsUser === "number" && runAsUser > 0)
			)
				findings.push({
					ruleId: "iac.kubernetes/run-as-root",
					title: "Container may run as root",
					severity: "medium",
					category: "security",
					message: `${where} does not enforce \`runAsNonRoot: true\` (or a non-zero runAsUser), so it runs as root if the image does.`,
					remediation:
						"Set `securityContext.runAsNonRoot: true` and a non-zero `runAsUser` on the pod or container.",
					location: { file, line: line(scPath) },
					references: [PSS, SECURITY_CONTEXT, CIS],
					tags: ["cwe-250", "pss-restricted"],
					confidence: "high",
				});

			if (sc.readOnlyRootFilesystem !== true)
				findings.push({
					ruleId: "iac.kubernetes/writable-root-filesystem",
					title: "Root filesystem is writable",
					severity: "low",
					category: "security",
					message: `${where} does not set \`readOnlyRootFilesystem: true\`; an attacker can modify binaries or drop tools.`,
					remediation:
						"Set `securityContext.readOnlyRootFilesystem: true` and mount emptyDir volumes for paths that need writes.",
					location: { file, line: line(scPath) },
					references: [SECURITY_CONTEXT, CIS],
					tags: ["cwe-732"],
					confidence: "high",
				});

			const dropped = asArray(caps.drop).map((d) => String(d).toUpperCase());
			if (!dropped.includes("ALL"))
				findings.push({
					ruleId: "iac.kubernetes/capabilities-not-dropped",
					title: "Linux capabilities not dropped",
					severity: "low",
					category: "security",
					message: `${where} keeps the runtime's default capabilities (e.g. NET_RAW).`,
					remediation:
						'Set `securityContext.capabilities.drop: ["ALL"]` and add back only what is needed.',
					location: { file, line: line(scPath) },
					references: [PSS, SECURITY_CONTEXT],
					tags: ["cwe-250", "pss-restricted"],
					confidence: "high",
				});

			for (const cap of asArray(caps.add)) {
				const name = String(cap).toUpperCase().replace(/^CAP_/, "");
				if (!DANGEROUS_CAPS.has(name)) continue;
				findings.push({
					ruleId: "iac.kubernetes/dangerous-capability",
					title: `Dangerous capability ${name} added`,
					severity: "high",
					category: "security",
					message: `${where} adds the ${name} capability, which allows container escape or network manipulation.`,
					remediation: `Remove ${name} from capabilities.add.`,
					location: { file, line: line([...scPath, "capabilities", "add"]) },
					evidence: `add: ${name}`,
					references: [PSS],
					tags: ["cwe-250", "pss-baseline"],
					confidence: "high",
				});
			}

			const image = typeof c.image === "string" ? c.image : undefined;
			if (image && mutableImage(image))
				findings.push({
					ruleId: "iac.kubernetes/image-mutable-tag",
					title: "Image uses latest or no tag",
					severity: "medium",
					category: "supply-chain",
					message: `${where} uses \`${image}\`, which can change under you and makes rollbacks unreliable.`,
					remediation:
						"Pin images to a specific version tag, ideally with a digest (`image:1.2.3@sha256:...`).",
					location: { file, line: line([...cPath, "image"]) },
					evidence: `image: ${image}`,
					references: [
						"https://kubernetes.io/docs/concepts/containers/images/#image-names",
					],
					tags: ["supply-chain"],
					confidence: "high",
				});

			const resources = asRecord(c.resources) ?? {};
			const missing = (["requests", "limits"] as const).filter(
				(k) => !asRecord(resources[k]),
			);
			if (missing.length > 0)
				findings.push({
					ruleId: "iac.kubernetes/resources-missing",
					title: "Resource requests/limits missing",
					severity: "low",
					category: "reliability",
					message: `${where} has no resource ${missing.join(" or ")}; it can starve neighbours or be evicted unpredictably.`,
					remediation:
						"Set `resources.requests` and `resources.limits` for CPU and memory.",
					location: { file, line: line(cPath) },
					references: [
						"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
					],
					tags: ["dos"],
					confidence: "high",
				});

			if (!isInit && !BATCH.has(kind)) {
				const probes = (["livenessProbe", "readinessProbe"] as const).filter(
					(p) => !c[p],
				);
				if (probes.length > 0)
					findings.push({
						ruleId: "iac.kubernetes/probes-missing",
						title: "Health probes missing",
						severity: "low",
						category: "reliability",
						message: `${where} has no ${probes.join(" or ")}; Kubernetes cannot detect a hung or unready process.`,
						remediation:
							"Add livenessProbe and readinessProbe (HTTP, TCP or exec) for long-running containers.",
						location: { file, line: line(cPath) },
						references: [
							"https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
						],
						tags: ["availability"],
						confidence: "high",
					});
			}

			asArray(c.env).forEach((rawEnv, j) => {
				const env = asRecord(rawEnv);
				if (!env || typeof env.name !== "string") return;
				const value = env.value;
				if (
					!SECRET_ENV_RE.test(env.name) ||
					typeof value !== "string" ||
					value.length < 4 ||
					/^\$\(|^\$\{/.test(value)
				)
					return;
				findings.push({
					ruleId: "iac.kubernetes/secret-in-env",
					title: "Secret hardcoded in environment variable",
					severity: "high",
					category: "security",
					message: `${where} sets \`${env.name}\` to a literal value in the manifest; anyone with read access to the manifest or the pod spec sees it.`,
					remediation:
						"Store the value in a Secret (or external secret manager) and reference it via `valueFrom.secretKeyRef`.",
					location: { file, line: line([...cPath, "env", j, "value"]) },
					evidence: `${env.name}=${redact(value)}`,
					references: [
						"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables",
						"https://cwe.mitre.org/data/definitions/798.html",
					],
					tags: ["cwe-798", "secrets"],
					confidence: "medium",
				});
			});
		});
	}
	return findings;
};

const auditRbac = (
	file: string,
	doc: YamlDoc,
	kind: string,
	name: string,
): FindingInput[] => {
	const value = asRecord(doc.value) ?? {};
	const findings: FindingInput[] = [];
	asArray(value.rules).forEach((raw, i) => {
		const rule = asRecord(raw);
		if (!rule) return;
		const wild = (["verbs", "resources", "apiGroups"] as const).filter((k) =>
			asArray(rule[k]).includes("*"),
		);
		if (!wild.includes("verbs") && !wild.includes("resources")) return;
		findings.push({
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
		});
	});
	return findings;
};

/** Audits a manifest file (possibly multi-document). Pure; exported for tests. */
export const auditManifest = (
	file: string,
	text: string,
): ReadonlyArray<FindingInput> => {
	// Helm/Go templates are not valid YAML until rendered.
	if (text.includes("{{")) return [];
	const { docs } = parseYaml(text);
	const findings: FindingInput[] = [];
	for (const doc of docs) {
		const value = asRecord(doc.value);
		if (!value || typeof value.kind !== "string") continue;
		const kind = value.kind;
		const name =
			(asRecord(value.metadata)?.name as string | undefined) ?? "unnamed";
		if (kind === "List") {
			// Kubernetes `List` wrappers are rare in source; skip rather than recurse.
			continue;
		}
		const specPath = WORKLOADS[kind];
		if (specPath)
			findings.push(...auditWorkload(file, doc, kind, name, specPath));
		else if (kind === "Role" || kind === "ClusterRole")
			findings.push(...auditRbac(file, doc, kind, name));
		else if (kind === "Service") {
			const type = asRecord(value.spec)?.type;
			if (type === "LoadBalancer" || type === "NodePort")
				findings.push({
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
				});
		}
	}
	return findings;
};

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
				if (ctx.target.type !== "file" && NOT_K8S_RE.test(file)) continue;
				const text = yield* readOptional(ws, file);
				if (
					text === undefined ||
					!/^apiVersion:\s*\S/m.test(text) ||
					!/^kind:\s*\S/m.test(text)
				)
					continue;
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
