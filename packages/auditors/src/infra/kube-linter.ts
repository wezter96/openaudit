import {
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord, kebab, truncate } from "../codebase/util";
import { arr, parseJson, relPath, runTool, str } from "../tool";
import { kubernetesManifests } from "./shared";

/** A kube-linter check name, such as `privileged-container`. */
type CheckName = string;

/** The workspace root kube-linter ran in. */
type FilePath = string;

/** Checks with a security impact, with a deliberate severity. */
const SECURITY: Record<CheckName, Severity> = {
	"privileged-container": "high",
	"privilege-escalation-container": "high",
	"docker-sock": "high",
	"host-network": "high",
	"host-pid": "high",
	"host-ipc": "high",
	"sensitive-host-mounts": "high",
	"writable-host-mount": "high",
	"cluster-admin-role-binding": "high",
	"access-to-create-pods": "high",
	"access-to-secrets": "high",
	"wildcard-in-rules": "high",
	"env-var-secret": "high",
	"unsafe-proc-mount": "high",
	"unsafe-sysctls": "high",
	"run-as-non-root": "medium",
	"no-read-only-root-fs": "medium",
	"drop-net-raw-capability": "medium",
	"read-secret-from-env-var": "medium",
	"default-service-account": "medium",
	"exposed-services": "medium",
	"ssh-port": "medium",
	"no-extensions-v1beta": "low",
	"use-namespace": "low",
	"restart-policy": "low",
};

const RELIABILITY = new Set([
	"unset-cpu-requirements",
	"unset-memory-requirements",
	"no-liveness-probe",
	"no-readiness-probe",
	"no-anti-affinity",
	"minimum-three-replicas",
	"pdb-max-unavailable",
	"pdb-min-available",
	"pdb-unhealthy-pod-eviction-policy",
	"dangling-service",
	"dangling-ingress",
	"dangling-horizontalpodautoscaler",
	"dangling-networkpolicy",
	"dangling-servicemonitor",
	"mismatching-selector",
	"non-existent-service-account",
	"no-rolling-update-strategy",
	"hpa-minimum-three-replicas",
]);

const recordAt = (value: unknown): Record<string, unknown> =>
	isRecord(value) ? value : {};

const severityOf = (check: CheckName): Severity =>
	SECURITY[check] ?? (RELIABILITY.has(check) ? "low" : "info");

const categoryOf = (check: CheckName): Category => {
	if (check in SECURITY) return "security";
	return RELIABILITY.has(check) ? "reliability" : "best-practices";
};

/** `Kind/name` of the reported object, or "" when kube-linter omits both. */
const resourceOf = (object: Record<string, unknown>): string => {
	const k8s = recordAt(object.K8sObject);
	const gvk = recordAt(k8s.GroupVersionKind);
	return [str(gvk.Kind), str(k8s.Name)].filter(Boolean).join("/");
};

const kubeLinterFinding = (
	raw: Record<string, unknown>,
	root: FilePath,
): FindingInput => {
	const check = str(raw.Check) ?? "unknown";
	const message = str(recordAt(raw.Diagnostic).Message) ?? check;
	const object = recordAt(raw.Object);
	const metadata = recordAt(object.Metadata);
	const resource = resourceOf(object);
	return {
		ruleId: `iac.kube-linter/${kebab(check)}`,
		title: `${check}${resource ? `: ${resource}` : ""}`,
		severity: severityOf(check),
		category: categoryOf(check),
		message: truncate(message, 300),
		remediation:
			str(raw.Remediation) ?? "See the kube-linter check documentation.",
		// kube-linter reports no line numbers.
		location: { file: relPath(root, str(metadata.FilePath)) },
		evidence: resource || undefined,
		references: [`https://docs.kubelinter.io/#/generated/checks?id=${check}`],
		tags: ["kube-linter", check],
	};
};

/** Parses `kube-linter lint --format json` output. */
export const parseKubeLinterReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.Reports).flatMap((raw): FindingInput[] =>
		isRecord(raw) ? [kubeLinterFinding(raw, root)] : [],
	);
};

/** Wraps kube-linter, a Kubernetes manifest linter from StackRox. */
export const kubeLinter = defineAuditor({
	id: "iac.kube-linter",
	title: "kube-linter",
	description:
		"Runs kube-linter over plain Kubernetes manifests: privileged and root containers, host namespaces, missing resource limits and probes, mutable image tags, RBAC wildcards. Helm templates are skipped.",
	categories: ["security", "reliability", "best-practices"],
	targets: ["iac"],
	engine: "external",
	tool: "kube-linter",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, manifests: byFile } = yield* kubernetesManifests(ctx);
			const manifests = [...byFile.keys()];
			if (manifests.length === 0)
				return yield* skip("No Kubernetes manifests found");
			const bin = yield* requireTool(
				ctx,
				"kube-linter",
				"Install: brew install kube-linter or go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest (https://docs.kubelinter.io/#/?id=installing-kubelinter).",
			);
			// Exit 1 = lint errors found; the JSON report is still on stdout.
			const res = yield* runTool(
				ctx,
				[bin, "lint", "--format", "json", ...manifests.map((f) => `./${f}`)],
				ws.root,
				[0, 1],
			);
			return parseKubeLinterReport(
				yield* parseJson(res.stdout || "{}", "kube-linter"),
				ws.root,
			);
		}),
});
