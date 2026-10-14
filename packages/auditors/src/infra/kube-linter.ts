import {
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

/** Checks with a security impact, with a deliberate severity. */
const SECURITY: Record<string, Severity> = {
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

/** Parses `kube-linter lint --format json` output. */
export const parseKubeLinterReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.Reports).flatMap((raw): FindingInput[] => {
		if (!isRecord(raw)) return [];
		const check = str(raw.Check) ?? "unknown";
		const diagnostic = isRecord(raw.Diagnostic) ? raw.Diagnostic : {};
		const message = str(diagnostic.Message) ?? check;
		const object = isRecord(raw.Object) ? raw.Object : {};
		const metadata = isRecord(object.Metadata) ? object.Metadata : {};
		const k8s = isRecord(object.K8sObject) ? object.K8sObject : {};
		const gvk = isRecord(k8s.GroupVersionKind) ? k8s.GroupVersionKind : {};
		const resource = [str(gvk.Kind), str(k8s.Name)].filter(Boolean).join("/");
		const security = check in SECURITY;
		return [
			{
				ruleId: `iac.kube-linter/${kebab(check)}`,
				title: `${check}${resource ? `: ${resource}` : ""}`,
				severity: SECURITY[check] ?? (RELIABILITY.has(check) ? "low" : "info"),
				category: security
					? "security"
					: RELIABILITY.has(check)
						? "reliability"
						: "best-practices",
				message: truncate(message, 300),
				remediation:
					str(raw.Remediation) ?? "See the kube-linter check documentation.",
				// kube-linter reports no line numbers.
				location: { file: relPath(root, str(metadata.FilePath)) },
				evidence: resource || undefined,
				references: [
					`https://docs.kubelinter.io/#/generated/checks?id=${check}`,
				],
				tags: ["kube-linter", check],
			},
		];
	});
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
