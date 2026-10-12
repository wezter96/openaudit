import { describe, expect, test } from "bun:test";

import { auditManifest, kubernetes } from "../src/infra/kubernetes";
import { fixture, ruleIds, runAuditor } from "./helpers";

describe("iac.kubernetes", () => {
	test("flags insecure workloads, services and RBAC (and skips Helm templates)", async () => {
		const report = await runAuditor(kubernetes, fixture("infra", "k8s-bad"));
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"iac.kubernetes/capabilities-not-dropped",
			"iac.kubernetes/dangerous-capability",
			"iac.kubernetes/host-network",
			"iac.kubernetes/host-path-volume",
			"iac.kubernetes/image-mutable-tag",
			"iac.kubernetes/privilege-escalation-allowed",
			"iac.kubernetes/privileged-container",
			"iac.kubernetes/probes-missing",
			"iac.kubernetes/rbac-wildcard",
			"iac.kubernetes/resources-missing",
			"iac.kubernetes/run-as-root",
			"iac.kubernetes/secret-in-env",
			"iac.kubernetes/service-account-token-automount",
			"iac.kubernetes/service-exposed",
			"iac.kubernetes/writable-root-filesystem",
		]);
		const findings = report.results[0]?.findings ?? [];
		expect(findings.every((f) => f.location?.file === "app.yaml")).toBe(true);
		const secret = findings.find((f) => f.ruleId.endsWith("/secret-in-env"));
		expect(secret?.location?.line).toBe(19);
		expect(secret?.evidence).not.toContain("hunter2-not-real");
		expect(
			findings.find((f) => f.ruleId.endsWith("/host-path-volume"))?.severity,
		).toBe("high");
	});

	test("passes a hardened deployment", async () => {
		const report = await runAuditor(kubernetes, fixture("infra", "k8s-clean"));
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual([]);
	});

	test("skips Helm templates and invalid YAML without erroring", () => {
		expect(
			auditManifest("t.yaml", "kind: Pod\nmetadata:\n  name: {{ .Values.x }}"),
		).toEqual([]);
		expect(auditManifest("bad.yaml", "kind: Pod\n  : : [unclosed")).toEqual([]);
	});

	test("resolves CronJob pod specs and skips probes for batch workloads", () => {
		const findings = auditManifest(
			"cron.yaml",
			[
				"apiVersion: batch/v1",
				"kind: CronJob",
				"metadata:",
				"  name: nightly",
				"spec:",
				"  jobTemplate:",
				"    spec:",
				"      template:",
				"        spec:",
				"          hostPID: true",
				"          containers:",
				"            - name: job",
				"              image: busybox",
			].join("\n"),
		);
		const ids = findings.map((f) => f.ruleId);
		expect(ids).toContain("iac.kubernetes/host-pid");
		expect(ids).toContain("iac.kubernetes/image-mutable-tag");
		expect(ids).not.toContain("iac.kubernetes/probes-missing");
		expect(
			findings.find((f) => f.ruleId === "iac.kubernetes/host-pid")?.location
				?.line,
		).toBe(10);
	});
});
