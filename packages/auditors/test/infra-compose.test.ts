import { describe, expect, test } from "bun:test";

import { auditCompose, compose, parsePort } from "../src/infra/compose";
import { fixture, ruleIds, runAuditor } from "./helpers";

describe("container.compose", () => {
	test("flags insecure services", async () => {
		const report = await runAuditor(compose, fixture("infra", "docker-bad"));
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"container.compose/dangerous-capability",
			"container.compose/database-port-exposed",
			"container.compose/docker-socket",
			"container.compose/healthcheck-missing",
			"container.compose/image-latest",
			"container.compose/network-mode-host",
			"container.compose/pid-host",
			"container.compose/plaintext-secret",
			"container.compose/plaintext-secret",
			"container.compose/privileged",
			"container.compose/restart-missing",
			"container.compose/seccomp-unconfined",
		]);
		const findings = report.results[0]?.findings ?? [];
		const privileged = findings.find(
			(f) => f.ruleId === "container.compose/privileged",
		);
		expect(privileged?.location).toEqual({
			file: "docker-compose.yml",
			line: 4,
		});
		const port = findings.find(
			(f) => f.ruleId === "container.compose/database-port-exposed",
		);
		expect(port?.location?.line).toBe(19);
		expect(port?.evidence).toBe("5432:5432");
		for (const f of findings.filter(
			(f) => f.ruleId === "container.compose/plaintext-secret",
		)) {
			expect(f.evidence).not.toMatch(/supersecretvalue|example123x/);
		}
	});

	test("clean compose file passes", async () => {
		const report = await runAuditor(compose, fixture("infra", "docker-clean"));
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual([]);
	});

	test("skips directories without compose files", async () => {
		const report = await runAuditor(compose, fixture("infra", "docker-ignore"));
		expect(report.results[0]?.status).toBe("skipped");
	});

	test("parses short and long port syntax", () => {
		expect(parsePort("5432")).toEqual({ hostIp: undefined, container: 5432 });
		expect(parsePort("15432:5432/tcp")).toEqual({
			hostIp: undefined,
			container: 5432,
		});
		expect(parsePort("127.0.0.1:6379:6379")).toEqual({
			hostIp: "127.0.0.1",
			container: 6379,
		});
		expect(parsePort("[::1]:9200:9200")).toEqual({
			hostIp: "::1",
			container: 9200,
		});
		expect(parsePort({ target: 27017, published: 27017 })).toEqual({
			hostIp: undefined,
			container: 27017,
		});
	});

	test("long-syntax volumes, deploy restart policy and list env", () => {
		const text = [
			"services:",
			"  agent:",
			"    image: portainer/agent:2.21.0",
			"    deploy:",
			"      restart_policy:",
			"        condition: on-failure",
			"    healthcheck:",
			"      disable: true",
			"    volumes:",
			"      - type: bind",
			"        source: /var/run/docker.sock",
			"        target: /var/run/docker.sock",
			"    ports:",
			"      - target: 3306",
			"        published: 3306",
			"        host_ip: 127.0.0.1",
		].join("\n");
		const findings = auditCompose("compose.yaml", text);
		expect(findings.map((f) => f.ruleId)).toEqual([
			"container.compose/docker-socket",
		]);
		expect(findings[0]?.location?.line).toBe(10);
	});
});

test("environment interpolation is not a plaintext secret, a literal default is", async () => {
	const { isPlaceholderValue } = await import("../src/infra/shared");
	for (const v of [
		"$" + "{API_TOKEN}",
		"$" + "{API_TOKEN:?API_TOKEN is required}",
		"$" + "{API_TOKEN?missing}",
		"$" + "{API_TOKEN:-}",
		"$API_TOKEN",
	])
		expect(isPlaceholderValue(v)).toBe(true);
	for (const v of [
		"$" + "{API_TOKEN:-s3cr3t-value}",
		"$" + "{API_TOKEN-s3cr3t-value}",
		"s3cr3t-value",
	])
		expect(isPlaceholderValue(v)).toBe(false);
});
