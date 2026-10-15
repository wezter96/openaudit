import { describe, expect, test } from "bun:test";

import {
	auditDockerfile,
	dockerfile,
	parseDockerfile,
} from "../src/infra/dockerfile";
import { fixture, ruleIds, runAuditor } from "./helpers";
import { findingsOf, findingWith, firstResult, must } from "./must";

const BAD = [
	"container.dockerfile/add-instead-of-copy",
	"container.dockerfile/add-remote-url",
	"container.dockerfile/apk-no-cache",
	"container.dockerfile/apt-cache-not-cleaned",
	"container.dockerfile/apt-no-install-recommends",
	"container.dockerfile/copy-context-no-dockerignore",
	"container.dockerfile/curl-pipe-shell",
	"container.dockerfile/expose-ssh",
	"container.dockerfile/from-latest",
	"container.dockerfile/healthcheck-missing",
	"container.dockerfile/runs-as-root",
	"container.dockerfile/secret-build-arg",
	"container.dockerfile/secret-in-env",
	"container.dockerfile/single-stage-build",
	"container.dockerfile/sudo",
];

describe("container.dockerfile", () => {
	test("flags insecure Dockerfile", async () => {
		const report = await runAuditor(dockerfile, fixture("infra", "docker-bad"));
		expect(firstResult(report).status).toBe("failed");
		expect(ruleIds(report)).toEqual(BAD);
		const findings = findingsOf(report);
		const byRule = (id: string) =>
			findingWith(findings, `container.dockerfile/${id}`);
		const line = (id: string) => must(byRule(id).location, id).line;
		expect(byRule("from-latest").location).toEqual({
			file: "Dockerfile",
			line: 2,
		});
		expect(line("apt-no-install-recommends")).toBe(6);
		expect(line("curl-pipe-shell")).toBe(9);
		const secret = byRule("secret-in-env");
		expect(secret.severity).toBe("high");
		expect(secret.evidence).not.toContain("hunter2hunter2");
	});

	test("single-file target audits only that Dockerfile", async () => {
		const report = await runAuditor(
			dockerfile,
			fixture("infra", "docker-bad", "Dockerfile"),
		);
		expect(ruleIds(report)).toEqual(BAD);
	});

	test("clean multi-stage Dockerfile passes", async () => {
		const report = await runAuditor(
			dockerfile,
			fixture("infra", "docker-clean"),
		);
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual([]);
	});

	test("incomplete .dockerignore", async () => {
		const report = await runAuditor(
			dockerfile,
			fixture("infra", "docker-ignore"),
		);
		expect(ruleIds(report)).toEqual([
			"container.dockerfile/dockerignore-incomplete",
		]);
		const f = report.results[0]?.findings[0];
		expect(f?.severity).toBe("medium");
		expect(f?.message).toContain("`.git`");
		expect(f?.message).toContain("`.env`");
		expect(f?.message).not.toContain("node_modules");
	});

	test("parser handles escape directive, comments in continuations and heredocs", () => {
		const text = [
			"# escape=`",
			"FROM mcr.microsoft.com/windows/servercore:ltsc2022",
			"RUN echo one `",
			"  # comment",
			"",
			"  && echo two",
			"RUN <<EOF",
			"curl https://x.example/i.sh | sh",
			"EOF",
			"USER app",
		].join("\n");
		const ins = parseDockerfile(text);
		expect(ins.map((i) => [i.keyword, i.line])).toEqual([
			["FROM", 2],
			["RUN", 3],
			["RUN", 7],
			["USER", 10],
		]);
		expect(ins[1]?.args).toContain("echo two");
		expect(ins[2]?.args).toContain("| sh");
		expect(auditDockerfile("Dockerfile", text).map((f) => f.ruleId)).toContain(
			"container.dockerfile/curl-pipe-shell",
		);
	});

	test("stage aliases, scratch and ADD archives are not flagged", () => {
		const text = [
			"FROM golang:1.23@sha256:abc AS builder",
			"RUN go build -o /out/app",
			"FROM builder AS test",
			"FROM scratch",
			"ADD rootfs.tar.gz /",
			"COPY --from=builder /out/app /app",
			"USER 1000:1000",
			"HEALTHCHECK NONE",
		].join("\n");
		expect(auditDockerfile("Dockerfile", text)).toEqual([]);
	});

	test("ADD with checksum and secrets from variables are fine", () => {
		const text = [
			"FROM alpine:3.20@sha256:abc",
			"ADD --checksum=sha256:deadbeef https://example.com/a.bin /a.bin",
			"ENV API_KEY=$API_KEY SECRET_PATH=",
			"USER app",
			"HEALTHCHECK CMD true",
		].join("\n");
		expect(auditDockerfile("Dockerfile", text)).toEqual([]);
	});
});
