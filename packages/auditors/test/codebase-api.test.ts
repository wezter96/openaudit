import { describe, expect, test } from "bun:test";

import {
	api,
	auditGraphqlPackage,
	auditGraphqlSource,
	auditOpenApi,
	owaspApiUrl,
} from "../src/codebase/api";
import { fixture, runAuditor } from "./helpers";

const rules = (
	findings: ReadonlyArray<{ ruleId: string; location?: { file?: string } }>,
	file?: string,
) =>
	findings
		.filter((f) => file === undefined || f.location?.file === file)
		.map((f) => f.ruleId.replace("code.api/", ""))
		.sort();

describe("code.api OpenAPI", () => {
	test("flags insecure patterns in a realistic spec", async () => {
		const report = await runAuditor(api, fixture("api"));
		const findings = report.results.flatMap((r) => r.findings);
		expect(report.results[0]?.status).toBe("failed");
		expect(rules(findings, "openapi.yaml")).toEqual([
			"api-key-in-query",
			"http-basic-auth",
			"insecure-server-url",
			"missing-auth-responses",
			"operation-no-security",
			"operation-no-security",
			"operation-no-security",
			"request-body-additional-properties",
			"sensitive-query-param",
			"sensitive-query-param",
			"unbounded-array-response",
		]);
	});

	test("severity depends on whether the path looks public", async () => {
		const report = await runAuditor(api, fixture("api"));
		const noAuth = report.results
			.flatMap((r) => r.findings)
			.filter(
				(f) =>
					f.ruleId === "code.api/operation-no-security" &&
					f.location?.file === "openapi.yaml",
			)
			.map((f) => `${f.evidence} ${f.severity}`)
			.sort();
		expect(noAuth).toEqual([
			"GET /health info",
			"GET /pets medium",
			"POST /login info",
		]);
	});

	test("locations point at the offending line", async () => {
		const report = await runAuditor(api, fixture("api"));
		const findings = report.results.flatMap((r) => r.findings);
		const server = findings.find(
			(f) =>
				f.ruleId === "code.api/insecure-server-url" &&
				f.location?.file === "openapi.yaml",
		);
		expect(server?.location?.line).toBe(6);
		expect(server?.evidence).toBe("url: http://api.pets.example.com/v1");
		const get = findings.find(
			(f) =>
				f.ruleId === "code.api/operation-no-security" &&
				f.evidence === "GET /pets",
		);
		expect(get?.location?.line).toBe(10);
	});

	test("localhost servers, bounded lists and hardened bodies are not flagged", async () => {
		const report = await runAuditor(api, fixture("api", "secure"));
		expect(report.results[0]?.findings).toEqual([]);
		expect(report.results[0]?.status).toBe("passed");
	});

	test("finds specs by content in any json/yaml file and handles Swagger 2", async () => {
		const report = await runAuditor(api, fixture("api", "spec-in-docs"));
		const findings = report.results.flatMap((r) => r.findings);
		expect(rules(findings)).toEqual([
			"insecure-server-url",
			"no-security-schemes",
			"operation-no-security",
		]);
		expect(findings.every((f) => f.location?.file === "docs/api.json")).toBe(
			true,
		);
	});

	test("findings carry OWASP API and CWE tags, references and remediation", async () => {
		const report = await runAuditor(api, fixture("api"));
		const f = report.results
			.flatMap((r) => r.findings)
			.find((x) => x.ruleId === "code.api/operation-no-security");
		expect(f?.tags).toEqual(["owasp-api2", "cwe-306"]);
		expect(f?.references?.[0]).toBe(owaspApiUrl("api2"));
		expect(f?.remediation).toContain("security");
		expect(report.results[0]?.categories).toContain("best-practices");
		const lists = report.results
			.flatMap((r) => r.findings)
			.find((x) => x.ruleId === "code.api/unbounded-array-response");
		expect(lists?.confidence).toBe("low");
	});

	test("ignores malformed documents", () => {
		expect(auditOpenApi("a.yaml", "openapi: [unclosed")).toEqual([]);
		expect(auditOpenApi("a.yaml", "- just\n- a list")).toEqual([]);
		expect(auditOpenApi("a.yaml", "name: not-a-spec")).toEqual([]);
	});

	test("resolves local $refs for parameters and bodies", () => {
		const spec = `
openapi: 3.0.0
security: [{k: []}]
paths:
  /a:
    post:
      parameters:
        - $ref: '#/components/parameters/Tok'
      requestBody:
        $ref: '#/components/requestBodies/B'
      responses: {"200": {description: ok}}
components:
  securitySchemes: {k: {type: apiKey, in: header, name: X}}
  parameters:
    Tok: {name: token, in: query, schema: {type: string}}
  requestBodies:
    B:
      content:
        application/json:
          schema: {type: object, properties: {a: {type: string}}}
`;
		expect(rules(auditOpenApi("s.yaml", spec))).toEqual([
			"missing-auth-responses",
			"request-body-additional-properties",
			"sensitive-query-param",
		]);
	});
});

describe("code.api GraphQL and REST heuristics", () => {
	test("flags hard-coded introspection, disabled CSRF protection and GraphiQL", async () => {
		const report = await runAuditor(api, fixture("api", "graphql"));
		const findings = report.results.flatMap((r) => r.findings);
		expect(rules(findings, "server.ts")).toEqual([
			"graphql-csrf-prevention-disabled",
			"graphql-introspection-enabled",
			"graphql-playground-enabled",
		]);
		expect(rules(findings, "package.json")).toEqual(["graphql-no-depth-limit"]);
		expect(findings.every((f) => f.confidence === "low")).toBe(true);
		const intro = findings.find(
			(f) => f.ruleId === "code.api/graphql-introspection-enabled",
		);
		expect(intro?.location?.line).toBe(8);
	});

	test("conditional introspection and commented code are not flagged", () => {
		const src = `import { ApolloServer } from "@apollo/server";
// introspection: true
new ApolloServer({ introspection: process.env.NODE_ENV !== "production" });`;
		expect(auditGraphqlSource("a.ts", src)).toEqual([]);
	});

	test("yoga without any introspection control gets an info finding", () => {
		const src = `import { createYoga } from "graphql-yoga";\nexport const y = createYoga({ schema });`;
		expect(rules(auditGraphqlSource("y.ts", src))).toEqual([
			"graphql-introspection-default",
		]);
		expect(
			auditGraphqlSource("y.ts", `${src}\nuseDisableIntrospection();`),
		).toEqual([]);
	});

	test("a depth limiter in package.json silences the missing-limit finding", () => {
		const base = {
			dependencies: { "graphql-yoga": "5", "graphql-depth-limit": "1" },
		};
		expect(auditGraphqlPackage("package.json", JSON.stringify(base))).toEqual(
			[],
		);
		expect(
			auditGraphqlPackage(
				"package.json",
				JSON.stringify({ dependencies: { express: "4" } }),
			),
		).toEqual([]);
		expect(auditGraphqlPackage("package.json", "{not json")).toEqual([]);
	});

	test("express login route without a rate limiter is flagged once", async () => {
		const report = await runAuditor(api, fixture("api", "rest"));
		const findings = report.results.flatMap((r) => r.findings);
		expect(rules(findings)).toEqual(["login-no-rate-limit"]);
		expect(findings[0]?.location).toEqual({ file: "app.js", line: 3 });
		expect(findings[0]?.tags).toEqual(["owasp-api2", "cwe-307"]);
	});
});
