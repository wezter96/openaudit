import { afterAll, describe, expect, test } from "bun:test";

import {
	apiExposure,
	introspectionEnabled,
	summarizeSpec,
} from "../src/web/api-exposure";
import { ruleIds, runAuditor } from "./helpers";
import { type Site, serve } from "./web-server";

const json = (body: unknown, status = 200) => Response.json(body, { status });
const html = (body: string, status = 200) =>
	new Response(body, {
		status,
		headers: { "content-type": "text/html; charset=utf-8" },
	});

const SPEC = {
	openapi: "3.0.3",
	info: { title: "Shop API", version: "1.2.0" },
	paths: {
		"/items": {
			get: { responses: {} },
			post: { responses: {} },
		},
		"/items/{id}": {
			get: { responses: {}, security: [{ key: [] }] },
			delete: { responses: {} },
		},
		"/health": { get: { security: [], responses: {} } },
	},
	components: { securitySchemes: { key: { type: "apiKey" } } },
	security: [{ key: [] }],
};

const sites: Site[] = [];
const start = (...args: Parameters<typeof serve>) => {
	const site = serve(...args);
	sites.push(site);
	return site;
};
afterAll(() => {
	for (const s of sites) s.stop();
});

describe("web.api-exposure parsing", () => {
	test("counts operations without effective security", () => {
		const summary = summarizeSpec(SPEC);
		expect(summary).toMatchObject({
			title: "Shop API",
			operations: 5,
			// Only the explicit `security: []` health check is unsecured; the
			// rest inherit the global requirement or declare their own.
			unsecured: 1,
			unsecuredMutating: 0,
			hasSecuritySchemes: true,
		});
		expect(summarizeSpec({ foo: 1, paths: {} })).toBeUndefined();
		expect(summarizeSpec({ openapi: "3.0.0" })).toBeUndefined();
	});

	test("introspection needs a real __schema answer", () => {
		const res = (body: unknown) =>
			({ body: JSON.stringify(body) }) as Parameters<
				typeof introspectionEnabled
			>[0];
		expect(
			introspectionEnabled(
				res({ data: { __schema: { queryType: { name: "Query" } } } }),
			),
		).toBe(true);
		expect(
			introspectionEnabled(
				res({ errors: [{ message: "introspection disabled" }] }),
			),
		).toBe(false);
		expect(introspectionEnabled(res({ data: null }))).toBe(false);
	});
});

describe("web.api-exposure on a local site", () => {
	test("finds spec, swagger UI, graphql and oidc", async () => {
		const site = start(
			{
				"/": () => html("<html><body>hi</body></html>"),
				"/openapi.json": () =>
					json({ ...SPEC, security: undefined, components: undefined }),
				"/swagger-ui/": () =>
					html(
						'<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>',
					),
				"/graphql": (req) => {
					const q = new URL(req.url).searchParams.get("query") ?? "";
					return q.includes("__schema")
						? json({ data: { __schema: { queryType: { name: "Query" } } } })
						: json({ data: { __typename: "Query" } });
				},
				"/.well-known/openid-configuration": () =>
					json({
						issuer: "https://id.example.com",
						authorization_endpoint: "https://id.example.com/auth",
					}),
			},
			() => html("not found", 404),
		);
		const report = await runAuditor(apiExposure, site.url);
		const findings = report.results[0]?.findings ?? [];
		expect(ruleIds(report)).toEqual([
			"web.api-exposure/graphql-get-queries",
			"web.api-exposure/graphql-introspection-enabled",
			"web.api-exposure/openapi-operations-without-security",
			"web.api-exposure/openapi-spec-exposed",
			"web.api-exposure/openid-configuration",
			"web.api-exposure/swagger-ui-exposed",
		]);
		const sev = (id: string) =>
			findings.find((f) => f.ruleId === `web.api-exposure/${id}`)?.severity;
		expect(sev("graphql-introspection-enabled")).toBe("medium");
		expect(sev("swagger-ui-exposed")).toBe("low");
		expect(sev("openapi-spec-exposed")).toBe("info");
		// Mutating operations with no security scheme at all.
		expect(sev("openapi-operations-without-security")).toBe("medium");
		// Low volume: baseline + 4 specs + ui + 2 graphql + oidc + start page.
		expect(site.requests.length).toBeLessThanOrEqual(12);
		expect(site.requests.every((r) => r.startsWith("GET"))).toBe(true);
	});

	test("a catch-all that answers 200 everywhere yields nothing", async () => {
		const page =
			'<html><title>Swagger UI</title><div id="swagger-ui"></div>{"openapi":"3.0.0","paths":{}}</html>';
		const site = start({}, () => html(page));
		const report = await runAuditor(apiExposure, site.url);
		expect(ruleIds(report)).toEqual([]);
	});

	test("graphql with introspection off and GET rejected reports nothing", async () => {
		const site = start(
			{
				"/graphql": () =>
					json(
						{ errors: [{ message: "GraphQL introspection is not allowed" }] },
						400,
					),
			},
			() => html("nope", 404),
		);
		const report = await runAuditor(apiExposure, site.url);
		expect(ruleIds(report)).toEqual([]);
	});

	test("graphql GET accepted without introspection is an info note", async () => {
		const site = start(
			{
				"/graphql": (req) => {
					const q = new URL(req.url).searchParams.get("query") ?? "";
					return q.includes("__schema")
						? json({ errors: [{ message: "introspection disabled" }] })
						: json({ data: { __typename: "Query" } });
				},
			},
			() => html("nope", 404),
		);
		const report = await runAuditor(apiExposure, site.url);
		expect(ruleIds(report)).toEqual(["web.api-exposure/graphql-get-queries"]);
	});
});
