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

	test("a spec is local only when every server is a loopback host", () => {
		const withServers = (
			servers: unknown,
			extra: Record<string, unknown> = {},
		) =>
			summarizeSpec({
				openapi: "3.1.0",
				info: { title: "Self-hosted", version: "1" },
				...(servers === undefined ? {} : { servers }),
				paths: { "/audit": { post: { responses: {} } } },
				...extra,
			})?.localOnly;
		const local = (...urls: string[]) => urls.map((url) => ({ url }));

		expect(
			withServers(
				local(
					"http://localhost:3000/api-reference",
					"http://127.0.0.1:8080",
					"http://127.1.2.3/",
					"http://[::1]:7337",
					"https://api.localhost",
				),
			),
		).toBe(true);
		// Any public, private or unknown host keeps the operations in scope.
		expect(
			withServers(local("http://localhost:3000", "https://api.example.com")),
		).toBe(false);
		expect(withServers(local("http://127.0.0.1.evil.com"))).toBe(false);
		expect(withServers(local("http://192.168.1.10:3000"))).toBe(false);
		expect(withServers(local("http://10.0.0.5"))).toBe(false);
		// A relative URL is the audited origin itself.
		expect(withServers(local("/"))).toBe(false);
		expect(withServers(local("/api"))).toBe(false);
		expect(withServers(local("http://{host}:3000"))).toBe(false);
		expect(withServers(local("ftp://localhost/"))).toBe(false);
		expect(withServers([{ description: "no url" }])).toBe(false);
		expect(withServers(undefined)).toBe(false);
		expect(withServers([])).toBe(false);
		// Path- and operation-level overrides count too.
		expect(
			withServers(local("http://localhost:3000"), {
				paths: {
					"/audit": {
						servers: local("https://api.example.com"),
						post: { responses: {} },
					},
				},
			}),
		).toBe(false);
		expect(
			withServers(local("http://localhost:3000"), {
				paths: {
					"/audit": {
						post: { responses: {}, servers: local("https://api.example.com") },
					},
				},
			}),
		).toBe(false);
		// Overrides alone are enough when every operation has a loopback one.
		expect(
			withServers(undefined, {
				paths: {
					"/audit": {
						servers: local("http://localhost:3000"),
						post: { responses: {} },
					},
				},
			}),
		).toBe(true);
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

	test("a spec for a loopback-only deployment is info, not medium", async () => {
		const spec = {
			...SPEC,
			security: undefined,
			components: undefined,
			servers: [{ url: "http://localhost:3000/api-reference" }],
		};
		const site = start(
			{
				"/": () => html("<html><body>hi</body></html>"),
				"/openapi.json": () => json(spec),
			},
			() => html("not found", 404),
		);
		const report = await runAuditor(apiExposure, site.url);
		const finding = report.results[0]?.findings.find(
			(f) =>
				f.ruleId === "web.api-exposure/openapi-operations-without-security",
		);
		expect(finding?.severity).toBe("info");
		expect(finding?.message).toContain("not served at this origin");

		// The same spec with one public server is back in scope.
		const publicSite = start(
			{
				"/": () => html("<html><body>hi</body></html>"),
				"/openapi.json": () =>
					json({
						...spec,
						servers: [...spec.servers, { url: "https://api.example.com" }],
					}),
			},
			() => html("not found", 404),
		);
		const again = await runAuditor(apiExposure, publicSite.url);
		const medium = again.results[0]?.findings.find(
			(f) =>
				f.ruleId === "web.api-exposure/openapi-operations-without-security",
		);
		expect(medium?.severity).toBe("medium");
		// Same rule id and fingerprint inputs either way.
		expect(medium?.ruleId).toBe(finding?.ruleId);
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
