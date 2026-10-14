import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	type HttpResponse,
} from "@openaudit/core";
import { Effect } from "effect";

import { fetchCached, sameOrigin, startPage } from "./page";
import { truncate } from "./util";

const OWASP_API =
	"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/";
const METHODS = ["get", "put", "post", "delete", "patch", "options", "head"];
const MUTATING = new Set(["put", "post", "delete", "patch"]);

const SPEC_PATHS = [
	"/openapi.json",
	"/swagger.json",
	"/v3/api-docs",
	"/api-docs",
] as const;
const SWAGGER_UI_PATH = "/swagger-ui/";
const GRAPHQL_PATH = "/graphql";
const OIDC_PATH = "/.well-known/openid-configuration";
const INTROSPECTION = "{__schema{queryType{name}}}";

/* -------------------------------------------------------------------------- */
/*                                  Parsers                                   */
/* -------------------------------------------------------------------------- */

type Json = Record<string, unknown>;

const isObject = (v: unknown): v is Json =>
	typeof v === "object" && v !== null && !Array.isArray(v);

export const parseJson = (body: string): Json | undefined => {
	try {
		const v: unknown = JSON.parse(body);
		return isObject(v) ? v : undefined;
	} catch {
		return undefined;
	}
};

export interface SpecSummary {
	readonly title: string | undefined;
	readonly version: string | undefined;
	readonly operations: number;
	/** Operations with no effective security requirement. */
	readonly unsecured: number;
	readonly unsecuredMutating: number;
	readonly hasSecuritySchemes: boolean;
	/**
	 * Every server the spec names (top level and path or operation
	 * overrides) is a loopback host, and every operation has one: the API is
	 * documented for a local or self-hosted deployment, not for this origin.
	 */
	readonly localOnly: boolean;
}

const nonEmptyArray = (v: unknown): boolean => Array.isArray(v) && v.length > 0;

/**
 * An absolute http(s) server URL on a loopback host: localhost, *.localhost,
 * 127.0.0.0/8 or [::1], as the WHATWG URL parser normalises them. Relative
 * URLs (the audited origin), templated hosts, private and public addresses
 * are not.
 */
export const isLoopbackServer = (url: unknown): boolean => {
	if (typeof url !== "string" || !URL.canParse(url)) return false;
	const { protocol, hostname } = new URL(url);
	if (protocol !== "http:" && protocol !== "https:") return false;
	return (
		hostname === "localhost" ||
		hostname.endsWith(".localhost") ||
		/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
		hostname === "[::1]"
	);
};

/** True when `servers` is a non-empty list of loopback server objects. */
const loopbackServers = (servers: unknown): boolean =>
	Array.isArray(servers) &&
	servers.length > 0 &&
	servers.every((s) => isObject(s) && isLoopbackServer(s.url));

/**
 * Summarises an OpenAPI 3 / Swagger 2 document. Returns `undefined` unless the
 * JSON really is a spec (version key plus `paths`), which is also what rules
 * out soft-404 pages and arbitrary JSON.
 */
export const summarizeSpec = (doc: Json): SpecSummary | undefined => {
	const isSpec =
		(typeof doc.openapi === "string" || typeof doc.swagger === "string") &&
		isObject(doc.paths);
	if (!isSpec || !isObject(doc.paths)) return undefined;
	const info = isObject(doc.info) ? doc.info : {};
	const globalSecurity = nonEmptyArray(doc.security);
	const components = isObject(doc.components) ? doc.components : {};
	const hasSecuritySchemes =
		(isObject(components.securitySchemes) &&
			Object.keys(components.securitySchemes).length > 0) ||
		(isObject(doc.securityDefinitions) &&
			Object.keys(doc.securityDefinitions).length > 0);
	let operations = 0;
	let unsecured = 0;
	let unsecuredMutating = 0;
	// Any server list that is present must be all loopback; each operation's
	// effective list (operation, else path, else top level) must exist.
	let localOnly = !("servers" in doc) || loopbackServers(doc.servers);
	for (const item of Object.values(doc.paths)) {
		if (!isObject(item)) continue;
		if ("servers" in item && !loopbackServers(item.servers)) localOnly = false;
		for (const method of METHODS) {
			const op = item[method];
			if (!isObject(op)) continue;
			operations++;
			if ("servers" in op && !loopbackServers(op.servers)) localOnly = false;
			const effective = op.servers ?? item.servers ?? doc.servers;
			if (!loopbackServers(effective)) localOnly = false;
			// An operation-level `security` replaces the global one; `[]` opts out.
			const secured =
				"security" in op ? nonEmptyArray(op.security) : globalSecurity;
			if (!secured) {
				unsecured++;
				if (MUTATING.has(method)) unsecuredMutating++;
			}
		}
	}
	return {
		title: typeof info.title === "string" ? info.title : undefined,
		version: typeof info.version === "string" ? info.version : undefined,
		operations,
		unsecured,
		unsecuredMutating,
		hasSecuritySchemes,
		localOnly: localOnly && operations > 0,
	};
};

/** Swagger UI / Redoc style landing page. */
export const looksLikeSwaggerUi = (res: HttpResponse): boolean =>
	res.status === 200 &&
	/text\/html/i.test(res.headers.get("content-type") ?? "") &&
	/<title>[^<]*Swagger UI[^<]*<\/title>|SwaggerUIBundle|swagger-ui-bundle|id=["']swagger-ui["']/i.test(
		res.body,
	);

/** A GraphQL JSON response, whatever its status. */
const graphqlBody = (res: HttpResponse): Json | undefined => {
	const json = parseJson(res.body);
	return json && ("data" in json || "errors" in json) ? json : undefined;
};

export const introspectionEnabled = (res: HttpResponse): boolean => {
	const data = graphqlBody(res)?.data;
	if (!isObject(data) || !isObject(data.__schema)) return false;
	return isObject(data.__schema.queryType);
};

/* -------------------------------------------------------------------------- */
/*                                   Auditor                                  */
/* -------------------------------------------------------------------------- */

/** True when `res` is the same page the server returns for any unknown path. */
const sameAsBaseline = (
	res: HttpResponse,
	baseline: HttpResponse | undefined,
): boolean =>
	baseline !== undefined &&
	baseline.status === res.status &&
	baseline.body === res.body;

export const apiExposure = defineAuditor({
	id: "web.api-exposure",
	title: "Exposed API surface",
	description:
		"Looks for public OpenAPI/Swagger documents, Swagger UI, GraphQL introspection and OpenID discovery with a handful of GET requests, ignoring catch-all pages that answer 200 everywhere.",
	categories: ["security"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx: AuditContext) =>
		Effect.gen(function* () {
			const start = yield* startPage(ctx);
			const origin = new URL(start.url).origin;
			const findings: FindingInput[] = [];

			const get = (path: string, accept = "application/json, text/html") =>
				fetchCached(ctx, `${origin}${path}`, {
					headers: { accept },
					timeoutMs: 8_000,
					maxBytes: 2 * 1024 * 1024,
				}).pipe(
					// Redirects to another site say nothing about this site.
					Effect.filterOrFail((res) => sameOrigin(res.url, origin)),
					Effect.option,
				);

			// What the server says about a path that cannot exist.
			const baseline = yield* get(
				`/openaudit-${Date.now().toString(36)}-not-found`,
			);
			const base = baseline._tag === "Some" ? baseline.value : undefined;

			/* ---------------------------- OpenAPI documents --------------------------- */
			const specs = yield* Effect.forEach(
				SPEC_PATHS,
				(path) => Effect.map(get(path), (res) => ({ path, res })),
				{ concurrency: 3 },
			);
			for (const { path, res } of specs) {
				if (res._tag === "None") continue;
				const r = res.value;
				if (r.status !== 200 || sameAsBaseline(r, base)) continue;
				const json = parseJson(r.body);
				const summary = json ? summarizeSpec(json) : undefined;
				if (!summary) continue;
				const url = `${origin}${path}`;
				const name = [summary.title, summary.version].filter(Boolean).join(" ");
				findings.push({
					ruleId: "web.api-exposure/openapi-spec-exposed",
					title: "API specification is publicly readable",
					severity: "info",
					category: "security",
					message: `${url} serves the API description${name ? ` for "${name}"` : ""} with ${summary.operations} operation(s). It maps the whole attack surface, including internal or undocumented endpoints. This is intended for public APIs but often unintended for internal ones.`,
					location: { url },
					evidence: truncate(
						`${r.headers.get("content-type") ?? "?"}; ${summary.operations} operations`,
						120,
					),
					remediation:
						"Serve API documentation only to authenticated users or internal networks unless the API is meant to be public.",
					references: [OWASP_API],
					tags: ["api", "cwe-200", "owasp-api8"],
				});
				const declared = `The specification at ${url} lists ${summary.unsecured} operation(s) with no security requirement${summary.unsecuredMutating > 0 ? `, ${summary.unsecuredMutating} of them state-changing (POST/PUT/PATCH/DELETE)` : ""}${summary.hasSecuritySchemes ? "" : " and defines no security schemes at all"}.`;
				if (summary.unsecured > 0)
					findings.push({
						ruleId: "web.api-exposure/openapi-operations-without-security",
						title: `${summary.unsecured} of ${summary.operations} documented operations declare no security`,
						// Only loopback servers: documented for a local deployment.
						severity: summary.localOnly
							? "info"
							: summary.unsecuredMutating > 0 && !summary.hasSecuritySchemes
								? "medium"
								: "low",
						category: "security",
						message: summary.localOnly
							? `${declared} Every server it names is a loopback address, so the operations are documented for a local or self-hosted deployment and are not served at this origin. Anyone who exposes that deployment beyond the local machine should put authentication in front of it.`
							: `${declared} This reflects what the document declares, not what the server enforces, so verify each endpoint.`,
						location: { url },
						evidence: `${summary.unsecured}/${summary.operations} operations without security; ${summary.unsecuredMutating} mutating`,
						remediation: summary.localOnly
							? "Nothing to change at this origin. Where the API is deployed beyond loopback, put authentication in front of it and declare that scheme in the specification."
							: "Declare a security scheme and apply it globally, opting individual public operations out explicitly, and enforce authentication on the server.",
						references: [
							"https://swagger.io/docs/specification/v3_0/authentication/",
							OWASP_API,
						],
						tags: ["api", "authentication", "owasp-api2"],
						confidence: "low",
					});
				// One spec is enough; the others are usually aliases.
				break;
			}

			/* -------------------------------- Swagger UI ------------------------------- */
			const ui = yield* get(SWAGGER_UI_PATH, "text/html");
			if (
				ui._tag === "Some" &&
				!sameAsBaseline(ui.value, base) &&
				looksLikeSwaggerUi(ui.value)
			)
				findings.push({
					ruleId: "web.api-exposure/swagger-ui-exposed",
					title: "Swagger UI is publicly accessible",
					severity: "low",
					category: "security",
					message: `${origin}${SWAGGER_UI_PATH} serves an interactive API console. Visitors can browse and call every documented endpoint from the browser.`,
					location: { url: `${origin}${SWAGGER_UI_PATH}` },
					evidence: truncate(
						ui.value.body.match(/<title>[^<]*<\/title>/i)?.[0] ??
							"Swagger UI bundle",
						100,
					),
					remediation:
						"Disable Swagger UI in production or restrict it to authenticated users and internal networks.",
					references: [OWASP_API],
					tags: ["api", "cwe-200", "owasp-api8"],
				});

			/* --------------------------------- GraphQL --------------------------------- */
			const gql = yield* get(
				`${GRAPHQL_PATH}?query=${encodeURIComponent(INTROSPECTION)}`,
			);
			if (gql._tag === "Some" && !sameAsBaseline(gql.value, base)) {
				const url = `${origin}${GRAPHQL_PATH}`;
				const body = graphqlBody(gql.value);
				const introspective = introspectionEnabled(gql.value);
				if (introspective)
					findings.push({
						ruleId: "web.api-exposure/graphql-introspection-enabled",
						title: "GraphQL introspection is enabled",
						severity: "medium",
						category: "security",
						message: `${url} answered an unauthenticated introspection query with its schema root. Introspection lets anyone enumerate every type, query and mutation, including ones the frontend never uses.`,
						location: { url },
						evidence: `GET ${GRAPHQL_PATH}?query=${INTROSPECTION} → __schema.queryType present`,
						remediation:
							"Disable introspection in production (or require authentication for it) and add field-level authorization.",
						references: [
							"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
							OWASP_API,
						],
						tags: ["api", "graphql", "cwe-200"],
					});
				if (body) {
					// Introspection proves GET works; otherwise ask the cheapest valid query.
					const getsWork =
						introspective ||
						(yield* Effect.map(
							get(
								`${GRAPHQL_PATH}?query=${encodeURIComponent("{__typename}")}`,
							),
							(r) => {
								const data =
									r._tag === "Some" ? graphqlBody(r.value)?.data : undefined;
								return isObject(data) && typeof data.__typename === "string";
							},
						));
					if (getsWork)
						findings.push({
							ruleId: "web.api-exposure/graphql-get-queries",
							title: "GraphQL endpoint accepts queries over GET",
							severity: "info",
							category: "security",
							message: `${url} executes queries sent as a URL parameter. GET requests are exempt from many CSRF defences and end up in logs and caches; this becomes a CSRF risk if mutations are also accepted over GET (not tested).`,
							location: { url },
							evidence: `GET ${GRAPHQL_PATH}?query={__typename} → data`,
							remediation:
								"Accept only POST (application/json) for mutations, and reject GET for anything but persisted queries; require a custom header or CSRF token on cookie-authenticated endpoints.",
							references: [
								"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
							],
							tags: ["api", "graphql", "csrf"],
							confidence: "low",
						});
				}
			}

			/* ------------------------------ OpenID discovery ------------------------------ */
			const oidc = yield* get(OIDC_PATH);
			if (oidc._tag === "Some" && oidc.value.status === 200) {
				const json = parseJson(oidc.value.body);
				if (
					json &&
					typeof json.issuer === "string" &&
					(json.authorization_endpoint ?? json.jwks_uri ?? json.token_endpoint)
				)
					findings.push({
						ruleId: "web.api-exposure/openid-configuration",
						title: "OpenID Connect discovery document is public",
						severity: "info",
						category: "security",
						message: `${origin}${OIDC_PATH} advertises issuer ${json.issuer}. The document is public by design; it is listed so the identity provider and its endpoints are part of your attack-surface inventory.`,
						location: { url: `${origin}${OIDC_PATH}` },
						evidence: `issuer=${truncate(json.issuer, 100)}`,
						remediation:
							"No action needed if this server is an identity provider. Otherwise check that it was meant to be exposed.",
						references: [
							"https://openid.net/specs/openid-connect-discovery-1_0.html",
						],
						tags: ["api", "oidc"],
					});
			}

			return findings;
		}),
});
