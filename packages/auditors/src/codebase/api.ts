import { basename, dirname } from "node:path";
import {
	type AuditorError,
	type Confidence,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import { isMap, isSeq, LineCounter, parseDocument } from "yaml";

import {
	cweUrl,
	extOf,
	fullLineAt,
	isCommentLine,
	isFixturePath,
	isGeneratedPath,
	isLockfile,
	isRecord,
	isTestPath,
	languageOf,
	lineLocator,
	nonCodeMask,
	readTextFiles,
	scrubLine,
	truncate,
} from "./util";

/* -------------------------------------------------------------------------- */
/*                               spec discovery                               */
/* -------------------------------------------------------------------------- */

export type SpecKind = "openapi" | "swagger" | "asyncapi";

export interface SpecFile {
	readonly path: string;
	readonly text: string;
	readonly kind: SpecKind;
}

/** Specs are bigger than typical source files; still bounded. */
const MAX_SPEC_BYTES = 5 * 1024 * 1024;
/** Unnamed yaml/json files are only probed when they are small. */
const MAX_PROBE_BYTES = 1024 * 1024;
const MAX_PROBE_FILES = 600;
const MAX_SPECS = 25;

const SPEC_NAME = /^(openapi|swagger|asyncapi)[^/]*\.(ya?ml|json)$/i;
/** Top-level version key of a yaml block document or a (possibly minified) JSON one. */
const SPEC_KEY =
	/(?:^|[{,]\s*)["']?(openapi|swagger|asyncapi)["']?\s*:\s*["']?\d/m;
const NOT_A_SPEC = /(^|\/)(package(-lock)?|tsconfig[^/]*|composer|deno)\.json$/;

/**
 * Finds OpenAPI, Swagger and AsyncAPI documents: files named like a spec, plus
 * any other small yaml/json file whose top-level key is `openapi:`, `swagger:`
 * or `asyncapi:`. Reads through the workspace and caps size and count.
 */
export const findSpecFiles = (
	ws: Workspace,
	kinds: ReadonlyArray<SpecKind> = ["openapi", "swagger", "asyncapi"],
): Effect.Effect<ReadonlyArray<SpecFile>, AuditorError> =>
	Effect.gen(function* () {
		const all = yield* ws.files;
		const candidates = all.filter(
			(p) =>
				["yaml", "yml", "json"].includes(extOf(p)) &&
				!isLockfile(p) &&
				!NOT_A_SPEC.test(p) &&
				!isFixturePath(p) &&
				!isGeneratedPath(p) &&
				!/(^|\/)(node_modules|dist|build|\.git)\//.test(p),
		);
		const named = candidates.filter((p) => SPEC_NAME.test(basename(p)));
		const others = candidates
			.filter((p) => !SPEC_NAME.test(basename(p)))
			.slice(0, MAX_PROBE_FILES);
		const found: SpecFile[] = [];
		for (const path of [...named, ...others]) {
			if (found.length >= MAX_SPECS) break;
			const isNamed = SPEC_NAME.test(basename(path));
			const cap = isNamed ? MAX_SPEC_BYTES : MAX_PROBE_BYTES;
			const size = yield* ws.size(path).pipe(Effect.orElseSucceed(() => 0));
			if (size === 0 || size > cap) continue;
			const text = yield* ws
				.readText(path)
				.pipe(Effect.orElseSucceed(() => ""));
			const key = SPEC_KEY.exec(text)?.[1]?.toLowerCase();
			if (!key || text.includes("\u0000")) continue;
			if (!(kinds as ReadonlyArray<string>).includes(key)) continue;
			found.push({ path, text, kind: key as SpecKind });
		}
		return found;
	});

/* -------------------------------------------------------------------------- */
/*                                   helpers                                  */
/* -------------------------------------------------------------------------- */

type Path = ReadonlyArray<string | number>;

const API_TOP10 = "https://owasp.org/API-Security/editions/2023/en/";
const API_SLUGS: Readonly<Record<string, string>> = {
	api1: "0xa1-broken-object-level-authorization",
	api2: "0xa2-broken-authentication",
	api3: "0xa3-broken-object-property-level-authorization",
	api4: "0xa4-unrestricted-resource-consumption",
	api5: "0xa5-broken-function-level-authorization",
	api6: "0xa6-unrestricted-access-to-sensitive-business-flows",
	api7: "0xa7-server-side-request-forgery",
	api8: "0xa8-security-misconfiguration",
	api9: "0xa9-improper-inventory-management",
	api10: "0xaa-unsafe-consumption-of-apis",
};

/** OWASP API Security Top 10 (2023) page for an id such as `api2`. */
export const owaspApiUrl = (id: string) =>
	`${API_TOP10}${API_SLUGS[id] ?? ""}/`;

interface RuleSpec {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly confidence?: Confidence;
	readonly owasp: keyof typeof API_SLUGS;
	readonly cwe: number;
	readonly remediation: string;
	readonly category?: "security" | "best-practices";
}

const finding = (
	rule: RuleSpec,
	file: string,
	line: number | undefined,
	message: string,
	evidence: string,
	overrides: { severity?: Severity; title?: string } = {},
): FindingInput => ({
	ruleId: `code.api/${rule.id}`,
	title: truncate(overrides.title ?? rule.title, 120),
	severity: overrides.severity ?? rule.severity,
	category: rule.category ?? "security",
	message,
	location: { file, line },
	evidence: truncate(scrubLine(evidence), 200),
	remediation: rule.remediation,
	references: [owaspApiUrl(rule.owasp), cweUrl(rule.cwe)],
	confidence: rule.confidence ?? "high",
	tags: [`owasp-${rule.owasp}`, `cwe-${rule.cwe}`],
});

const R = {
	noAuth: {
		id: "operation-no-security",
		title: "API operation has no authentication requirement",
		severity: "medium",
		owasp: "api2",
		cwe: 306,
		remediation:
			"Declare a `security` requirement globally or on the operation. For intentionally public endpoints, document it with an explicit empty `security: []`.",
	},
	noSchemes: {
		id: "no-security-schemes",
		title: "API definition declares no security schemes",
		severity: "medium",
		owasp: "api2",
		cwe: 306,
		remediation:
			"Define `components.securitySchemes` (OAuth 2.0, OpenID Connect or bearer tokens) and reference them from `security`.",
	},
	httpServer: {
		id: "insecure-server-url",
		title: "API server is declared over plain HTTP",
		severity: "medium",
		owasp: "api8",
		cwe: 319,
		remediation:
			"Serve the API over HTTPS only and declare `https://` server URLs.",
	},
	keyInQuery: {
		id: "api-key-in-query",
		title: "API key is sent in the query string",
		severity: "medium",
		owasp: "api2",
		cwe: 598,
		remediation:
			"Send API keys in a header (`in: header`). Query strings end up in access logs, browser history and Referer headers.",
	},
	basic: {
		id: "http-basic-auth",
		title: "API uses HTTP basic authentication",
		severity: "low",
		owasp: "api2",
		cwe: 522,
		remediation:
			"Prefer OAuth 2.0 or short-lived bearer tokens. If basic auth stays, require TLS and rate limit attempts.",
	},
	sensitiveQuery: {
		id: "sensitive-query-param",
		title: "Sensitive value is passed as a query parameter",
		severity: "medium",
		owasp: "api2",
		cwe: 598,
		remediation:
			"Move credentials and tokens into a header or the request body so they are not logged in URLs.",
	},
	unboundedArray: {
		id: "unbounded-array-response",
		title: "List response has no size bound or pagination",
		severity: "low",
		confidence: "low",
		owasp: "api4",
		cwe: 770,
		category: "best-practices",
		remediation:
			"Add pagination parameters (`limit`/`offset` or a cursor) and `maxItems` on the array schema.",
	},
	massAssignment: {
		id: "request-body-additional-properties",
		title: "Request body accepts undeclared properties",
		severity: "info",
		confidence: "low",
		owasp: "api3",
		cwe: 915,
		remediation:
			"Set `additionalProperties: false` on request body objects and have the server bind only declared fields (mass assignment, OWASP API3).",
	},
	noAuthResponses: {
		id: "missing-auth-responses",
		title: "Secured operation does not document 401/403",
		severity: "info",
		confidence: "medium",
		owasp: "api2",
		cwe: 287,
		category: "best-practices",
		remediation:
			"Document `401` and `403` responses (or `default`) on secured operations so clients handle authentication failures.",
	},
} as const satisfies Record<string, RuleSpec>;

const METHODS = [
	"get",
	"put",
	"post",
	"delete",
	"options",
	"head",
	"patch",
	"trace",
] as const;
const WRITE_METHODS = new Set(["post", "put", "patch"]);

/** Paths that are public by design: health probes, login, docs, signup. */
const PUBLIC_PATH =
	/(^|\/)(health(z|check)?|ping|status|ready(z)?|live(z)?|version|metrics|login|logout|signin|sign-in|signup|sign-up|register|auth|token|oauth2?|authorize|callback|forgot-password|reset-password|openapi|swagger|docs|\.well-known|jwks)(\/|\.|$|\{)/i;

const SENSITIVE_PARAM =
	/^(password|passwd|pwd|pass|passphrase|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|session[_-]?id|sessionid|jwt|authorization|credentials?)$/i;
const API_KEY_PARAM = /^(api[_-]?key|apikey|key|access[_-]?key)$/i;
const PAGINATION_PARAM =
	/^(limit|offset|page|page[_-]?size|pagesize|per[_-]?page|perpage|size|cursor|after|before|next|next[_-]?token|page[_-]?token|skip|top|take|count|max|max[_-]?results|first|last|\$top|\$skip)$/i;

const LOCAL_HOST =
	/^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\]|::1|[^.]+\.local(host)?|host\.docker\.internal)$/i;

const isLocalHost = (host: string) =>
	LOCAL_HOST.test(host.replace(/:\d+$/, ""));

/* ------------------------------ yaml locator ------------------------------ */

interface ParsedSpec {
	readonly data: Record<string, unknown>;
	/** 1-based line of the key (or sequence item) at `path`, or its nearest ancestor. */
	readonly lineAt: (path: Path) => number | undefined;
}

const parseSpec = (text: string): ParsedSpec | undefined => {
	try {
		const lineCounter = new LineCounter();
		const doc = parseDocument(text, {
			lineCounter,
			uniqueKeys: false,
		});
		if (doc.errors.length > 0) return undefined;
		const data: unknown = doc.toJS({ maxAliasCount: 100 });
		if (!isRecord(data)) return undefined;
		const lineAt = (path: Path): number | undefined => {
			for (let n = path.length; n >= 0; n--) {
				const parent =
					n === 0 ? doc.contents : doc.getIn(path.slice(0, n - 1), true);
				const last = path[n - 1];
				let offset: number | undefined;
				if (n === 0) offset = doc.contents?.range?.[0];
				else if (isMap(parent)) {
					const pair = parent.items.find(
						(p) => isScalarLike(p.key) && String(p.key.value) === String(last),
					);
					offset = (pair?.key as { range?: number[] } | undefined)?.range?.[0];
				} else if (isSeq(parent) && typeof last === "number") {
					offset = (parent.items[last] as { range?: number[] } | undefined)
						?.range?.[0];
				}
				if (offset !== undefined) return lineCounter.linePos(offset).line;
			}
			return undefined;
		};
		return { data, lineAt };
	} catch {
		return undefined;
	}
};

const isScalarLike = (v: unknown): v is { value: unknown } =>
	typeof v === "object" && v !== null && "value" in v;

/* -------------------------------- $ref walk ------------------------------- */

const decodePointer = (s: string) =>
	decodeURIComponent(s).replace(/~1/g, "/").replace(/~0/g, "~");

/** Follows local `#/…` $refs (bounded); returns the target or the node itself. */
const deref = (root: Record<string, unknown>, node: unknown): unknown => {
	let cur = node;
	for (let i = 0; i < 8; i++) {
		if (!isRecord(cur) || typeof cur.$ref !== "string") return cur;
		if (!cur.$ref.startsWith("#/")) return cur;
		let next: unknown = root;
		for (const part of cur.$ref.slice(2).split("/")) {
			next = isRecord(next) ? next[decodePointer(part)] : undefined;
		}
		if (next === undefined) return cur;
		cur = next;
	}
	return cur;
};

const arrayOf = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** True when the schema (or a one-level allOf/items parent) is an unbounded array. */
const isArraySchema = (root: Record<string, unknown>, node: unknown) => {
	const s = deref(root, node);
	return isRecord(s) && s.type === "array" ? s : undefined;
};

/* -------------------------------------------------------------------------- */
/*                              OpenAPI / Swagger                             */
/* -------------------------------------------------------------------------- */

interface Operation {
	readonly path: string;
	readonly method: string;
	readonly node: Record<string, unknown>;
	readonly at: Path;
	readonly params: ReadonlyArray<{ name: string; in: string; at: Path }>;
}

const collectOperations = (
	data: Record<string, unknown>,
): ReadonlyArray<Operation> => {
	const ops: Operation[] = [];
	const paths = isRecord(data.paths) ? data.paths : {};
	for (const [p, item] of Object.entries(paths)) {
		const pathItem = deref(data, item);
		if (!isRecord(pathItem)) continue;
		const shared = arrayOf(pathItem.parameters);
		for (const method of METHODS) {
			const node = pathItem[method];
			if (!isRecord(node)) continue;
			const params: Operation["params"][number][] = [];
			const own = arrayOf(node.parameters);
			for (const [list, base] of [
				[shared, ["paths", p, "parameters"]],
				[own, ["paths", p, method, "parameters"]],
			] as const) {
				list.forEach((raw, i) => {
					const param = deref(data, raw);
					if (isRecord(param) && typeof param.name === "string")
						params.push({
							name: param.name,
							in: String(param.in ?? ""),
							at: [...base, i],
						});
				});
			}
			ops.push({ path: p, method, node, at: ["paths", p, method], params });
		}
	}
	return ops;
};

const securityRequirementsOf = (v: unknown): unknown[] | undefined =>
	Array.isArray(v) ? v : undefined;

const schemesOf = (data: Record<string, unknown>) => {
	const components = isRecord(data.components) ? data.components : {};
	const fromComponents = isRecord(components.securitySchemes)
		? components.securitySchemes
		: undefined;
	const swagger = isRecord(data.securityDefinitions)
		? data.securityDefinitions
		: undefined;
	return {
		defs: (fromComponents ?? swagger ?? {}) as Record<string, unknown>,
		at: fromComponents
			? (["components", "securitySchemes"] as const)
			: (["securityDefinitions"] as const),
	};
};

/** Audits one OpenAPI 3.x / Swagger 2.0 document. */
export const auditOpenApi = (file: string, text: string): FindingInput[] => {
	const spec = parseSpec(text);
	if (!spec) return [];
	const { data, lineAt } = spec;
	if (typeof data.openapi !== "string" && typeof data.swagger !== "string")
		return [];
	const out: FindingInput[] = [];
	const evidenceLine = (path: Path) => ({ line: lineAt(path) });
	const ops = collectOperations(data);
	const globalSecurity = securityRequirementsOf(data.security);
	const { defs, at: schemesAt } = schemesOf(data);

	/* servers */
	const servers = arrayOf(data.servers);
	servers.forEach((s, i) => {
		const url = isRecord(s) && typeof s.url === "string" ? s.url : undefined;
		if (!url || !/^http:\/\//i.test(url)) return;
		const host = url.replace(/^http:\/\//i, "").split(/[/?#]/)[0] ?? "";
		if (host.includes("{") || isLocalHost(host)) return;
		const ev = evidenceLine(["servers", i, "url"]);
		out.push(
			finding(
				R.httpServer,
				file,
				ev.line,
				`Server ${url} uses plain HTTP, so traffic (including credentials) can be read or modified in transit.`,
				`url: ${url}`,
			),
		);
	});
	const schemes = arrayOf(data.schemes).map(String);
	if (schemes.includes("http") && typeof data.host === "string") {
		if (!isLocalHost(data.host)) {
			const ev = evidenceLine(["schemes"]);
			out.push(
				finding(
					R.httpServer,
					file,
					ev.line,
					`The API is served over ${schemes.includes("https") ? "both HTTP and HTTPS" : "plain HTTP"} on ${data.host}.`,
					`schemes: [${schemes.join(", ")}]`,
					{ severity: schemes.includes("https") ? "low" : "medium" },
				),
			);
		}
	}

	/* security schemes */
	const schemeEntries = Object.entries(defs);
	if (schemeEntries.length === 0 && ops.length > 0) {
		out.push(
			finding(
				R.noSchemes,
				file,
				lineAt(["paths"]),
				"The definition has operations but declares no security schemes, so clients cannot know how to authenticate.",
				"no components.securitySchemes / securityDefinitions",
			),
		);
	}
	for (const [name, raw] of schemeEntries) {
		const scheme = deref(data, raw);
		if (!isRecord(scheme)) continue;
		const at = [...schemesAt, name];
		const ev = evidenceLine(at);
		if (scheme.type === "apiKey" && scheme.in === "query") {
			out.push(
				finding(
					R.keyInQuery,
					file,
					ev.line,
					`Security scheme "${name}" sends the API key in query parameter "${String(scheme.name ?? "")}".`,
					`securityScheme ${name} (apiKey in query: ${String(scheme.name ?? "")})`,
				),
			);
		}
		const basic =
			scheme.type === "basic" ||
			(scheme.type === "http" &&
				String(scheme.scheme ?? "").toLowerCase() === "basic");
		if (basic) {
			out.push(
				finding(
					R.basic,
					file,
					ev.line,
					`Security scheme "${name}" uses HTTP basic authentication, which sends the password with every request.`,
					`securityScheme ${name} (http basic)`,
				),
			);
		}
	}

	/* operations */
	for (const op of ops) {
		const label = `${op.method.toUpperCase()} ${op.path}`;
		const opSecurity = securityRequirementsOf(op.node.security);
		const effective = opSecurity ?? globalSecurity;
		const explicitPublic =
			effective !== undefined &&
			(effective.length === 0 ||
				effective.some((r) => isRecord(r) && Object.keys(r).length === 0));
		const looksPublic = PUBLIC_PATH.test(op.path);
		const evOp = evidenceLine(op.at);

		if (effective === undefined || effective.length === 0) {
			const sev: Severity = looksPublic
				? "info"
				: effective === undefined
					? "medium"
					: "low";
			out.push(
				finding(
					R.noAuth,
					file,
					evOp.line,
					effective === undefined
						? `${label} declares no security requirement (neither on the operation nor globally).`
						: `${label} explicitly disables authentication with an empty security list.`,
					label,
					{ severity: sev },
				),
			);
		}

		if (!explicitPublic && effective !== undefined && !looksPublic) {
			const responses = isRecord(op.node.responses) ? op.node.responses : {};
			const codes = Object.keys(responses);
			if (
				codes.length > 0 &&
				!codes.some((c) => c === "401" || c === "403" || c === "default")
			) {
				out.push(
					finding(
						R.noAuthResponses,
						file,
						lineAt([...op.at, "responses"]) ?? evOp.line,
						`${label} requires authentication but documents no 401 or 403 response.`,
						label,
					),
				);
			}
		}

		for (const p of op.params) {
			if (p.in !== "query") continue;
			if (SENSITIVE_PARAM.test(p.name) || API_KEY_PARAM.test(p.name)) {
				const ev = evidenceLine(p.at);
				out.push(
					finding(
						R.sensitiveQuery,
						file,
						ev.line ?? evOp.line,
						`${label} takes "${p.name}" as a query parameter; query strings are logged by proxies, servers and browsers.`,
						`${label} ?${p.name}=`,
					),
				);
			}
		}

		if (op.method === "get") {
			const hasPaging = op.params.some((p) => PAGINATION_PARAM.test(p.name));
			const responses = isRecord(op.node.responses) ? op.node.responses : {};
			for (const [code, raw] of Object.entries(responses)) {
				if (!/^2\d\d$/.test(code)) continue;
				const resp = deref(data, raw);
				if (!isRecord(resp)) continue;
				const content = isRecord(resp.content) ? resp.content : {};
				const schemas = [
					resp.schema,
					...Object.values(content).map((m) =>
						isRecord(m) ? m.schema : undefined,
					),
				];
				const unbounded = schemas.some((sch) => {
					const arrSchema = isArraySchema(data, sch);
					return arrSchema && arrSchema.maxItems === undefined && !hasPaging;
				});
				if (unbounded)
					out.push(
						finding(
							R.unboundedArray,
							file,
							lineAt([...op.at, "responses", code]) ?? evOp.line,
							`${label} returns an array with no maxItems and no pagination parameters; a large collection can exhaust server and client resources.`,
							`${label} -> ${code} array`,
						),
					);
			}
		}

		if (WRITE_METHODS.has(op.method)) {
			const bodies: unknown[] = [];
			const rb = deref(data, op.node.requestBody);
			if (isRecord(rb) && isRecord(rb.content))
				for (const m of Object.values(rb.content))
					if (isRecord(m)) bodies.push(m.schema);
			for (const raw of [
				...arrayOf(op.node.parameters),
				...arrayOf(
					isRecord(data.paths) &&
						isRecord((data.paths as Record<string, unknown>)[op.path])
						? (
								(data.paths as Record<string, unknown>)[op.path] as Record<
									string,
									unknown
								>
							).parameters
						: [],
				),
			]) {
				const param = deref(data, raw);
				if (isRecord(param) && param.in === "body") bodies.push(param.schema);
			}
			for (const sch of bodies) {
				const s = deref(data, sch);
				if (
					isRecord(s) &&
					(s.type === "object" || isRecord(s.properties)) &&
					isRecord(s.properties) &&
					Object.keys(s.properties).length > 0 &&
					s.additionalProperties !== false &&
					s.unevaluatedProperties !== false
				) {
					out.push(
						finding(
							R.massAssignment,
							file,
							lineAt([...op.at, "requestBody"]) ??
								lineAt([...op.at, "parameters"]) ??
								evOp.line,
							`The request body of ${label} does not set additionalProperties: false, so clients can send fields the API never declared.`,
							`${label} request body`,
						),
					);
					break;
				}
			}
		}
	}
	return out;
};

/* -------------------------------------------------------------------------- */
/*                               GraphQL servers                              */
/* -------------------------------------------------------------------------- */

const GRAPHQL_FILE =
	/@apollo\/server|apollo-server|graphql-yoga|@graphql-yoga|mercurius|express-graphql|graphql-http|@nestjs\/apollo|@nestjs\/mercurius/;
const GRAPHQL_SERVER_DEPS =
	/^(@apollo\/server|apollo-server(-[a-z]+)?|graphql-yoga|@graphql-yoga\/.+|mercurius|express-graphql|graphql-http|@nestjs\/apollo|@nestjs\/mercurius|graphql-helix)$/;
const GRAPHQL_LIMIT_DEPS =
	/^(graphql-depth-limit|graphql-query-complexity|graphql-validation-complexity|graphql-cost-analysis|graphql-armor|@escape\.tech\/graphql-armor.*|@envelop\/depth-limit|@graphile\/depth-limit|graphql-no-alias|@graphql-armor\/.+)$/;

interface CodeRule {
	readonly rule: RuleSpec;
	readonly pattern: RegExp;
	readonly message: string;
}

const G = {
	introspection: {
		id: "graphql-introspection-enabled",
		title: "GraphQL introspection is hard-coded on",
		severity: "low",
		confidence: "low",
		owasp: "api8",
		cwe: 200,
		remediation:
			"Disable introspection in production, e.g. `introspection: process.env.NODE_ENV !== 'production'`.",
	},
	introspectionDefault: {
		id: "graphql-introspection-default",
		title: "GraphQL server does not control introspection",
		severity: "info",
		confidence: "low",
		owasp: "api8",
		cwe: 200,
		remediation:
			"Yoga and Mercurius expose introspection by default. Add a plugin or validation rule that disables it in production.",
	},
	noLimit: {
		id: "graphql-no-depth-limit",
		title: "GraphQL server has no query depth or complexity limit",
		severity: "low",
		confidence: "low",
		owasp: "api4",
		cwe: 770,
		remediation:
			"Add graphql-depth-limit, graphql-query-complexity or @escape.tech/graphql-armor to reject abusive queries.",
	},
	csrf: {
		id: "graphql-csrf-prevention-disabled",
		title: "Apollo CSRF prevention is disabled",
		severity: "medium",
		confidence: "low",
		owasp: "api8",
		cwe: 352,
		remediation:
			"Remove `csrfPrevention: false` (it is on by default in Apollo Server 4) or require a preflight-triggering header.",
	},
	playground: {
		id: "graphql-playground-enabled",
		title: "GraphQL IDE is enabled unconditionally",
		severity: "low",
		confidence: "low",
		owasp: "api8",
		cwe: 489,
		remediation:
			"Enable GraphiQL / Playground only outside production, e.g. `graphiql: process.env.NODE_ENV !== 'production'`.",
	},
} as const satisfies Record<string, RuleSpec>;

const GRAPHQL_CODE_RULES: ReadonlyArray<CodeRule> = [
	{
		rule: G.introspection,
		pattern: /\bintrospection\s*:\s*true\b/g,
		message:
			"Introspection is set to true unconditionally, which lets anyone download the full schema.",
	},
	{
		rule: G.csrf,
		pattern: /\bcsrfPrevention\s*:\s*false\b/g,
		message:
			"CSRF prevention is turned off, so simple cross-site requests can run queries and mutations with the user's cookies.",
	},
	{
		rule: G.playground,
		pattern: /\b(?:playground|graphiql)\s*:\s*true\b/g,
		message:
			"A GraphQL IDE is enabled with a literal true, so it ships to production too.",
	},
];

const YOGA_OR_MERCURIUS = /\b(?:createYoga|mercurius)\s*[(,.]/g;
const INTROSPECTION_CONTROL =
	/introspection|NoSchemaIntrospectionCustomRule|useDisableIntrospection|graphql-armor|blockFieldSuggestions/i;

/** Audits one JS/TS source file for risky GraphQL server configuration. */
export const auditGraphqlSource = (
	file: string,
	text: string,
): FindingInput[] => {
	if (!GRAPHQL_FILE.test(text)) return [];
	const lineOf = lineLocator(text);
	const out: FindingInput[] = [];
	const mask = nonCodeMask(text, "js");
	for (const { rule, pattern, message } of GRAPHQL_CODE_RULES) {
		for (const m of text.matchAll(pattern)) {
			if (mask[m.index ?? 0]) continue;
			const line = fullLineAt(text, m.index ?? 0);
			if (isCommentLine(line)) continue;
			out.push(finding(rule, file, lineOf(m.index ?? 0), message, line));
		}
	}
	if (!INTROSPECTION_CONTROL.test(text)) {
		for (const m of text.matchAll(YOGA_OR_MERCURIUS)) {
			const line = fullLineAt(text, m.index ?? 0);
			if (isCommentLine(line) || /^\s*import\b|\brequire\(/.test(line))
				continue;
			out.push(
				finding(
					G.introspectionDefault,
					file,
					lineOf(m.index ?? 0),
					"The server is created without any introspection setting, so introspection stays enabled in every environment.",
					line,
				),
			);
			break;
		}
	}
	return out;
};

/** Audits one package.json for a GraphQL server without a depth/complexity limiter. */
export const auditGraphqlPackage = (
	file: string,
	text: string,
): FindingInput[] => {
	let pkg: unknown;
	try {
		pkg = JSON.parse(text);
	} catch {
		return [];
	}
	if (!isRecord(pkg)) return [];
	const deps = new Set<string>();
	for (const key of ["dependencies", "devDependencies", "peerDependencies"]) {
		const section = pkg[key];
		if (isRecord(section))
			for (const name of Object.keys(section)) deps.add(name);
	}
	const server = [...deps].find((d) => GRAPHQL_SERVER_DEPS.test(d));
	if (!server || [...deps].some((d) => GRAPHQL_LIMIT_DEPS.test(d))) return [];
	const idx = text.indexOf(`"${server}"`);
	return [
		finding(
			G.noLimit,
			file,
			idx >= 0 ? lineLocator(text)(idx) : undefined,
			`package.json depends on ${server} but on no query depth or complexity limiter, so deeply nested queries are accepted.`,
			`"${server}" without graphql-depth-limit / graphql-armor / graphql-query-complexity`,
		),
	];
};

/* -------------------------------------------------------------------------- */
/*                               REST framework                               */
/* -------------------------------------------------------------------------- */

const RATE_LIMIT_DEPS =
	/rate-?limit|throttl|express-brute|express-slow-down|limiter|bottleneck/i;
const AUTH_ROUTE =
	/\b(?:app|router|api|auth\w*|server)\s*\.\s*(?:post|all)\s*\(\s*(["'`])[^"'`\n]*(?:login|signin|sign-in|token|password|reset)[^"'`\n]*\1/gi;

const REST = {
	id: "login-no-rate-limit",
	title: "Login route without rate limiting",
	severity: "low",
	confidence: "low",
	owasp: "api2",
	cwe: 307,
	remediation:
		"Add express-rate-limit or rate-limiter-flexible to authentication routes to slow credential stuffing and brute force.",
} as const satisfies RuleSpec;

interface PackageInfo {
	readonly dir: string;
	readonly express: boolean;
	readonly limited: boolean;
}

const packageInfo = (path: string, text: string): PackageInfo | undefined => {
	try {
		const pkg: unknown = JSON.parse(text);
		if (!isRecord(pkg)) return undefined;
		const names: string[] = [];
		for (const key of ["dependencies", "devDependencies"]) {
			const section = pkg[key];
			if (isRecord(section)) names.push(...Object.keys(section));
		}
		const dir = dirname(path) === "." ? "" : dirname(path);
		return {
			dir,
			express: names.includes("express"),
			limited: names.some((n) => RATE_LIMIT_DEPS.test(n)),
		};
	} catch {
		return undefined;
	}
};

/* -------------------------------------------------------------------------- */
/*                                   auditor                                  */
/* -------------------------------------------------------------------------- */

const isScannableSource = (path: string) =>
	languageOf(path) === "js" &&
	!isTestPath(path) &&
	!isFixturePath(path) &&
	!isGeneratedPath(path) &&
	!/(^|\/)(node_modules|dist|build)\//.test(path);

export const api = defineAuditor({
	id: "code.api",
	title: "API definition and server configuration",
	description:
		"Checks OpenAPI/Swagger files (missing or weak authentication, HTTP servers, secrets in query strings, unbounded lists, mass assignment) and heuristically flags risky GraphQL server settings and unthrottled Express login routes. Tagged with OWASP API Security Top 10 (2023) ids.",
	categories: ["security", "best-practices"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const findings: FindingInput[] = [];

			const specs = yield* findSpecFiles(ws, ["openapi", "swagger"]);
			for (const spec of specs) {
				findings.push(...auditOpenApi(spec.path, spec.text));
			}

			const sources = yield* readTextFiles(ws, isScannableSource);
			for (const file of sources) {
				findings.push(...auditGraphqlSource(file.path, file.text));
			}

			const manifests = yield* readTextFiles(
				ws,
				(p) =>
					basename(p) === "package.json" &&
					!isFixturePath(p) &&
					!isTestPath(p) &&
					!/(^|\/)node_modules\//.test(p),
				{ limit: 200 },
			);
			const packages = new Map<string, PackageInfo>();
			for (const m of manifests) {
				findings.push(...auditGraphqlPackage(m.path, m.text));
				const info = packageInfo(m.path, m.text);
				if (info) packages.set(info.dir, info);
			}

			/* Express login routes without rate limiting, once per package. */
			const owner = (path: string): PackageInfo | undefined => {
				let dir = dirname(path) === "." ? "" : dirname(path);
				for (;;) {
					const hit = packages.get(dir);
					if (hit) return hit;
					if (dir === "") return undefined;
					dir = dirname(dir) === "." ? "" : dirname(dir);
				}
			};
			const limitedInCode = new Set<PackageInfo>();
			for (const file of sources) {
				const pkg = owner(file.path);
				if (pkg && /rate-?limit|throttle/i.test(file.text))
					limitedInCode.add(pkg);
			}
			const reported = new Set<PackageInfo>();
			for (const file of sources) {
				const pkg = owner(file.path);
				if (
					!pkg?.express ||
					pkg.limited ||
					limitedInCode.has(pkg) ||
					reported.has(pkg)
				)
					continue;
				AUTH_ROUTE.lastIndex = 0;
				const m = AUTH_ROUTE.exec(file.text);
				if (!m) continue;
				reported.add(pkg);
				const line = fullLineAt(file.text, m.index);
				findings.push(
					finding(
						REST,
						file.path,
						lineLocator(file.text)(m.index),
						"This Express app has an authentication route but no rate-limiting dependency or middleware, so credentials can be guessed at full speed.",
						line,
					),
				);
			}
			return findings;
		}),
});
