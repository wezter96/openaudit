import type { FindingInput, Severity } from "@openaudit/core";
import { isMap, isSeq, LineCounter, parseDocument } from "yaml";

import {
	type FilePath,
	finding,
	type Path,
	type RuleSpec,
	type SourceText,
} from "./api-shared";
import { isRecord } from "./util";

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
const AUTH_RESPONSE_CODES = new Set(["401", "403", "default"]);

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

/** A server host such as `api.example.com:8080`. */
type Host = string;

const isLocalHost = (host: Host) => LOCAL_HOST.test(host.replace(/:\d+$/, ""));

/* ------------------------------ yaml locator ------------------------------ */

type YamlDocument = ReturnType<typeof parseDocument>;

interface ParsedSpec {
	readonly data: Record<string, unknown>;
	/** 1-based line of the key (or sequence item) at `path`, or its nearest ancestor. */
	readonly lineAt: (path: Path) => number | undefined;
}

const isScalarLike = (v: unknown): v is { value: unknown } =>
	typeof v === "object" && v !== null && "value" in v;

const rangeStart = (node: unknown): number | undefined =>
	(node as { range?: number[] } | undefined)?.range?.[0];

/** Offset of the key `last` in a yaml map, or of item `last` in a sequence. */
const childOffset = (
	parent: unknown,
	last: Path[number] | undefined,
): number | undefined => {
	if (isMap(parent)) {
		const pair = parent.items.find(
			(p) => isScalarLike(p.key) && String(p.key.value) === String(last),
		);
		return rangeStart(pair?.key);
	}
	if (isSeq(parent) && typeof last === "number")
		return rangeStart(parent.items[last]);
	return undefined;
};

/** Offset of the first `depth` segments of `path`; depth 0 is the document. */
const offsetAt = (doc: YamlDocument, path: Path, depth: number) =>
	depth === 0
		? rangeStart(doc.contents)
		: childOffset(doc.getIn(path.slice(0, depth - 1), true), path[depth - 1]);

const lineOfPath = (
	doc: YamlDocument,
	lineCounter: LineCounter,
	path: Path,
): number | undefined => {
	for (let depth = path.length; depth >= 0; depth--) {
		const offset = offsetAt(doc, path, depth);
		if (offset !== undefined) return lineCounter.linePos(offset).line;
	}
	return undefined;
};

const parseSpec = (text: SourceText): ParsedSpec | undefined => {
	try {
		const lineCounter = new LineCounter();
		const doc = parseDocument(text, {
			lineCounter,
			uniqueKeys: false,
		});
		if (doc.errors.length > 0) return undefined;
		const data: unknown = doc.toJS({ maxAliasCount: 100 });
		if (!isRecord(data)) return undefined;
		return { data, lineAt: (path) => lineOfPath(doc, lineCounter, path) };
	} catch {
		return undefined;
	}
};

/* -------------------------------- $ref walk ------------------------------- */

/** A local JSON pointer such as `#/components/schemas/User`. */
type Pointer = string;

const decodePointer = (s: Pointer) =>
	decodeURIComponent(s).replace(/~1/g, "/").replace(/~0/g, "~");

const resolvePointer = (
	root: Record<string, unknown>,
	ref: Pointer,
): unknown => {
	let next: unknown = root;
	for (const part of ref.slice(2).split("/")) {
		next = isRecord(next) ? next[decodePointer(part)] : undefined;
	}
	return next;
};

const localRefOf = (node: unknown): Pointer | undefined =>
	isRecord(node) && typeof node.$ref === "string" ? node.$ref : undefined;

/** Follows local `#/…` $refs (bounded); returns the target or the node itself. */
const deref = (root: Record<string, unknown>, node: unknown): unknown => {
	let cur = node;
	for (let i = 0; i < 8; i++) {
		const ref = localRefOf(cur);
		if (!ref?.startsWith("#/")) return cur;
		const next = resolvePointer(root, ref);
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

interface Parameter {
	readonly name: string;
	readonly in: string;
	readonly at: Path;
}

interface Operation {
	readonly path: string;
	readonly method: string;
	readonly node: Record<string, unknown>;
	readonly at: Path;
	readonly params: ReadonlyArray<Parameter>;
}

const parametersOf = (
	data: Record<string, unknown>,
	list: unknown[],
	base: Path,
): Parameter[] =>
	list.flatMap((raw, i) => {
		const param = deref(data, raw);
		return isRecord(param) && typeof param.name === "string"
			? [{ name: param.name, in: String(param.in ?? ""), at: [...base, i] }]
			: [];
	});

/** A key of the `paths` object, such as `/users/{id}`. */
type RoutePath = string;

const pathOperations = (
	data: Record<string, unknown>,
	p: RoutePath,
	item: unknown,
): Operation[] => {
	const pathItem = deref(data, item);
	if (!isRecord(pathItem)) return [];
	const shared = arrayOf(pathItem.parameters);
	const ops: Operation[] = [];
	for (const method of METHODS) {
		const node = pathItem[method];
		if (!isRecord(node)) continue;
		const params = [
			...parametersOf(data, shared, ["paths", p, "parameters"]),
			...parametersOf(data, arrayOf(node.parameters), [
				"paths",
				p,
				method,
				"parameters",
			]),
		];
		ops.push({ path: p, method, node, at: ["paths", p, method], params });
	}
	return ops;
};

const collectOperations = (
	data: Record<string, unknown>,
): ReadonlyArray<Operation> => {
	const paths = isRecord(data.paths) ? data.paths : {};
	return Object.entries(paths).flatMap(([p, item]) =>
		pathOperations(data, p, item),
	);
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

/** One parsed spec document plus the file it came from. */
interface SpecContext extends ParsedSpec {
	readonly file: FilePath;
}

/* --------------------------------- servers -------------------------------- */

/** The server's URL when it is plain HTTP on a non-local host. */
const insecureServerUrl = (server: unknown): string | undefined => {
	const url =
		isRecord(server) && typeof server.url === "string" ? server.url : undefined;
	if (!url || !/^http:\/\//i.test(url)) return undefined;
	const host = url.replace(/^http:\/\//i, "").split(/[/?#]/)[0] ?? "";
	if (host.includes("{") || isLocalHost(host)) return undefined;
	return url;
};

const serverFindings = (ctx: SpecContext): FindingInput[] =>
	arrayOf(ctx.data.servers).flatMap((server, i) => {
		const url = insecureServerUrl(server);
		if (!url) return [];
		return [
			finding(R.httpServer, {
				file: ctx.file,
				line: ctx.lineAt(["servers", i, "url"]),
				message: `Server ${url} uses plain HTTP, so traffic (including credentials) can be read or modified in transit.`,
				evidence: `url: ${url}`,
			}),
		];
	});

/** Swagger 2.0 `schemes` + `host` that include plain HTTP. */
const swaggerSchemeFindings = (ctx: SpecContext): FindingInput[] => {
	const schemes = arrayOf(ctx.data.schemes).map(String);
	const host = ctx.data.host;
	if (!schemes.includes("http") || typeof host !== "string") return [];
	if (isLocalHost(host)) return [];
	const alsoHttps = schemes.includes("https");
	return [
		finding(R.httpServer, {
			file: ctx.file,
			line: ctx.lineAt(["schemes"]),
			message: `The API is served over ${alsoHttps ? "both HTTP and HTTPS" : "plain HTTP"} on ${host}.`,
			evidence: `schemes: [${schemes.join(", ")}]`,
			severity: alsoHttps ? "low" : "medium",
		}),
	];
};

/* ---------------------------- security schemes ---------------------------- */

interface NamedScheme {
	readonly name: string;
	readonly scheme: Record<string, unknown>;
	readonly line: number | undefined;
}

const isHttpBasic = (scheme: Record<string, unknown>) =>
	scheme.type === "http" &&
	String(scheme.scheme ?? "").toLowerCase() === "basic";

const isBasicScheme = (scheme: Record<string, unknown>) =>
	scheme.type === "basic" || isHttpBasic(scheme);

const schemeFindings = (
	ctx: SpecContext,
	{ name, scheme, line }: NamedScheme,
): FindingInput[] => {
	const out: FindingInput[] = [];
	if (scheme.type === "apiKey" && scheme.in === "query") {
		out.push(
			finding(R.keyInQuery, {
				file: ctx.file,
				line,
				message: `Security scheme "${name}" sends the API key in query parameter "${String(scheme.name ?? "")}".`,
				evidence: `securityScheme ${name} (apiKey in query: ${String(scheme.name ?? "")})`,
			}),
		);
	}
	if (isBasicScheme(scheme)) {
		out.push(
			finding(R.basic, {
				file: ctx.file,
				line,
				message: `Security scheme "${name}" uses HTTP basic authentication, which sends the password with every request.`,
				evidence: `securityScheme ${name} (http basic)`,
			}),
		);
	}
	return out;
};

const securitySchemeFindings = (
	ctx: SpecContext,
	hasOperations: boolean,
): FindingInput[] => {
	const { defs, at } = schemesOf(ctx.data);
	const entries = Object.entries(defs);
	const out: FindingInput[] = [];
	if (entries.length === 0 && hasOperations) {
		out.push(
			finding(R.noSchemes, {
				file: ctx.file,
				line: ctx.lineAt(["paths"]),
				message:
					"The definition has operations but declares no security schemes, so clients cannot know how to authenticate.",
				evidence: "no components.securitySchemes / securityDefinitions",
			}),
		);
	}
	for (const [name, raw] of entries) {
		const scheme = deref(ctx.data, raw);
		if (!isRecord(scheme)) continue;
		const line = ctx.lineAt([...at, name]);
		out.push(...schemeFindings(ctx, { name, scheme, line }));
	}
	return out;
};

/* ------------------------------- operations ------------------------------- */

/** One operation with what every per-operation check needs. */
interface OperationScope {
	readonly ctx: SpecContext;
	readonly op: Operation;
	/** `GET /users`. */
	readonly label: string;
	/** Line of the operation itself, the fallback location. */
	readonly line: number | undefined;
	/** Security requirements of the operation, else the global ones. */
	readonly effective: unknown[] | undefined;
	readonly looksPublic: boolean;
}

const isEmptyRequirement = (r: unknown) =>
	isRecord(r) && Object.keys(r).length === 0;

/** An empty list, or an empty `{}` alternative, allows anonymous calls. */
const allowsAnonymous = (requirements: unknown[]) =>
	requirements.length === 0 || requirements.some(isEmptyRequirement);

const noAuthSeverity = (s: OperationScope): Severity => {
	if (s.looksPublic) return "info";
	return s.effective === undefined ? "medium" : "low";
};

const noAuthFindings = (s: OperationScope): FindingInput[] => {
	if (s.effective?.length) return [];
	return [
		finding(R.noAuth, {
			file: s.ctx.file,
			line: s.line,
			message:
				s.effective === undefined
					? `${s.label} declares no security requirement (neither on the operation nor globally).`
					: `${s.label} explicitly disables authentication with an empty security list.`,
			evidence: s.label,
			severity: noAuthSeverity(s),
		}),
	];
};

const responsesOf = (op: Operation) =>
	isRecord(op.node.responses) ? op.node.responses : {};

const requiresAuth = (s: OperationScope) =>
	s.effective !== undefined && !allowsAnonymous(s.effective);

const authResponseFindings = (s: OperationScope): FindingInput[] => {
	if (!requiresAuth(s) || s.looksPublic) return [];
	const codes = Object.keys(responsesOf(s.op));
	if (codes.length === 0) return [];
	if (codes.some((c) => AUTH_RESPONSE_CODES.has(c))) return [];
	return [
		finding(R.noAuthResponses, {
			file: s.ctx.file,
			line: s.ctx.lineAt([...s.op.at, "responses"]) ?? s.line,
			message: `${s.label} requires authentication but documents no 401 or 403 response.`,
			evidence: s.label,
		}),
	];
};

const isSensitiveQueryParam = (p: Parameter) =>
	p.in === "query" &&
	(SENSITIVE_PARAM.test(p.name) || API_KEY_PARAM.test(p.name));

const sensitiveQueryFindings = (s: OperationScope): FindingInput[] =>
	s.op.params.filter(isSensitiveQueryParam).map((p) =>
		finding(R.sensitiveQuery, {
			file: s.ctx.file,
			line: s.ctx.lineAt(p.at) ?? s.line,
			message: `${s.label} takes "${p.name}" as a query parameter; query strings are logged by proxies, servers and browsers.`,
			evidence: `${s.label} ?${p.name}=`,
		}),
	);

const responseSchemas = (resp: Record<string, unknown>): unknown[] => {
	const content = isRecord(resp.content) ? resp.content : {};
	return [
		resp.schema,
		...Object.values(content).map((m) => (isRecord(m) ? m.schema : undefined)),
	];
};

const isUnboundedArray = (root: Record<string, unknown>, schema: unknown) => {
	const array = isArraySchema(root, schema);
	return array !== undefined && array.maxItems === undefined;
};

const returnsUnboundedArray = (root: Record<string, unknown>, raw: unknown) => {
	const resp = deref(root, raw);
	if (!isRecord(resp)) return false;
	return responseSchemas(resp).some((sch) => isUnboundedArray(root, sch));
};

/** An HTTP status code key such as `200` or `default`. */
type StatusCode = string;

const isSuccessCode = (code: StatusCode) => /^2\d\d$/.test(code);

const unboundedArrayFindings = (s: OperationScope): FindingInput[] => {
	if (s.op.method !== "get") return [];
	if (s.op.params.some((p) => PAGINATION_PARAM.test(p.name))) return [];
	return Object.entries(responsesOf(s.op))
		.filter(
			([code, raw]) =>
				isSuccessCode(code) && returnsUnboundedArray(s.ctx.data, raw),
		)
		.map(([code]) =>
			finding(R.unboundedArray, {
				file: s.ctx.file,
				line: s.ctx.lineAt([...s.op.at, "responses", code]) ?? s.line,
				message: `${s.label} returns an array with no maxItems and no pagination parameters; a large collection can exhaust server and client resources.`,
				evidence: `${s.label} -> ${code} array`,
			}),
		);
};

const requestBodySchemas = (
	data: Record<string, unknown>,
	op: Operation,
): unknown[] => {
	const rb = deref(data, op.node.requestBody);
	if (!isRecord(rb) || !isRecord(rb.content)) return [];
	return Object.values(rb.content)
		.filter(isRecord)
		.map((m) => m.schema);
};

const pathItemParameters = (data: Record<string, unknown>, op: Operation) => {
	const paths = isRecord(data.paths) ? data.paths : {};
	const item = paths[op.path];
	return isRecord(item) ? item.parameters : [];
};

const isBodyParam = (p: unknown): p is Record<string, unknown> =>
	isRecord(p) && p.in === "body";

/** Swagger 2.0 `in: body` parameter schemas, operation first then path item. */
const bodyParamSchemas = (
	data: Record<string, unknown>,
	op: Operation,
): unknown[] =>
	[...arrayOf(op.node.parameters), ...arrayOf(pathItemParameters(data, op))]
		.map((raw) => deref(data, raw))
		.filter(isBodyParam)
		.map((p) => p.schema);

const hasDeclaredProperties = (s: Record<string, unknown>) =>
	isRecord(s.properties) && Object.keys(s.properties).length > 0;

const isOpenObject = (s: Record<string, unknown>) =>
	s.additionalProperties !== false && s.unevaluatedProperties !== false;

const acceptsUndeclaredProperties = (schema: unknown) => {
	if (!isRecord(schema)) return false;
	return hasDeclaredProperties(schema) && isOpenObject(schema);
};

const massAssignmentFindings = (s: OperationScope): FindingInput[] => {
	if (!WRITE_METHODS.has(s.op.method)) return [];
	const { data, lineAt } = s.ctx;
	const bodies = [
		...requestBodySchemas(data, s.op),
		...bodyParamSchemas(data, s.op),
	];
	if (!bodies.some((sch) => acceptsUndeclaredProperties(deref(data, sch))))
		return [];
	return [
		finding(R.massAssignment, {
			file: s.ctx.file,
			line:
				lineAt([...s.op.at, "requestBody"]) ??
				lineAt([...s.op.at, "parameters"]) ??
				s.line,
			message: `The request body of ${s.label} does not set additionalProperties: false, so clients can send fields the API never declared.`,
			evidence: `${s.label} request body`,
		}),
	];
};

const operationFindings = (
	ctx: SpecContext,
	op: Operation,
	globalSecurity: unknown[] | undefined,
): FindingInput[] => {
	const s: OperationScope = {
		ctx,
		op,
		label: `${op.method.toUpperCase()} ${op.path}`,
		line: ctx.lineAt(op.at),
		effective: securityRequirementsOf(op.node.security) ?? globalSecurity,
		looksPublic: PUBLIC_PATH.test(op.path),
	};
	return [
		...noAuthFindings(s),
		...authResponseFindings(s),
		...sensitiveQueryFindings(s),
		...unboundedArrayFindings(s),
		...massAssignmentFindings(s),
	];
};

const isApiDefinition = (data: Record<string, unknown>) =>
	typeof data.openapi === "string" || typeof data.swagger === "string";

/** Audits one OpenAPI 3.x / Swagger 2.0 document. */
export const auditOpenApi = (
	file: FilePath,
	text: SourceText,
): FindingInput[] => {
	const spec = parseSpec(text);
	if (!spec || !isApiDefinition(spec.data)) return [];
	const ctx: SpecContext = { file, ...spec };
	const ops = collectOperations(spec.data);
	const globalSecurity = securityRequirementsOf(spec.data.security);
	return [
		...serverFindings(ctx),
		...swaggerSchemeFindings(ctx),
		...securitySchemeFindings(ctx, ops.length > 0),
		...ops.flatMap((op) => operationFindings(ctx, op, globalSecurity)),
	];
};
