import { basename, dirname } from "node:path";
import {
	type AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { auditGraphqlPackage, auditGraphqlSource } from "./api-graphql";
import { auditOpenApi } from "./api-openapi";
import {
	dependencyNames,
	type FilePath,
	finding,
	parseJsonRecord,
	type RuleSpec,
	type SourceText,
} from "./api-shared";
import {
	extOf,
	fullLineAt,
	isFixturePath,
	isGeneratedPath,
	isLockfile,
	isTestPath,
	languageOf,
	lineLocator,
	readTextFiles,
} from "./util";

export { auditGraphqlPackage, auditGraphqlSource } from "./api-graphql";
export { auditOpenApi } from "./api-openapi";
export { owaspApiUrl } from "./api-shared";

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
const SPEC_EXTENSIONS = ["yaml", "yml", "json"];

/** Paths that are never probed as specs even with a yaml/json extension. */
const NEVER_A_SPEC: ReadonlyArray<(path: FilePath) => boolean> = [
	isLockfile,
	(p) => NOT_A_SPEC.test(p),
	isFixturePath,
	isGeneratedPath,
	(p) => /(^|\/)(node_modules|dist|build|\.git)\//.test(p),
];

const isSpecCandidate = (path: FilePath) =>
	SPEC_EXTENSIONS.includes(extOf(path)) &&
	!NEVER_A_SPEC.some((excluded) => excluded(path));

const isNamedSpec = (path: FilePath) => SPEC_NAME.test(basename(path));

/** The spec kind declared by the document's top-level version key. */
const specKindOf = (text: SourceText): string | undefined => {
	const key = SPEC_KEY.exec(text)?.[1]?.toLowerCase();
	if (!key || text.includes("\u0000")) return undefined;
	return key;
};

const readSpec = (
	ws: Workspace,
	path: FilePath,
	kinds: ReadonlyArray<SpecKind>,
): Effect.Effect<SpecFile | undefined> =>
	Effect.gen(function* () {
		const cap = isNamedSpec(path) ? MAX_SPEC_BYTES : MAX_PROBE_BYTES;
		const size = yield* ws.size(path).pipe(Effect.orElseSucceed(() => 0));
		if (size === 0 || size > cap) return undefined;
		const text = yield* ws.readText(path).pipe(Effect.orElseSucceed(() => ""));
		const key = specKindOf(text);
		if (!key || !(kinds as ReadonlyArray<string>).includes(key))
			return undefined;
		return { path, text, kind: key as SpecKind };
	});

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
		const candidates = (yield* ws.files).filter(isSpecCandidate);
		const named = candidates.filter(isNamedSpec);
		const others = candidates
			.filter((p) => !isNamedSpec(p))
			.slice(0, MAX_PROBE_FILES);
		const found: SpecFile[] = [];
		for (const path of [...named, ...others]) {
			if (found.length >= MAX_SPECS) break;
			const spec = yield* readSpec(ws, path, kinds);
			if (spec) found.push(spec);
		}
		return found;
	});

/* -------------------------------------------------------------------------- */
/*                               REST framework                               */
/* -------------------------------------------------------------------------- */

const RATE_LIMIT_DEPS =
	/rate-?limit|throttl|express-brute|express-slow-down|limiter|bottleneck/i;
const RATE_LIMIT_CODE = /rate-?limit|throttle/i;
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

interface TextFile {
	readonly path: FilePath;
	readonly text: SourceText;
}

/** The directory of a path, with the workspace root as "". */
const dirOf = (path: FilePath) => (dirname(path) === "." ? "" : dirname(path));

const packageInfo = (
	path: FilePath,
	text: SourceText,
): PackageInfo | undefined => {
	const pkg = parseJsonRecord(text);
	if (!pkg) return undefined;
	const names = dependencyNames(pkg, ["dependencies", "devDependencies"]);
	return {
		dir: dirOf(path),
		express: names.includes("express"),
		limited: names.some((n) => RATE_LIMIT_DEPS.test(n)),
	};
};

/** package.json files by directory; a later manifest in the same directory wins. */
const packagesByDir = (manifests: ReadonlyArray<TextFile>) => {
	const packages = new Map<string, PackageInfo>();
	for (const m of manifests) {
		const info = packageInfo(m.path, m.text);
		if (info) packages.set(info.dir, info);
	}
	return packages;
};

/** The nearest package.json at or above the file. */
const ownerOf = (
	packages: ReadonlyMap<string, PackageInfo>,
	path: FilePath,
): PackageInfo | undefined => {
	let dir = dirOf(path);
	for (;;) {
		const hit = packages.get(dir);
		if (hit) return hit;
		if (dir === "") return undefined;
		dir = dirOf(dir);
	}
};

const isUnthrottledExpress = (
	pkg: PackageInfo | undefined,
): pkg is PackageInfo => {
	if (!pkg) return false;
	return pkg.express && !pkg.limited;
};

const authRouteIndex = (text: SourceText): number | undefined => {
	AUTH_ROUTE.lastIndex = 0;
	return AUTH_ROUTE.exec(text)?.index;
};

const loginRouteFinding = (file: TextFile, index: number): FindingInput =>
	finding(REST, {
		file: file.path,
		line: lineLocator(file.text)(index),
		message:
			"This Express app has an authentication route but no rate-limiting dependency or middleware, so credentials can be guessed at full speed.",
		evidence: fullLineAt(file.text, index),
	});

/** Express login routes without rate limiting, once per package. */
const loginRouteFindings = (
	sources: ReadonlyArray<TextFile>,
	packages: ReadonlyMap<string, PackageInfo>,
): FindingInput[] => {
	const owner = (path: FilePath) => ownerOf(packages, path);
	/* Packages that throttle in code, then packages already reported. */
	const done = new Set<PackageInfo>(
		sources
			.filter((file) => RATE_LIMIT_CODE.test(file.text))
			.flatMap((file) => owner(file.path) ?? []),
	);
	const out: FindingInput[] = [];
	for (const file of sources) {
		const pkg = owner(file.path);
		if (!isUnthrottledExpress(pkg) || done.has(pkg)) continue;
		const index = authRouteIndex(file.text);
		if (index === undefined) continue;
		done.add(pkg);
		out.push(loginRouteFinding(file, index));
	}
	return out;
};

/* -------------------------------------------------------------------------- */
/*                                   auditor                                  */
/* -------------------------------------------------------------------------- */

const VENDORED_DIR = /(^|\/)(node_modules|dist|build)\//;

const isScannableSource = (path: FilePath) =>
	languageOf(path) === "js" &&
	!isTestPath(path) &&
	!isFixturePath(path) &&
	!isGeneratedPath(path) &&
	!VENDORED_DIR.test(path);

const isScannableManifest = (path: FilePath) =>
	basename(path) === "package.json" &&
	!isFixturePath(path) &&
	!isTestPath(path) &&
	!/(^|\/)node_modules\//.test(path);

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
			const specs = yield* findSpecFiles(ws, ["openapi", "swagger"]);
			const sources = yield* readTextFiles(ws, isScannableSource);
			const manifests = yield* readTextFiles(ws, isScannableManifest, {
				limit: 200,
			});
			return [
				...specs.flatMap((spec) => auditOpenApi(spec.path, spec.text)),
				...sources.flatMap((file) => auditGraphqlSource(file.path, file.text)),
				...manifests.flatMap((m) => auditGraphqlPackage(m.path, m.text)),
				...loginRouteFindings(sources, packagesByDir(manifests)),
			];
		}),
});
