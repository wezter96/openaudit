import type { FindingInput } from "@openaudit/core";

import {
	dependencyNames,
	type FilePath,
	finding,
	parseJsonRecord,
	type RuleSpec,
	type SourceText,
} from "./api-shared";
import { fullLineAt, isCommentLine, lineLocator, nonCodeMask } from "./util";

const GRAPHQL_FILE =
	/@apollo\/server|apollo-server|graphql-yoga|@graphql-yoga|mercurius|express-graphql|graphql-http|@nestjs\/apollo|@nestjs\/mercurius/;
const GRAPHQL_SERVER_DEPS =
	/^(@apollo\/server|apollo-server(-[a-z]+)?|graphql-yoga|@graphql-yoga\/.+|mercurius|express-graphql|graphql-http|@nestjs\/apollo|@nestjs\/mercurius|graphql-helix)$/;
const GRAPHQL_LIMIT_DEPS =
	/^(graphql-depth-limit|graphql-query-complexity|graphql-validation-complexity|graphql-cost-analysis|graphql-armor|@escape\.tech\/graphql-armor.*|@envelop\/depth-limit|@graphile\/depth-limit|graphql-no-alias|@graphql-armor\/.+)$/;
const DEPENDENCY_SECTIONS = [
	"dependencies",
	"devDependencies",
	"peerDependencies",
];

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

/** One JS/TS source file prepared for pattern checks. */
interface ScannedSource {
	readonly file: FilePath;
	readonly text: SourceText;
	readonly lineOf: (index: number) => number;
	readonly mask: Uint8Array;
}

const codeRuleFindings = (
	src: ScannedSource,
	{ rule, pattern, message }: CodeRule,
): FindingInput[] => {
	const out: FindingInput[] = [];
	for (const m of src.text.matchAll(pattern)) {
		const index = m.index ?? 0;
		if (src.mask[index]) continue;
		const line = fullLineAt(src.text, index);
		if (isCommentLine(line)) continue;
		out.push(
			finding(rule, {
				file: src.file,
				line: src.lineOf(index),
				message,
				evidence: line,
			}),
		);
	}
	return out;
};

const isImportOrComment = (line: SourceText) =>
	isCommentLine(line) || /^\s*import\b|\brequire\(/.test(line);

/** The first Yoga/Mercurius server in a file that never mentions introspection. */
const introspectionDefaultFindings = (src: ScannedSource): FindingInput[] => {
	if (INTROSPECTION_CONTROL.test(src.text)) return [];
	for (const m of src.text.matchAll(YOGA_OR_MERCURIUS)) {
		const index = m.index ?? 0;
		const line = fullLineAt(src.text, index);
		if (isImportOrComment(line)) continue;
		return [
			finding(G.introspectionDefault, {
				file: src.file,
				line: src.lineOf(index),
				message:
					"The server is created without any introspection setting, so introspection stays enabled in every environment.",
				evidence: line,
			}),
		];
	}
	return [];
};

/** Audits one JS/TS source file for risky GraphQL server configuration. */
export const auditGraphqlSource = (
	file: FilePath,
	text: SourceText,
): FindingInput[] => {
	if (!GRAPHQL_FILE.test(text)) return [];
	const src: ScannedSource = {
		file,
		text,
		lineOf: lineLocator(text),
		mask: nonCodeMask(text, "js"),
	};
	return [
		...GRAPHQL_CODE_RULES.flatMap((rule) => codeRuleFindings(src, rule)),
		...introspectionDefaultFindings(src),
	];
};

/** Audits one package.json for a GraphQL server without a depth/complexity limiter. */
export const auditGraphqlPackage = (
	file: FilePath,
	text: SourceText,
): FindingInput[] => {
	const pkg = parseJsonRecord(text);
	if (!pkg) return [];
	const deps = [...new Set(dependencyNames(pkg, DEPENDENCY_SECTIONS))];
	const server = deps.find((d) => GRAPHQL_SERVER_DEPS.test(d));
	if (!server || deps.some((d) => GRAPHQL_LIMIT_DEPS.test(d))) return [];
	const idx = text.indexOf(`"${server}"`);
	return [
		finding(G.noLimit, {
			file,
			line: idx >= 0 ? lineLocator(text)(idx) : undefined,
			message: `package.json depends on ${server} but on no query depth or complexity limiter, so deeply nested queries are accepted.`,
			evidence: `"${server}" without graphql-depth-limit / graphql-armor / graphql-query-complexity`,
		}),
	];
};
