import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	type HttpResponse,
	redact,
	type Severity,
} from "@openaudit/core";
import { Effect, type Option } from "effect";

import {
	type Crawl,
	crawl,
	fetchCached,
	type Page,
	resourcesOf,
	sameOrigin,
} from "./page";
import { truncate } from "./util";

const OWASP_CONFIG =
	"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/";
const MAX_SOURCEMAP_CHECKS = 10;
const MAX_DIR_CHECKS = 3;

interface Probe {
	readonly path: string;
	readonly rule: string;
	readonly severity: Severity;
	readonly title: string;
	readonly message: string;
	readonly remediation: string;
	readonly references: ReadonlyArray<string>;
	readonly tags?: ReadonlyArray<string>;
	/** Body signature; status alone is not trusted because of soft 404s. */
	readonly match: (res: HttpResponse) => string | undefined;
}

const isHtml = (res: HttpResponse) =>
	/text\/html/i.test(res.headers.get("content-type") ?? "") ||
	/^\s*<(!doctype|html)/i.test(res.body);

const PROBES: ReadonlyArray<Probe> = [
	{
		path: "/.git/HEAD",
		rule: "git-exposed",
		severity: "critical",
		title: "Git repository is publicly accessible",
		message:
			"/.git/ is served by the web server. Attackers can download the full repository history, including source code and any secrets ever committed.",
		remediation:
			"Block access to /.git (and all dot-directories) in the web server, and deploy build artefacts rather than a git checkout.",
		references: [
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
		],
		tags: ["cwe-527", "owasp-a05"],
		match: (res) => {
			const m = res.body.match(/^(ref: refs\/[\w./-]+|[0-9a-f]{40})\s*$/);
			return m ? m[1] : undefined;
		},
	},
	{
		path: "/.env",
		rule: "env-file-exposed",
		severity: "critical",
		title: ".env file is publicly accessible",
		message:
			"/.env is served and contains KEY=value configuration, typically database credentials and API keys.",
		remediation:
			"Remove .env from the web root, block dotfiles at the server, and rotate every credential it contained.",
		references: [OWASP_CONFIG],
		tags: ["cwe-538", "owasp-a05"],
		match: (res) => {
			if (isHtml(res)) return undefined;
			const pairs = [
				...res.body.matchAll(
					/^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=\s*(.*)$/gm,
				),
			];
			if (pairs.length < 2) return undefined;
			return pairs
				.slice(0, 4)
				.map(
					(m) =>
						`${m[1]}=${redact((m[2] ?? "").trim().replace(/^["']|["']$/g, ""))}`,
				)
				.join("; ");
		},
	},
	{
		path: "/.DS_Store",
		rule: "ds-store-exposed",
		severity: "low",
		title: ".DS_Store file is publicly accessible",
		message:
			"A macOS .DS_Store file is served; it lists file names in the directory, revealing unlinked files and backups.",
		remediation:
			"Delete .DS_Store files from deployments and block dotfiles at the server.",
		references: [OWASP_CONFIG],
		tags: ["cwe-538"],
		match: (res) =>
			res.body.slice(4, 8) === "Bud1" ? "Bud1 header" : undefined,
	},
	{
		path: "/server-status",
		rule: "server-status-exposed",
		severity: "medium",
		title: "Apache server-status is public",
		message:
			"mod_status is reachable, exposing live requests, client IPs, virtual hosts and server internals.",
		remediation:
			"Restrict /server-status to localhost or an admin network (`Require local`).",
		references: ["https://httpd.apache.org/docs/2.4/mod/mod_status.html"],
		tags: ["cwe-200"],
		match: (res) =>
			/Apache Server Status for/i.test(res.body)
				? "Apache Server Status"
				: undefined,
	},
	{
		path: "/phpinfo.php",
		rule: "phpinfo-exposed",
		severity: "high",
		title: "phpinfo() page is public",
		message:
			"A phpinfo() page discloses PHP configuration, extensions, file paths and environment variables (often including secrets).",
		remediation: "Delete phpinfo.php from the server.",
		references: [OWASP_CONFIG],
		tags: ["cwe-200", "owasp-a05"],
		match: (res) =>
			/<title>(PHP \d[^<]*- )?phpinfo\(\)<\/title>/i.test(res.body) ||
			/PHP Version \d+\.\d+.*?(System|Build Date)/is.test(res.body)
				? "phpinfo() output"
				: undefined,
	},
	{
		path: "/wp-login.php",
		rule: "wordpress-login",
		severity: "info",
		title: "WordPress login page is reachable",
		message:
			"The default WordPress login is public and a constant target for credential-stuffing bots.",
		remediation:
			"Rate-limit or restrict /wp-login.php, enforce MFA, and keep WordPress and plugins updated.",
		references: [
			"https://developer.wordpress.org/advanced-administration/security/hardening/",
		],
		match: (res) =>
			res.status === 200 &&
			/name=["']log["']|id=["']user_login["']|wp-submit/i.test(res.body)
				? "WordPress login form"
				: undefined,
	},
];

const ERROR_SIGNATURES: ReadonlyArray<[RegExp, string]> = [
	[/Traceback \(most recent call last\)/, "Python traceback"],
	[
		/You're seeing this error because you have <code>DEBUG = True<\/code>/,
		"Django debug page",
	],
	[/Using the URLconf defined in/, "Django debug 404"],
	[
		/<title>Action Controller: Exception caught<\/title>/,
		"Rails exception page",
	],
	[
		/Whoops[!,] (There was an error|Something went wrong)|Illuminate\\[A-Za-z\\]+Exception/,
		"Laravel/Whoops error page",
	],
	[
		/<b>(Fatal error|Warning|Parse error|Notice)<\/b>:\s+.+? in <b>[^<]+<\/b> on line <b>\d+<\/b>/,
		"PHP error with file path",
	],
	[
		/\bat [\w.$<>]+ \((?:\/|[A-Za-z]:\\|file:\/\/|webpack:|node:)[^)]+:\d+:\d+\)/,
		"JavaScript stack trace",
	],
	[
		/Exception in thread "[^"]+" [\w.]+(Exception|Error)|\tat [\w.$]+\([\w]+\.java:\d+\)/,
		"Java stack trace",
	],
	[
		/Server Error in '[^']*' Application\.|<b>Stack Trace:<\/b>/,
		"ASP.NET yellow screen of death",
	],
	[
		/SQLSTATE\[\w+\]|You have an error in your SQL syntax|ORA-\d{5}:|PG::\w+Error|SQLITE_ERROR/,
		"SQL error message",
	],
];

const verboseError = (body: string): [string, string] | undefined => {
	for (const [re, label] of ERROR_SIGNATURES) {
		const m = body.match(re);
		if (m)
			return [
				label,
				truncate(m[0].replace(/<[^>]+>/g, "").replace(/\s+/g, " "), 140),
			];
	}
	return undefined;
};

const DIR_LISTING =
	/<title>\s*Index of \/|<h1>\s*Index of \/|<title>Directory listing for \//i;

/** The crawl and origin every exposure check works from. */
interface Scan {
	readonly ctx: AuditContext;
	readonly crawl: Crawl;
	readonly origin: string;
}

type Probed = Option.Option<HttpResponse>;

interface ProbeResult {
	readonly probe: Probe;
	readonly res: Probed;
}

interface Body {
	readonly url: string;
	readonly body: string;
}

const probePath = (ctx: AuditContext, origin: string, path: string) =>
	fetchCached(ctx, `${origin}${path}`, {
		redirect: "manual",
		timeoutMs: 8_000,
		maxBytes: 128 * 1024,
	}).pipe(Effect.option);

/** The response when the probe answered 200. */
const okResponse = (res: Probed): HttpResponse | undefined =>
	res._tag === "Some" && res.value.status === 200 ? res.value : undefined;

const pageBodies = (crawl: Crawl): Array<Body> =>
	crawl.pages.map((p: Page) => ({ url: p.url, body: p.response.body }));

const runProbes = ({ ctx, origin }: Scan) =>
	Effect.forEach(
		PROBES,
		(probe) =>
			Effect.map(probePath(ctx, origin, probe.path), (res) => ({
				probe,
				res,
			})),
		{ concurrency: 3 },
	);

const probeFinding = (
	origin: string,
	{ probe, res }: ProbeResult,
): FindingInput[] => {
	const ok = okResponse(res);
	if (!ok) return [];
	const evidence = probe.match(ok);
	if (evidence === undefined) return [];
	return [
		{
			ruleId: `web.exposure/${probe.rule}`,
			title: probe.title,
			severity: probe.severity,
			category: "security",
			message: probe.message,
			location: { url: `${origin}${probe.path}` },
			evidence,
			remediation: probe.remediation,
			references: [...probe.references],
			tags: probe.tags ? [...probe.tags] : undefined,
			confidence: "high",
		},
	];
};

const hasSecurityContact = (res: Probed): boolean => {
	const ok = okResponse(res);
	return ok !== undefined && /^\s*contact\s*:/im.test(ok.body);
};

const securityTxtFindings = ({ ctx, origin }: Scan) =>
	Effect.map(
		probePath(ctx, origin, "/.well-known/security.txt"),
		(secTxt): FindingInput[] =>
			hasSecurityContact(secTxt)
				? []
				: [
						{
							ruleId: "web.exposure/security-txt-missing",
							title: "No security.txt",
							severity: "info",
							category: "security",
							message:
								"There is no /.well-known/security.txt telling researchers how to report vulnerabilities.",
							location: { url: `${origin}/.well-known/security.txt` },
							remediation:
								"Publish /.well-known/security.txt with at least Contact: and Expires: fields.",
							references: [
								"https://securitytxt.org/",
								"https://www.rfc-editor.org/rfc/rfc9116",
							],
						},
					],
	);

const sameOriginScripts = (crawl: Crawl): string[] =>
	[
		...new Set(
			crawl.pages
				.flatMap(resourcesOf)
				.filter(
					(r) => r.kind === "script" && sameOrigin(r.url, crawl.start.url),
				)
				.map((r) => r.url.replace(/[?#].*$/, "")),
		),
	].slice(0, MAX_SOURCEMAP_CHECKS);

const looksLikeSourceMap = (body: string): boolean =>
	/"mappings"\s*:/.test(body) && /"sources"\s*:/.test(body);

const sourceMapFinding = (src: string, res: HttpResponse): FindingInput[] => {
	if (res.status !== 200 || !looksLikeSourceMap(res.body)) return [];
	const hasContent = /"sourcesContent"\s*:/.test(res.body);
	return [
		{
			ruleId: "web.exposure/source-map-exposed",
			title: "JavaScript source map is public",
			severity: hasContent ? "medium" : "low",
			category: "security",
			message: `${src}.map is publicly served${hasContent ? " with embedded original sources" : ""}, revealing un-minified source code, internal paths and comments that help attackers find bugs.`,
			location: { url: `${src}.map` },
			evidence: truncate(
				res.body.match(/"sources"\s*:\s*\[[^\]]{0,120}/)?.[0] ?? "",
				140,
			),
			remediation:
				"Do not deploy .map files publicly; upload them to your error tracker instead, or restrict access.",
			references: [
				"https://developer.mozilla.org/en-US/docs/Glossary/Source_map",
			],
			tags: ["cwe-540"],
		},
	];
};

const sourceMapFindings = ({ ctx, crawl }: Scan) =>
	Effect.map(
		Effect.forEach(
			sameOriginScripts(crawl),
			(src) =>
				fetchCached(ctx, `${src}.map`, {
					redirect: "manual",
					timeoutMs: 8_000,
					maxBytes: 256 * 1024,
				}).pipe(
					Effect.map((res) => ({ src, res })),
					Effect.option,
				),
			{ concurrency: 3 },
		),
		(maps) =>
			maps.flatMap((m) =>
				m._tag === "None" ? [] : sourceMapFinding(m.value.src, m.value.res),
			),
	);

const listingDirs = (crawl: Crawl): string[] =>
	[
		...new Set(
			crawl.pages
				.flatMap(resourcesOf)
				.filter((r) => sameOrigin(r.url, crawl.start.url) && r.kind !== "form")
				.map((r) => new URL(r.url).pathname.replace(/[^/]*$/, ""))
				.filter((d) => d !== "/"),
		),
	].slice(0, MAX_DIR_CHECKS);

const listingFinding = ({ url, body }: Body): FindingInput[] =>
	DIR_LISTING.test(body)
		? [
				{
					ruleId: "web.exposure/directory-listing",
					title: "Directory listing is enabled",
					severity: "medium",
					category: "security",
					message: `${url} shows an auto-generated directory index, exposing every file in the folder, including ones never linked.`,
					location: { url },
					evidence: truncate(body.match(DIR_LISTING)?.[0] ?? "", 80),
					remediation:
						"Disable auto-indexing (`autoindex off` in nginx, `Options -Indexes` in Apache).",
					references: [OWASP_CONFIG],
					tags: ["cwe-548", "owasp-a05"],
				},
			]
		: [];

const directoryListingFindings = ({ ctx, crawl, origin }: Scan) =>
	Effect.map(
		Effect.forEach(
			listingDirs(crawl),
			(dir) => Effect.map(probePath(ctx, origin, dir), (res) => ({ dir, res })),
			{ concurrency: 3 },
		),
		(listed) =>
			[
				...pageBodies(crawl),
				...listed.flatMap(({ dir, res }) => {
					const ok = okResponse(res);
					return ok ? [{ url: `${origin}${dir}`, body: ok.body }] : [];
				}),
			].flatMap(listingFinding),
	);

const errorProbeBodies = (
	origin: string,
	probes: ReadonlyArray<ProbeResult>,
): Array<Body> =>
	probes.flatMap(({ probe, res }) =>
		res._tag === "Some" && res.value.status >= 400
			? [{ url: `${origin}${probe.path}`, body: res.value.body }]
			: [],
	);

const verboseErrorFinding = (
	{ url }: Body,
	hit: [string, string],
	location: string,
): FindingInput => ({
	ruleId: "web.exposure/verbose-error",
	title: `Verbose error page (${hit[0]})`,
	severity: "medium",
	category: "security",
	message: `${url} shows a ${hit[0]}, leaking file paths, framework versions or queries. Debug output in production usually also means debug mode is on.`,
	location: { url: location },
	evidence: hit[1],
	remediation:
		"Disable debug mode in production and serve generic error pages; log details server-side.",
	references: ["https://owasp.org/www-community/Improper_Error_Handling"],
	tags: ["cwe-209", "owasp-a05"],
	confidence: "medium",
});

const verboseErrorFindings = (
	scan: Scan,
	probes: ReadonlyArray<ProbeResult>,
) => {
	const { ctx, crawl, origin } = scan;
	const notFoundUrl = `${origin}/openaudit-${Date.now().toString(36)}-not-found`;
	return Effect.map(
		probePath(ctx, origin, new URL(notFoundUrl).pathname),
		(notFound) => {
			const errorBodies: Array<Body> = [
				...pageBodies(crawl),
				...(notFound._tag === "Some"
					? [{ url: notFoundUrl, body: notFound.value.body }]
					: []),
				...errorProbeBodies(origin, probes),
			];
			const reported = new Set<string>();
			const findings: FindingInput[] = [];
			for (const page of errorBodies) {
				const hit = verboseError(page.body);
				if (!hit || reported.has(hit[0])) continue;
				reported.add(hit[0]);
				const location = page.url.startsWith(notFoundUrl)
					? `${origin}/<random-404>`
					: page.url;
				findings.push(verboseErrorFinding(page, hit, location));
			}
			return findings;
		},
	);
};

/** Light probes for files and pages that should never be public. */
export const exposure = defineAuditor({
	id: "web.exposure",
	title: "Sensitive file exposure",
	description:
		"Probes a handful of well-known paths (/.git, /.env, server-status, phpinfo…), checks for public source maps, directory listings and verbose error pages, and for security.txt.",
	categories: ["security"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const c = yield* crawl(ctx);
			const scan: Scan = { ctx, crawl: c, origin: new URL(c.start.url).origin };
			const probes = yield* runProbes(scan);
			const probed = probes.flatMap((p) => probeFinding(scan.origin, p));
			const securityTxt = yield* securityTxtFindings(scan);
			const sourceMaps = yield* sourceMapFindings(scan);
			const listings = yield* directoryListingFindings(scan);
			const errors = yield* verboseErrorFindings(scan, probes);
			return [...probed, ...securityTxt, ...sourceMaps, ...listings, ...errors];
		}),
});
