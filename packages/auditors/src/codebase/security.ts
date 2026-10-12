import {
	type Confidence,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	baseName,
	cweUrl,
	fullLineAt,
	isCommentLine,
	isFixturePath,
	isGeneratedPath,
	isTestPath,
	languageOf,
	lineLocator,
	nonCodeMask,
	owaspUrl,
	readTextFiles,
	type SourceFile,
	scrubLine,
	truncate,
} from "./util";

/** `config` covers env files, YAML, Dockerfiles and shell scripts. */
type Lang =
	| "js"
	| "python"
	| "go"
	| "php"
	| "ruby"
	| "java"
	| "csharp"
	| "config";

interface MatchContext {
	readonly match: string;
	/** Arguments of the call starting at the match (up to the balancing paren). */
	readonly args: string;
	readonly line: string;
	/** The matched line plus the two following lines. */
	readonly window: string;
	readonly text: string;
	readonly path: string;
}

interface SastRule {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly confidence: Confidence;
	readonly cwe: number;
	readonly owasp: string;
	readonly message: string;
	readonly remediation: string;
	readonly patterns: Partial<Record<Lang, ReadonlyArray<RegExp>>>;
	readonly when?: (m: MatchContext) => boolean;
	readonly references?: ReadonlyArray<string>;
}

const SENSITIVE_NAME =
	/token|secret|passw|pwd|nonce|salt|otp|session|csrf|api_?key|auth|verif|reset|invite|code/i;
const PASSWORD_CONTEXT = /passw|pwd|credential/i;

const isStringLiteral = (s: string) =>
	/^\s*(?:"[^"$]*"|'[^']*'|`[^`$]*`)\s*;?\s*$/.test(s);

export const SAST_RULES: ReadonlyArray<SastRule> = [
	{
		id: "code-injection",
		title: "Dynamic code evaluation",
		severity: "high",
		confidence: "medium",
		cwe: 95,
		owasp: "a03",
		message:
			"Code is evaluated from a string at runtime. If any part of it is user-controlled this is remote code execution.",
		remediation:
			"Avoid eval/new Function/exec on strings. Use a lookup table, JSON.parse, or a safe expression parser instead.",
		patterns: {
			js: [
				/(?<![.\w$])eval\s*\(/g,
				/\bnew\s+Function\s*\(/g,
				/(?<![.\w$])set(?:Timeout|Interval)\s*\(\s*["'`]/g,
			],
			python: [/(?<![.\w])(?:eval|exec)\s*\(\s*(?!["')])/g],
			php: [/(?<![\w>$])(?:eval|assert|create_function)\s*\(\s*\$/g],
			ruby: [/(?<![.\w:])(?:eval|instance_eval|class_eval)\s*[( ]\s*(?!["'])/g],
		},
	},
	{
		id: "command-injection",
		title: "Shell command built from variables",
		severity: "high",
		confidence: "medium",
		cwe: 78,
		owasp: "a03",
		message:
			"A shell command is assembled from variables. Attacker-controlled input can inject additional commands.",
		remediation:
			"Pass arguments as an array to a non-shell API (execFile/spawn without shell, subprocess.run([...]), exec.Command with separate args) and validate inputs.",
		patterns: {
			js: [
				/\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"'\n]*["']\s*\+|\w+\s*\+)/g,
				/\bspawn(?:Sync)?\s*\([^\n]*\bshell\s*:\s*true/g,
			],
			python: [
				/\bsubprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\([^\n]*shell\s*=\s*True/g,
				/\bos\.(?:system|popen)\s*\(\s*(?:f["']|["'][^"'\n]*["']\s*(?:%|\+|\.format)|[A-Za-z_]\w*\s*[+%)])/g,
			],
			go: [
				/exec\.Command(?:Context)?\(\s*(?:\w+\s*,\s*)?"(?:sh|bash|zsh|cmd|\/bin\/sh|\/bin\/bash)"\s*,\s*"(?:-c|\/c)"\s*,\s*(?:fmt\.Sprintf|[^)\n]*\+)/g,
			],
			php: [
				/(?<![\w>$])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)\n]*\$/g,
			],
			ruby: [
				/(?:\bsystem|\bexec|\bspawn|%x)\s*[({]?\s*["`{][^\n]*#\{/g,
				/`[^`\n]*#\{[^`\n]*`/g,
			],
			java: [
				/Runtime\.getRuntime\(\)\.exec\(\s*(?:"[^"\n]*"\s*\+|\w+\s*\+)/g,
				/new\s+ProcessBuilder\([^)\n]*"(?:sh|bash|cmd)"\s*,\s*"(?:-c|\/c)"/g,
			],
		},
		when: ({ text, path }) =>
			languageOf(path) !== "js" || /child_process|shelljs/.test(text),
	},
	{
		id: "xss",
		title: "Unescaped HTML rendering",
		severity: "medium",
		confidence: "medium",
		cwe: 79,
		owasp: "a03",
		message:
			"HTML is rendered without escaping. If the value contains user input, attackers can inject scripts (XSS).",
		remediation:
			"Render text instead of HTML (textContent, JSX children), or sanitize with a vetted library such as DOMPurify before inserting HTML.",
		patterns: {
			js: [
				/dangerouslySetInnerHTML\s*=\s*\{\{?\s*(?:__html\s*:\s*)?(?!["'`]|DOMPurify|sanitize|purify)/g,
				/\.(?:innerHTML|outerHTML)\s*\+?=(?!=)/g,
				/\bdocument\.write(?:ln)?\s*\(/g,
				/\.insertAdjacentHTML\s*\(/g,
				/\bv-html\s*=/g,
				/\{@html\s/g,
			],
			python: [
				/\bmark_safe\s*\(\s*(?!["'])/g,
				/\brender_template_string\s*\(/g,
			],
			php: [/\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/g],
			ruby: [/\.html_safe\b/g, /(?<![.\w])raw\s*\(\s*(?:params|@)/g],
			go: [/template\.(?:HTML|JS|URL)\(\s*(?!")/g],
		},
		when: ({ match, line }) => {
			if (/innerHTML|outerHTML/.test(match)) {
				const rhs = line.slice(line.indexOf(match) + match.length);
				return !isStringLiteral(rhs) && !/DOMPurify|sanitize/i.test(rhs);
			}
			return !/DOMPurify|sanitize/i.test(line);
		},
	},
	{
		id: "sql-injection",
		title: "SQL query built from variables",
		severity: "high",
		confidence: "medium",
		cwe: 89,
		owasp: "a03",
		message:
			"A SQL statement is built with string interpolation or concatenation. User input reaching it can read or modify arbitrary data.",
		remediation:
			"Use parameterized queries / prepared statements (placeholders such as $1 or ?) or a query builder; never interpolate values into SQL text.",
		patterns: {
			js: [
				/(?<![\w$.)\]])`\s*(?:SELECT\b[^`]*?\bFROM|INSERT\s+INTO|UPDATE\s+[\w."`]+\s+SET|DELETE\s+FROM)\b[^`]*\$\{/gi,
				/["'](?:SELECT\b[^"'\n]*\bFROM|INSERT\s+INTO|UPDATE\s+[\w."]+\s+SET|DELETE\s+FROM)\b[^"'\n]*["']\s*\+\s*[\w(]/gi,
			],
			python: [
				/\.(?:execute|executemany|raw|extra|executescript)\s*\(\s*(?:f"[^"\n]*\{|f'[^'\n]*\{|"[^"\n]*"\s*(?:%\s*[\w(]|\.format\s*\(|\+)|'[^'\n]*'\s*(?:%\s*[\w(]|\.format\s*\(|\+))/g,
				/\btext\s*\(\s*f["'](?:SELECT|INSERT|UPDATE|DELETE)/gi,
			],
			go: [
				/\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw)\(\s*(?:ctx\s*,\s*)?(?:fmt\.Sprintf\(|"[^"\n]*"\s*\+)/g,
			],
			php: [
				/(?:mysqli?_query|->query|->exec)\s*\([^;\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^;\n]*(?:\{\$|\$\w|["']\s*\.\s*\$)/gi,
			],
			ruby: [
				/\.(?:where|find_by_sql|execute|select|order|joins|group|having|exec_query|pluck)\s*\(\s*"[^"\n]*#\{/g,
			],
			java: [
				/\.(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|addBatch)\s*\(\s*(?:"[^"\n]*"\s*\+|String\.format\()/g,
			],
			csharp: [
				/new\s+SqlCommand\s*\(\s*(?:\$"|"[^"\n]*"\s*\+)/g,
				/\.(?:FromSqlRaw|ExecuteSqlRaw)\s*\(\s*\$"/g,
			],
		},
	},
	{
		id: "weak-password-hash",
		title: "Weak hash used for passwords",
		severity: "high",
		confidence: "medium",
		cwe: 916,
		owasp: "a02",
		message:
			"MD5/SHA-1 is used near password handling. Fast hashes are trivially brute-forced; MD5 and SHA-1 are also broken.",
		remediation:
			"Hash passwords with a slow, salted algorithm: Argon2id, scrypt or bcrypt (e.g. Bun.password, argon2, passlib, password_hash()).",
		patterns: {},
		when: ({ window }) => PASSWORD_CONTEXT.test(window),
		references: [
			"https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
		],
	},
	{
		id: "weak-hash",
		title: "Weak hash algorithm",
		severity: "low",
		confidence: "low",
		cwe: 328,
		owasp: "a02",
		message:
			"MD5/SHA-1 is collision-prone. This is fine for non-security checksums but not for signatures, tokens or integrity checks.",
		remediation:
			"Use SHA-256 or stronger for security-relevant hashing; mark non-security uses explicitly (e.g. usedforsecurity=False).",
		patterns: {},
		when: ({ window }) =>
			!PASSWORD_CONTEXT.test(window) &&
			!/usedforsecurity\s*=\s*False/.test(window),
	},
	{
		id: "insecure-random",
		title: "Non-cryptographic randomness for secrets",
		severity: "medium",
		confidence: "medium",
		cwe: 338,
		owasp: "a02",
		message:
			"A predictable random generator is used to produce what looks like a token, password or other secret.",
		remediation:
			"Use a CSPRNG: crypto.randomUUID()/crypto.getRandomValues() (JS), secrets (Python), crypto/rand (Go), random_bytes() (PHP), SecureRandom (Java/Ruby).",
		patterns: {
			js: [/\bMath\.random\s*\(\)/g],
			python: [
				/\brandom\.(?:random|randint|choice|choices|randrange|getrandbits|sample)\s*\(/g,
			],
			php: [/(?<![\w>$])(?:rand|mt_rand|uniqid|lcg_value)\s*\(/g],
			java: [/\bnew\s+Random\s*\(/g],
			go: [/\brand\.(?:Int|Intn|Int63|Int31|Read)\s*\(/g],
		},
		when: ({ line, path, text }) =>
			SENSITIVE_NAME.test(
				line.replace(/Math\.random|random\.\w+|rand\w*/g, ""),
			) &&
			(languageOf(path) !== "go" || /"math\/rand"/.test(text)),
	},
	{
		id: "tls-verification-disabled",
		title: "TLS certificate verification disabled",
		severity: "high",
		confidence: "high",
		cwe: 295,
		owasp: "a02",
		message:
			"Certificate validation is turned off, so connections can be intercepted by anyone on the network path (MITM).",
		remediation:
			"Keep verification on. For private CAs, configure the CA bundle (ca option, REQUESTS_CA_BUNDLE, RootCAs) instead of disabling checks.",
		patterns: {
			js: [
				/\brejectUnauthorized\s*:\s*false\b/g,
				/NODE_TLS_REJECT_UNAUTHORIZED["'\]]?\s*[=:]\s*["']?0\b/g,
			],
			config: [/NODE_TLS_REJECT_UNAUTHORIZED["']?\s*[=:]\s*["']?0\b/g],
			python: [
				/\bverify\s*=\s*False\b/g,
				/\bssl\._create_unverified_context\b/g,
				/\bcheck_hostname\s*=\s*False\b/g,
				/\bcert_reqs\s*=\s*(?:ssl\.)?CERT_NONE\b/g,
			],
			go: [/\bInsecureSkipVerify\s*:\s*true\b/g],
			php: [
				/CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b/g,
				/["']verify["']\s*=>\s*false\b/g,
			],
			ruby: [/OpenSSL::SSL::VERIFY_NONE\b/g],
			java: [
				/\bNoopHostnameVerifier\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bTrustAllStrategy\b|\bInsecureTrustManagerFactory\b/g,
			],
			csharp: [
				/ServerCertificate(?:Custom)?ValidationCallback\s*=\s*[^;\n]*=>\s*true/g,
				/\bDangerousAcceptAnyServerCertificateValidator\b/g,
			],
		},
	},
	{
		id: "cors-wildcard-credentials",
		title: "Permissive CORS with credentials",
		severity: "high",
		confidence: "medium",
		cwe: 942,
		owasp: "a05",
		message:
			"CORS allows any (or a reflected) origin while also allowing credentials, letting any website make authenticated requests on behalf of users.",
		remediation:
			"Allow an explicit list of trusted origins when credentials are enabled; never combine `*`/reflected origins with credentials.",
		patterns: {
			js: [
				/\borigin\s*:\s*(?:["']\*["']|true)/g,
				/Access-Control-Allow-Origin["']?\s*,\s*(?:["']\*["']|req\.headers\.origin|req\.get\(["']origin["']\))/gi,
			],
			python: [
				/\bCORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True\b/g,
				/\bCORS\s*\((?![^)\n]*origins)[^)\n]*supports_credentials\s*=\s*True/g,
				/allow_origins\s*=\s*\[\s*["']\*["']\s*\]/g,
			],
			go: [
				/\bAllowAllOrigins\s*:\s*true\b|AllowOrigins\s*:\s*\[\]string\{\s*"\*"\s*\}/g,
			],
			php: [/Access-Control-Allow-Origin:\s*\*/g],
		},
		when: ({ text }) =>
			/credentials["']?\s*[:=,]\s*["']?true|allow_credentials\s*=\s*True|AllowCredentials\s*:\s*true|Allow-Credentials:\s*true/i.test(
				text,
			),
	},
	{
		id: "jwt-verification-disabled",
		title: "JWT signature verification disabled",
		severity: "high",
		confidence: "high",
		cwe: 347,
		owasp: "a02",
		message:
			"JWTs are accepted without verifying their signature (or with the `none` algorithm), so anyone can forge tokens.",
		remediation:
			"Always verify tokens with an explicit allow-list of strong algorithms (e.g. RS256/ES256/HS256) and a trusted key.",
		patterns: {
			js: [
				/\balgorithms\s*:\s*\[[^\]\n]*["']none["']/gi,
				/\balg(?:orithm)?\s*:\s*["']none["']/gi,
			],
			python: [
				/["']verify_signature["']\s*:\s*False\b/g,
				/\bjwt\.decode\([^)\n]*verify\s*=\s*False/g,
				/\balgorithms\s*=\s*\[[^\]\n]*["']none["']/gi,
			],
			go: [
				/\bjwt\.SigningMethodNone\b|\bUnsafeAllowNoneSignatureType\b|\.ParseUnverified\(/g,
			],
			java: [/\.parseUnsecuredClaims\(|\bAlgorithm\.none\(\)/g],
			ruby: [/\bJWT\.decode\([^)\n]*,\s*(?:nil|false)\s*(?:,|\))/g],
		},
		references: [
			"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
		],
	},
	{
		id: "insecure-deserialization",
		title: "Insecure deserialization",
		severity: "high",
		confidence: "medium",
		cwe: 502,
		owasp: "a08",
		message:
			"Data is deserialized with a format that can instantiate arbitrary objects. Untrusted input leads to remote code execution.",
		remediation:
			"Deserialize untrusted data only with data-only formats (JSON) or safe loaders (yaml.safe_load, allowed_classes => false, type allow-lists).",
		patterns: {
			python: [
				/\b(?:pickle|cPickle|dill|shelve|marshal|jsonpickle)\.(?:loads?|decode|open|Unpickler)\s*\(/g,
				/\byaml\.(?:load|load_all)\s*\(/g,
				/\byaml\.unsafe_load(?:_all)?\s*\(/g,
			],
			php: [/(?<![\w>$])unserialize\s*\(/g],
			ruby: [/\bMarshal\.load\b|\bYAML\.unsafe_load\b|\bOj\.load\b/g],
			java: [
				/\bnew\s+ObjectInputStream\s*\(|\bnew\s+XMLDecoder\s*\(|\.enableDefaultTyping\s*\(/g,
			],
			js: [
				/require\(\s*["']node-serialize["']\s*\)|from\s+["']node-serialize["']/g,
			],
			csharp: [
				/\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bLosFormatter\b|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects)/g,
			],
		},
		when: ({ match, args }) => {
			if (/yaml\.(?:load|load_all)/.test(match))
				return !/(?:Safe|CSafe|Base)Loader/.test(args);
			if (/unserialize/.test(match))
				return !/allowed_classes["']?\s*=>\s*false/.test(args);
			return true;
		},
	},
	{
		id: "debug-mode-enabled",
		title: "Debug mode enabled",
		severity: "medium",
		confidence: "medium",
		cwe: 489,
		owasp: "a05",
		message:
			"Debug mode exposes stack traces, settings and sometimes an interactive console to anyone who triggers an error.",
		remediation:
			"Drive debug from an environment variable that defaults to off (e.g. DEBUG = os.environ.get('DEBUG') == '1').",
		patterns: {
			python: [
				/^\s*DEBUG\s*=\s*True\b/gm,
				/\.run\s*\([^)\n]*\bdebug\s*=\s*True/g,
			],
			php: [
				/ini_set\(\s*["']display_errors["']\s*,\s*["']?(?:1|on|true)["']?\s*\)/gi,
			],
		},
		when: ({ match, path }) =>
			!/DEBUG\s*=/.test(match) ||
			/(^|\/)(settings[^/]*|config|production)\.py$|\/settings\//.test(path),
	},
	{
		id: "cleartext-http-endpoint",
		title: "API endpoint over plain HTTP",
		severity: "low",
		confidence: "medium",
		cwe: 319,
		owasp: "a02",
		message:
			"An API endpoint is hardcoded with http://, so requests and credentials travel unencrypted.",
		remediation:
			"Use https:// and load endpoints from configuration so environments can differ without code changes.",
		patterns: {
			js: [/["'`]http:\/\/[^"'`\s]+["'`]/g],
			python: [/["']http:\/\/[^"'\s]+["']/g],
			go: [/"http:\/\/[^"\s]+"/g],
			php: [/["']http:\/\/[^"'\s]+["']/g],
			ruby: [/["']http:\/\/[^"'\s]+["']/g],
			java: [/"http:\/\/[^"\s]+"/g],
			csharp: [/"http:\/\/[^"\s]+"/g],
		},
		when: ({ match }) => {
			const url = match.slice(1, -1);
			if (
				/^http:\/\/(?:localhost|127\.|0\.0\.0\.0|\[::1\]|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|[^/:]*\.(?:local|localhost|test|example|internal|invalid|lan)(?:[:/]|$)|(?:[\w-]+\.)?example\.(?:com|org|net)|host\.docker\.internal|[^/:.]+(?:[:/]|$))/i.test(
					url,
				)
			)
				return false;
			return /\/api(?:\/|$)|\/v\d+(?:\/|$)|\/graphql|\/rest\/|^http:\/\/api\.|\.api\.|\/oauth|\/token|\/webhook/i.test(
				url,
			);
		},
	},
	{
		id: "open-redirect",
		title: "Open redirect",
		severity: "medium",
		confidence: "medium",
		cwe: 601,
		owasp: "a01",
		message:
			"The redirect target comes straight from the request, so attackers can craft links on your domain that send users to phishing sites.",
		remediation:
			"Redirect only to relative paths or to an allow-list of known hosts; validate the parsed URL's origin before redirecting.",
		patterns: {
			js: [
				/\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?(?:req|request|ctx\.request|ctx)\.(?:query|params|body|searchParams)\b/g,
				/(?:window\.)?location(?:\.href)?\s*=\s*(?:new\s+URLSearchParams\([^)\n]*\)|\w*[Pp]arams)\.get\(/g,
			],
			python: [
				/\b(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(\s*request\.(?:args|GET|POST|form|values|query_params)\b/g,
			],
			php: [
				/header\s*\(\s*["']Location:\s*["']?\s*\.\s*\$_(?:GET|POST|REQUEST)/gi,
			],
			ruby: [/\bredirect_to\s*\(?\s*params\[/g],
			go: [/http\.Redirect\([^)\n]*r\.(?:URL\.Query\(\)|FormValue|PathValue)/g],
			java: [/\.sendRedirect\s*\(\s*request\.getParameter/g],
		},
	},
	{
		id: "path-traversal",
		title: "File path built from request input",
		severity: "high",
		confidence: "medium",
		cwe: 22,
		owasp: "a01",
		message:
			"A filesystem path is built from request parameters. Inputs like `../../etc/passwd` can read or overwrite arbitrary files.",
		remediation:
			"Resolve the path, then verify it stays inside the intended base directory (or map ids to files via an allow-list). Reject `..` and absolute paths.",
		patterns: {
			js: [
				/\b(?:path\.(?:join|resolve)|(?:fs\.)?(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|unlink|unlinkSync|readdir|readdirSync)|res\.sendFile|res\.download|Bun\.file)\s*\([^)\n]*\b(?:req|request)\.(?:params|query|body)\b/g,
			],
			python: [
				/\b(?:open|send_file|os\.path\.join|FileResponse|os\.remove|shutil\.rmtree)\s*\([^)\n]*request\.(?:args|form|GET|POST|values|files|query_params)\b/g,
			],
			php: [
				/\b(?:include|require|include_once|require_once|file_get_contents|fopen|readfile|file|unlink)\s*\(?\s*[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/g,
			],
			go: [
				/\b(?:os\.Open|os\.ReadFile|os\.Create|ioutil\.ReadFile|http\.ServeFile|filepath\.Join)\([^)\n]*r\.(?:URL\.Query\(\)|FormValue|PathValue)/g,
			],
			java: [/\bnew\s+File(?:InputStream)?\s*\([^)\n]*request\.getParameter/g],
			ruby: [
				/\b(?:File\.(?:read|open|delete)|send_file)\s*\(?\s*[^)\n]*params\[/g,
			],
		},
		when: ({ text, path, line }) =>
			languageOf(path) !== "js" ||
			!/path\.(?:join|resolve)/.test(line) ||
			/\bfs\b|node:fs|sendFile|download|createReadStream|Bun\.file/.test(text),
	},
];

/* Weak-hash patterns are shared by two rules (password vs general context). */
const WEAK_HASH: Partial<Record<Lang, ReadonlyArray<RegExp>>> = {
	js: [/\bcreateHash\s*\(\s*["'](?:md5|sha1)["']/gi],
	python: [
		/\bhashlib\.(?:md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*["'](?:md5|sha1)["']/gi,
	],
	go: [/\b(?:md5|sha1)\.(?:New|Sum)\s*\(/g],
	php: [/(?<![\w>$])(?:md5|sha1)\s*\(/g],
	ruby: [/\bDigest::(?:MD5|SHA1)\b/g],
	java: [/MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"/gi],
	csharp: [
		/\b(?:MD5|SHA1)\.Create\s*\(|new\s+(?:MD5|SHA1)CryptoServiceProvider/g,
	],
};

const rulePatterns = (rule: SastRule) =>
	rule.id === "weak-hash" || rule.id === "weak-password-hash"
		? WEAK_HASH
		: rule.patterns;

const langOf = (path: string): Lang | undefined => {
	const lang = languageOf(path);
	if (
		lang === "js" ||
		lang === "python" ||
		lang === "go" ||
		lang === "php" ||
		lang === "ruby" ||
		lang === "java" ||
		lang === "csharp"
	)
		return lang;
	const base = baseName(path);
	if (
		/^\.env(\.|$)|\.env$|^Dockerfile|\.dockerfile$|\.(ya?ml|sh|bash|zsh|toml|ini|conf)$/i.test(
			base,
		)
	)
		return "config";
	return undefined;
};

/** Text from `index` through the parenthesis that closes the first `(`. */
const callArgsAt = (text: string, index: number): string => {
	const open = text.indexOf("(", index);
	if (open === -1 || open - index > 80) return "";
	let depth = 0;
	for (let i = open; i < text.length && i - open < 2000; i++) {
		if (text[i] === "(") depth++;
		else if (text[i] === ")" && --depth === 0) return text.slice(open, i + 1);
	}
	return text.slice(open, open + 2000);
};

const windowAt = (text: string, index: number): string => {
	let end = index;
	for (let n = 0; n < 3 && end !== -1; n++) end = text.indexOf("\n", end + 1);
	return text.slice(
		text.lastIndexOf("\n", index - 1) + 1,
		end === -1 ? undefined : end,
	);
};

/** Runs every SAST rule over one file. Exported for unit tests. */
export const scanSecurity = (file: SourceFile): FindingInput[] => {
	const lang = langOf(file.path);
	if (!lang) return [];
	const { text, path } = file;
	const lineOf = lineLocator(text);
	const mask = nonCodeMask(text, lang);
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const rule of SAST_RULES) {
		for (const re of rulePatterns(rule)[lang] ?? []) {
			for (const m of text.matchAll(re)) {
				const index = m.index ?? 0;
				if (mask[index]) continue; // inside a string, comment or regex
				const line = fullLineAt(text, index);
				if (isCommentLine(line) || /openaudit-ignore|nosec|NOSONAR/.test(line))
					continue;
				if (
					rule.when &&
					!rule.when({
						match: m[0],
						args: callArgsAt(text, index),
						line,
						window: windowAt(text, index),
						text,
						path,
					})
				)
					continue;
				const lineNo = lineOf(index);
				const key = `${rule.id}:${lineNo}`;
				if (seen.has(key)) continue;
				seen.add(key);
				findings.push({
					ruleId: `code.security/${rule.id}`,
					title: rule.title,
					severity: rule.severity,
					category: "security",
					message: rule.message,
					location: { file: path, line: lineNo },
					evidence: truncate(scrubLine(line)),
					remediation: rule.remediation,
					references: [
						cweUrl(rule.cwe),
						owaspUrl(rule.owasp),
						...(rule.references ?? []),
					],
					confidence: rule.confidence,
					tags: [`cwe-${rule.cwe}`, `owasp-${rule.owasp}`],
				});
			}
		}
	}
	return findings;
};

const shouldScan = (path: string) =>
	langOf(path) !== undefined &&
	!isTestPath(path) &&
	!isFixturePath(path) &&
	!isGeneratedPath(path);

export const security = defineAuditor({
	id: "code.security",
	title: "Static security analysis",
	description:
		"Heuristic SAST for JS/TS, Python, Go, PHP, Ruby, Java and C#: injection, XSS, weak crypto, disabled TLS/JWT verification, permissive CORS, insecure deserialization, open redirects and path traversal.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, shouldScan);
			return files.flatMap(scanSecurity);
		}),
});
