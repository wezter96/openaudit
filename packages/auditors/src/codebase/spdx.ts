/**
 * SPDX licence expressions: parsing, normalisation of common non-SPDX
 * spellings, and evaluation against an allow/deny policy.
 */

/** A licence as declared or configured, before it is parsed. */
export type LicenseText = string;
/** An SPDX licence id (`MIT`) or exception id (`Classpath-exception-2.0`). */
export type LicenseId = string;
/** A policy entry's id, where `*` is the only wildcard. */
export type GlobPattern = string;

export type LicenseExpr =
	| {
			readonly type: "license";
			readonly id: LicenseId;
			readonly exception?: LicenseId;
	  }
	| { readonly type: "and" | "or"; readonly args: ReadonlyArray<LicenseExpr> };

/* -------------------------------------------------------------------------- */
/*                               Normalisation                                */
/* -------------------------------------------------------------------------- */

const ALIASES: Readonly<Record<string, string>> = {
	mit: "MIT",
	expat: "MIT",
	"apache 2.0": "Apache-2.0",
	"apache 2": "Apache-2.0",
	apache2: "Apache-2.0",
	"apache2.0": "Apache-2.0",
	// Python's "Apache Software License" classifier carries no version.
	apache: "Apache-2.0",
	"asl 2.0": "Apache-2.0",
	"asl 2": "Apache-2.0",
	asl2: "Apache-2.0",
	"apache 1.1": "Apache-1.1",
	"bsd 3 clause": "BSD-3-Clause",
	"bsd 3": "BSD-3-Clause",
	bsd3: "BSD-3-Clause",
	"new bsd": "BSD-3-Clause",
	"bsd new": "BSD-3-Clause",
	"modified bsd": "BSD-3-Clause",
	"revised bsd": "BSD-3-Clause",
	"3 clause bsd": "BSD-3-Clause",
	"bsd 2 clause": "BSD-2-Clause",
	"bsd 2": "BSD-2-Clause",
	bsd2: "BSD-2-Clause",
	"simplified bsd": "BSD-2-Clause",
	freebsd: "BSD-2-Clause",
	"2 clause bsd": "BSD-2-Clause",
	"bsd 4 clause": "BSD-4-Clause",
	"0bsd": "0BSD",
	isc: "ISC",
	iscl: "ISC",
	"mpl 2.0": "MPL-2.0",
	"mpl 2": "MPL-2.0",
	mpl2: "MPL-2.0",
	"mozilla public 2.0": "MPL-2.0",
	"mozilla public 2": "MPL-2.0",
	"mpl 1.1": "MPL-1.1",
	"mozilla public 1.1": "MPL-1.1",
	"epl 2.0": "EPL-2.0",
	"eclipse public 2.0": "EPL-2.0",
	"epl 1.0": "EPL-1.0",
	"eclipse public 1.0": "EPL-1.0",
	cc0: "CC0-1.0",
	"cc0 1.0": "CC0-1.0",
	"cc0 1.0 universal": "CC0-1.0",
	"creative commons zero 1.0 universal": "CC0-1.0",
	"cc by 4.0": "CC-BY-4.0",
	"cc by 3.0": "CC-BY-3.0",
	"cc by sa 4.0": "CC-BY-SA-4.0",
	unlicense: "Unlicense",
	psf: "PSF-2.0",
	psfl: "PSF-2.0",
	"psf 2.0": "PSF-2.0",
	"python foundation": "PSF-2.0",
	zlib: "Zlib",
	wtfpl: "WTFPL",
	"boost 1.0": "BSL-1.0",
	"bsl 1.0": "BSL-1.0",
	boost: "BSL-1.0",
	"artistic 2.0": "Artistic-2.0",
	"cddl 1.0": "CDDL-1.0",
	"cddl 1.1": "CDDL-1.1",
	"eupl 1.2": "EUPL-1.2",
	"sspl 1.0": "SSPL-1.0",
	sspl: "SSPL-1.0",
	"server side public 1.0": "SSPL-1.0",
};

/** `GPL-2.0+`, `GPLv3`, `GNU Lesser General Public License v2.1 or later`, ... */
const GNU =
	/^(?:gnu )?(?:(agpl|lgpl|gpl)|(affero |lesser |library |library or lesser )?general public)(?: ?(\d+)(?:\.(\d+))?)?( ?\+| or later| or any later)?(?: only)?$/;

/** Lowercased text with punctuation and filler words removed. */
type AliasKey = string;

const aliasKey = (s: LicenseText): AliasKey =>
	s
		.toLowerCase()
		.replace(/[()",]/g, " ")
		.replace(/[-_]/g, " ")
		.replace(/\b(the|licen[cs]es?|version|software)\b/g, " ")
		.replace(/\bv(?=\d)/g, " ")
		.replace(/(gpl) ?v(?=\d)/g, "$1")
		.replace(/\s+/g, " ")
		.trim();

type GnuFamily = "AGPL" | "LGPL" | "GPL";

/** The GNU licence family named by `agpl`/`lgpl`/`gpl` or its long form. */
const gnuFamily = (name: AliasKey): GnuFamily => {
	if (/^a|affero/.test(name)) return "AGPL";
	return /^l|lesser|library/.test(name) ? "LGPL" : "GPL";
};

/** The version an unversioned GNU licence starts from. */
const GNU_FIRST_VERSION: Record<GnuFamily, string> = {
	AGPL: "3.0",
	LGPL: "2.0",
	GPL: "1.0",
};

const gnuId = (key: AliasKey): LicenseId | undefined => {
	const m = GNU.exec(key);
	if (!m) return undefined;
	const [, short, long, major, minor, later] = m;
	const family = gnuFamily(short ?? long ?? "");
	// An unversioned GPL lets the recipient pick any published version.
	if (!major) return `${family}-${GNU_FIRST_VERSION[family]}-or-later`;
	return `${family}-${major}.${minor ?? "0"}-${later ? "or-later" : "only"}`;
};

const lookupAlias = (raw: LicenseText): LicenseId | undefined => {
	const key = aliasKey(raw);
	return ALIASES[key] ?? gnuId(key);
};

/**
 * Canonical SPDX id for a common spelling (`Apache 2.0`, `GPLv3`, deprecated
 * `GPL-2.0`); anything unrecognised is returned trimmed, as written.
 */
export const normaliseLicenseId = (raw: LicenseText): LicenseId =>
	lookupAlias(raw) ?? raw.trim();

/* -------------------------------------------------------------------------- */
/*                                  Parsing                                   */
/* -------------------------------------------------------------------------- */

const VALID_ID = /^[A-Za-z0-9][A-Za-z0-9.+:-]*$/;
const OPERATORS = new Set(["AND", "OR", "WITH"]);

const join = (
	type: "and" | "or",
	args: ReadonlyArray<LicenseExpr>,
): LicenseExpr => {
	if (args.length === 1 && args[0]) return args[0];
	return {
		type,
		args: args.flatMap((a) => (a.type === type ? a.args : [a])),
	};
};

/** Tokens of an expression and the position of the next one to read. */
interface Cursor {
	readonly tokens: ReadonlyArray<string>;
	i: number;
}

type Reader = (c: Cursor) => LicenseExpr | undefined;

const atOperator = (c: Cursor, name: "AND" | "OR" | "WITH") =>
	c.tokens[c.i]?.toUpperCase() === name;

const isBracket = (t: LicenseText) => t === "(" || t === ")";

const isIdToken = (t: LicenseText | undefined): t is LicenseText => {
	if (!t) return false;
	return !isBracket(t) && !OPERATORS.has(t.toUpperCase());
};

const readId = (c: Cursor): LicenseId | undefined => {
	const t = c.tokens[c.i];
	if (!isIdToken(t)) return undefined;
	c.i++;
	return t;
};

/** `id` or `id WITH exception`. */
const readLicense: Reader = (c) => {
	const token = readId(c);
	if (!token) return undefined;
	const license = normaliseLicenseId(token);
	if (!VALID_ID.test(license)) return undefined;
	if (!atOperator(c, "WITH")) return { type: "license", id: license };
	c.i++;
	const exception = readId(c);
	return exception && VALID_ID.test(exception)
		? { type: "license", id: license, exception }
		: undefined;
};

/** `( expression )`, with the cursor on the opening bracket. */
const readGroup: Reader = (c) => {
	c.i++;
	const inner = readOr(c);
	if (!inner || c.tokens[c.i] !== ")") return undefined;
	c.i++;
	return inner;
};

const readAtom: Reader = (c) =>
	c.tokens[c.i] === "(" ? readGroup(c) : readLicense(c);

/** `next (name next)*`, joined into one `and`/`or` node. */
const readSequence = (
	c: Cursor,
	name: "AND" | "OR",
	next: Reader,
): LicenseExpr | undefined => {
	const first = next(c);
	if (!first) return undefined;
	const args = [first];
	while (atOperator(c, name)) {
		c.i++;
		const more = next(c);
		if (!more) return undefined;
		args.push(more);
	}
	return join(name === "AND" ? "and" : "or", args);
};

const readAnd: Reader = (c) => readSequence(c, "AND", readAtom);
const readOr: Reader = (c) => readSequence(c, "OR", readAnd);

/** Strict SPDX syntax (operators in any case); `undefined` when malformed. */
const parseExpression = (raw: LicenseText): LicenseExpr | undefined => {
	const tokens = raw.match(/\(|\)|[^\s()]+/g) ?? [];
	if (!tokens.length) return undefined;
	const cursor: Cursor = { tokens, i: 0 };
	const expr = readOr(cursor);
	return expr && cursor.i === tokens.length ? expr : undefined;
};

/** Free text such as a Python classifier: the whole string, then its parts. */
const parseFreeText = (raw: LicenseText): LicenseExpr | undefined => {
	if (raw.split("(").length !== raw.split(")").length) return undefined;
	const outside = raw.replace(/\([^)]*\)/g, " ");
	const inside = [...raw.matchAll(/\(([^)]*)\)/g)].map((m) => m[1] ?? "");
	for (const candidate of [raw, outside, ...inside]) {
		const id = lookupAlias(candidate);
		if (id) return { type: "license", id };
	}
	return undefined;
};

/**
 * Parses a declared licence: an SPDX expression, a known non-SPDX spelling
 * (`Apache License, Version 2.0`), or a list separated by `/` or `,` (read as
 * alternatives, as npm's legacy `licenses` arrays and old crates use them).
 * `undefined` when nothing usable can be read.
 */
export const parseLicense = (raw: LicenseText): LicenseExpr | undefined => {
	const text = raw.trim();
	if (!text) return undefined;
	const parsed = parseExpression(text) ?? parseFreeText(text);
	if (parsed || !/[/,]/.test(text)) return parsed;
	const parts = text.split(/\s*[/,]\s*/).filter(Boolean);
	const alternatives = parts.map((p) => parseExpression(p) ?? parseFreeText(p));
	return alternatives.length > 1 && alternatives.every((a) => a !== undefined)
		? join("or", alternatives as LicenseExpr[])
		: undefined;
};

export const formatLicenseExpression = (expr: LicenseExpr): LicenseText => {
	if (expr.type === "license")
		return expr.exception ? `${expr.id} WITH ${expr.exception}` : expr.id;
	return expr.args
		.map(formatOperand)
		.join(expr.type === "and" ? " AND " : " OR ");
};

/** An operand of AND/OR, bracketed unless it is a single licence. */
const formatOperand = (a: LicenseExpr): LicenseText =>
	a.type === "license"
		? formatLicenseExpression(a)
		: `(${formatLicenseExpression(a)})`;

/* -------------------------------------------------------------------------- */
/*                                   Policy                                   */
/* -------------------------------------------------------------------------- */

/** A compiled glob; `test` mirrors RegExp so either can be passed around. */
export interface Glob {
	readonly test: (value: LicenseText) => boolean;
}

interface Matcher {
	readonly id: Glob;
	readonly exception?: Glob;
	/** Starts with `*`: too broad to accept or reject an unknown licence. */
	readonly broad: boolean;
}

export interface LicensePolicy {
	readonly deny: ReadonlyArray<Matcher>;
	/** Absent: everything that is not denied passes. */
	readonly allow?: ReadonlyArray<Matcher>;
}

const PATTERN = /^[A-Za-z0-9*][A-Za-z0-9.+:*-]*$/;

/**
 * Case-insensitive, anchored match where `*` is the only wildcard. Globs and
 * the values they test both come from the audited target, so this is the
 * classic greedy matcher with one backtrack point (at most
 * O(pattern × value)), not a regex, which `*a*a*…b` would send into
 * catastrophic backtracking.
 */
export const globMatcher = (glob: GlobPattern): Glob => {
	const pattern = glob.toLowerCase();
	return { test: (raw) => globMatches(pattern, raw.toLowerCase()) };
};

const globMatches = (pattern: GlobPattern, value: LicenseText): boolean => {
	let p = 0;
	let v = 0;
	let star = -1;
	let resume = 0;
	while (v < value.length) {
		if (pattern[p] === "*") {
			star = p++;
			resume = v;
		} else if (pattern[p] === value[v]) {
			p++;
			v++;
		} else if (star !== -1) {
			p = star + 1;
			v = ++resume;
		} else return false;
	}
	while (pattern[p] === "*") p++;
	return p === pattern.length;
};

/** A policy id or exception: an SPDX-like id that may contain `*`. */
const isPattern = (s: GlobPattern | undefined) =>
	s === undefined || PATTERN.test(s);

const compilePattern = (raw: LicenseText): Matcher => {
	const [license = "", exception, ...rest] = raw.trim().split(/\s+WITH\s+/i);
	const id = license.includes("*") ? license : normaliseLicenseId(license);
	const wellFormed = isPattern(id) && isPattern(exception);
	if (rest.length || !wellFormed)
		throw new Error(
			`Licence policy entry "${raw}" must be a single licence id or glob (MIT, GPL-*), optionally with "WITH <exception>"`,
		);
	return {
		id: globMatcher(id),
		...(exception ? { exception: globMatcher(exception) } : {}),
		broad: id.startsWith("*"),
	};
};

/**
 * Compiles deny/allow entries: SPDX ids or `*` globs, case-insensitive, with
 * common spellings normalised. Throws on an entry that is not a single id.
 */
export const compileLicensePolicy = (input: {
	readonly deny?: ReadonlyArray<string>;
	readonly allow?: ReadonlyArray<string>;
}): LicensePolicy => ({
	deny: (input.deny ?? []).map(compilePattern),
	...(input.allow ? { allow: input.allow.map(compilePattern) } : {}),
});

export type LicenseStatus = "ok" | "unknown" | "not-allowed" | "denied";

const RANK: Record<LicenseStatus, number> = {
	ok: 0,
	unknown: 1,
	"not-allowed": 2,
	denied: 3,
};

export interface LicenseVerdict {
	readonly status: LicenseStatus;
	/** The licences that caused a non-`ok` status. */
	readonly culprits: ReadonlyArray<LicenseText>;
}

/** Placeholders and proprietary markers that grant nothing on their own. */
const isUnknownId = (id: LicenseId) =>
	/^(NOASSERTION|NONE|UNLICENSED|UNKNOWN|PROPRIETARY|CUSTOM|OTHER|COMMERCIAL)$/i.test(
		id,
	) || /^(LicenseRef|DocumentRef)-/i.test(id);

/** An `-or-later` / `+` licence also matches entries for its base version. */
const idCandidates = (id: LicenseId) =>
	id.endsWith("-or-later")
		? [id, id.replace(/-or-later$/, "-only")]
		: id.endsWith("+")
			? [id, id.slice(0, -1)]
			: [id];

/** One licence of an expression, as the policy sees it. */
interface Leaf {
	/** The id, plus its base version for an `-or-later` / `+` licence. */
	readonly ids: ReadonlyArray<LicenseId>;
	readonly exception: LicenseId | undefined;
	/** A placeholder or unreadable licence: broad entries do not apply. */
	readonly unknown: boolean;
}

/** Whether an entry's exception part fits: named exactly, or absent. */
const exceptionFits = (m: Matcher, leaf: Leaf, withException: boolean) => {
	if (!withException) return m.exception === undefined;
	if (m.exception === undefined || leaf.exception === undefined) return false;
	return m.exception.test(leaf.exception);
};

const entryMatches = (m: Matcher, leaf: Leaf, withException: boolean) => {
	if (leaf.unknown && m.broad) return false;
	if (!exceptionFits(m, leaf, withException)) return false;
	return leaf.ids.some((x) => m.id.test(x));
};

const anyMatches = (
	list: ReadonlyArray<Matcher>,
	leaf: Leaf,
	withException: boolean,
) => list.some((m) => entryMatches(m, leaf, withException));

/** An entry naming the exact exception wins over one for the bare licence. */
const exceptionStatus = (
	leaf: Leaf,
	policy: LicensePolicy,
): LicenseStatus | undefined => {
	if (!leaf.exception) return undefined;
	if (anyMatches(policy.deny, leaf, true)) return "denied";
	if (policy.allow && anyMatches(policy.allow, leaf, true)) return "ok";
	return undefined;
};

const bareStatus = (leaf: Leaf, policy: LicensePolicy): LicenseStatus => {
	if (anyMatches(policy.deny, leaf, false)) return "denied";
	if (policy.allow && anyMatches(policy.allow, leaf, false)) return "ok";
	if (leaf.unknown) return "unknown";
	return policy.allow ? "not-allowed" : "ok";
};

const leafStatus = (
	id: LicenseId,
	exception: LicenseId | undefined,
	unknown: boolean,
	policy: LicensePolicy,
): LicenseStatus => {
	const leaf: Leaf = { ids: idCandidates(id), exception, unknown };
	return exceptionStatus(leaf, policy) ?? bareStatus(leaf, policy);
};

const evaluateLicenseLeaf = (
	expr: Extract<LicenseExpr, { type: "license" }>,
	policy: LicensePolicy,
): LicenseVerdict => {
	const status = leafStatus(
		expr.id,
		expr.exception,
		isUnknownId(expr.id),
		policy,
	);
	return {
		status,
		culprits: status === "ok" ? [] : [formatLicenseExpression(expr)],
	};
};

/** OR: the consumer may pick the best alternative. AND: every term applies. */
const combinedStatus = (
	type: "and" | "or",
	parts: ReadonlyArray<LicenseVerdict>,
): LicenseStatus => {
	const ranks = parts.map((p) => RANK[p.status]);
	const rank = type === "or" ? Math.min(...ranks) : Math.max(...ranks);
	return parts.find((p) => RANK[p.status] === rank)?.status ?? "ok";
};

const evaluate = (expr: LicenseExpr, policy: LicensePolicy): LicenseVerdict => {
	if (expr.type === "license") return evaluateLicenseLeaf(expr, policy);
	const parts = expr.args.map((a) => evaluate(a, policy));
	const status = combinedStatus(expr.type, parts);
	if (status === "ok") return { status, culprits: [] };
	const culprits = parts.flatMap((p) =>
		expr.type === "or" || p.status === status ? p.culprits : [],
	);
	return { status, culprits: [...new Set(culprits)] };
};

/**
 * Evaluates a declared licence against the policy. `OR` passes when any
 * alternative passes, `AND` needs every term to pass. Missing, proprietary
 * and unreadable licences are `unknown` unless the policy names them.
 */
export const evaluateLicense = (
	raw: LicenseText,
	policy: LicensePolicy,
): LicenseVerdict => {
	const expr = parseLicense(raw);
	if (expr) return evaluate(expr, policy);
	const text = raw.trim();
	const status = text ? leafStatus(text, undefined, true, policy) : "unknown";
	return {
		status,
		culprits: status === "ok" ? [] : [text || "(none)"],
	};
};
