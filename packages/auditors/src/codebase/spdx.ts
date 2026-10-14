/**
 * SPDX licence expressions: parsing, normalisation of common non-SPDX
 * spellings, and evaluation against an allow/deny policy.
 */

export type LicenseExpr =
	| {
			readonly type: "license";
			readonly id: string;
			readonly exception?: string;
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

const aliasKey = (s: string) =>
	s
		.toLowerCase()
		.replace(/[()",]/g, " ")
		.replace(/[-_]/g, " ")
		.replace(/\b(the|licen[cs]es?|version|software)\b/g, " ")
		.replace(/\bv(?=\d)/g, " ")
		.replace(/(gpl) ?v(?=\d)/g, "$1")
		.replace(/\s+/g, " ")
		.trim();

const gnuId = (key: string): string | undefined => {
	const m = GNU.exec(key);
	if (!m) return undefined;
	const [, short, long, major, minor, later] = m;
	const family = /^a|affero/.test(short ?? long ?? "")
		? "AGPL"
		: /^l|lesser|library/.test(short ?? long ?? "")
			? "LGPL"
			: "GPL";
	// An unversioned GPL lets the recipient pick any published version.
	if (!major)
		return `${family}-${{ AGPL: "3.0", LGPL: "2.0", GPL: "1.0" }[family]}-or-later`;
	return `${family}-${major}.${minor ?? "0"}-${later ? "or-later" : "only"}`;
};

const lookupAlias = (raw: string): string | undefined => {
	const key = aliasKey(raw);
	return ALIASES[key] ?? gnuId(key);
};

/**
 * Canonical SPDX id for a common spelling (`Apache 2.0`, `GPLv3`, deprecated
 * `GPL-2.0`); anything unrecognised is returned trimmed, as written.
 */
export const normaliseLicenseId = (raw: string): string =>
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

/** Strict SPDX syntax (operators in any case); `undefined` when malformed. */
const parseExpression = (raw: string): LicenseExpr | undefined => {
	const tokens = raw.match(/\(|\)|[^\s()]+/g) ?? [];
	let i = 0;
	const op = (name: string) => tokens[i]?.toUpperCase() === name;
	const id = (): string | undefined => {
		const t = tokens[i];
		if (!t || t === "(" || t === ")" || OPERATORS.has(t.toUpperCase()))
			return undefined;
		i++;
		return t;
	};
	const atom = (): LicenseExpr | undefined => {
		if (tokens[i] === "(") {
			i++;
			const inner = or();
			if (!inner || tokens[i] !== ")") return undefined;
			i++;
			return inner;
		}
		const token = id();
		if (!token) return undefined;
		const license = normaliseLicenseId(token);
		if (!VALID_ID.test(license)) return undefined;
		if (!op("WITH")) return { type: "license", id: license };
		i++;
		const exception = id();
		return exception && VALID_ID.test(exception)
			? { type: "license", id: license, exception }
			: undefined;
	};
	const sequence =
		(name: "AND" | "OR", next: () => LicenseExpr | undefined) =>
		(): LicenseExpr | undefined => {
			const first = next();
			if (!first) return undefined;
			const args = [first];
			while (op(name)) {
				i++;
				const more = next();
				if (!more) return undefined;
				args.push(more);
			}
			return join(name === "AND" ? "and" : "or", args);
		};
	const and = sequence("AND", atom);
	const or = sequence("OR", and);
	if (!tokens.length) return undefined;
	const expr = or();
	return expr && i === tokens.length ? expr : undefined;
};

/** Free text such as a Python classifier: the whole string, then its parts. */
const parseFreeText = (raw: string): LicenseExpr | undefined => {
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
export const parseLicense = (raw: string): LicenseExpr | undefined => {
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

export const formatLicenseExpression = (expr: LicenseExpr): string => {
	if (expr.type === "license")
		return expr.exception ? `${expr.id} WITH ${expr.exception}` : expr.id;
	return expr.args
		.map((a) =>
			a.type === "license"
				? formatLicenseExpression(a)
				: `(${formatLicenseExpression(a)})`,
		)
		.join(expr.type === "and" ? " AND " : " OR ");
};

/* -------------------------------------------------------------------------- */
/*                                   Policy                                   */
/* -------------------------------------------------------------------------- */

interface Matcher {
	readonly id: RegExp;
	readonly exception?: RegExp;
	/** Starts with `*`: too broad to accept or reject an unknown licence. */
	readonly broad: boolean;
}

export interface LicensePolicy {
	readonly deny: ReadonlyArray<Matcher>;
	/** Absent: everything that is not denied passes. */
	readonly allow?: ReadonlyArray<Matcher>;
}

const PATTERN = /^[A-Za-z0-9*][A-Za-z0-9.+:*-]*$/;

/** Case-insensitive, anchored match where `*` is the only wildcard. */
export const globRegExp = (glob: string): RegExp =>
	// The pattern is escaped, so it only matches literally apart from `*`.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	new RegExp(
		`^${glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`,
		"i",
	);

const compilePattern = (raw: string): Matcher => {
	const [license = "", exception, ...rest] = raw.trim().split(/\s+WITH\s+/i);
	const id = license.includes("*") ? license : normaliseLicenseId(license);
	if (
		rest.length ||
		!PATTERN.test(id) ||
		(exception !== undefined && !PATTERN.test(exception))
	)
		throw new Error(
			`Licence policy entry "${raw}" must be a single licence id or glob (MIT, GPL-*), optionally with "WITH <exception>"`,
		);
	return {
		id: globRegExp(id),
		...(exception ? { exception: globRegExp(exception) } : {}),
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
	readonly culprits: ReadonlyArray<string>;
}

/** Placeholders and proprietary markers that grant nothing on their own. */
const isUnknownId = (id: string) =>
	/^(NOASSERTION|NONE|UNLICENSED|UNKNOWN|PROPRIETARY|CUSTOM|OTHER|COMMERCIAL)$/i.test(
		id,
	) || /^(LicenseRef|DocumentRef)-/i.test(id);

/** An `-or-later` / `+` licence also matches entries for its base version. */
const idCandidates = (id: string) =>
	id.endsWith("-or-later")
		? [id, id.replace(/-or-later$/, "-only")]
		: id.endsWith("+")
			? [id, id.slice(0, -1)]
			: [id];

const leafStatus = (
	id: string,
	exception: string | undefined,
	unknown: boolean,
	policy: LicensePolicy,
): LicenseStatus => {
	const ids = idCandidates(id);
	const matches = (list: ReadonlyArray<Matcher>, withException: boolean) =>
		list.some(
			(m) =>
				!(unknown && m.broad) &&
				(withException
					? m.exception !== undefined &&
						exception !== undefined &&
						m.exception.test(exception)
					: m.exception === undefined) &&
				ids.some((x) => m.id.test(x)),
		);
	// An entry naming the exact exception wins over one for the bare licence.
	if (exception) {
		if (matches(policy.deny, true)) return "denied";
		if (policy.allow && matches(policy.allow, true)) return "ok";
	}
	if (matches(policy.deny, false)) return "denied";
	if (policy.allow && matches(policy.allow, false)) return "ok";
	if (unknown) return "unknown";
	return policy.allow ? "not-allowed" : "ok";
};

const evaluate = (expr: LicenseExpr, policy: LicensePolicy): LicenseVerdict => {
	if (expr.type === "license") {
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
	}
	const parts = expr.args.map((a) => evaluate(a, policy));
	const ranks = parts.map((p) => RANK[p.status]);
	// OR: the consumer may pick the best alternative. AND: every term applies.
	const rank = expr.type === "or" ? Math.min(...ranks) : Math.max(...ranks);
	const status = parts.find((p) => RANK[p.status] === rank)?.status ?? "ok";
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
	raw: string,
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
