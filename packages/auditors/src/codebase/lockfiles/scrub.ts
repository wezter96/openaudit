import { type FindingInput, redact } from "@openaudit/core";

import { isRecord } from "../util";

/*
 * The last line of defence against credentials in findings. Every string a
 * finding carries passes through scrubText after the finding is built, so a
 * new way of quoting a URL or spec cannot leak what the builders missed.
 * Each pass is linear: no pattern rescans text it has already passed.
 */

/** Longer strings are cut first; findings never need more. */
const MAX_SCRUBBED = 16_384;

/** Characters that end a URL's authority (not `\`, which other parsers keep). */
const AUTHORITY_END = new Set([
	"/",
	"?",
	"#",
	" ",
	"\t",
	"\n",
	'"',
	"'",
	"<",
	">",
]);

/** Drops `scheme://userinfo@`, up to the last `@` or `%40` of the authority. */
const stripUrlUserinfo = (s: string): string => {
	let out = "";
	let from = 0;
	for (let i = s.indexOf("://"); i !== -1; i = s.indexOf("://", i + 3)) {
		const start = i + 3;
		let end = start;
		while (end < s.length && !AUTHORITY_END.has(s[end] as string)) end++;
		const authority = s.slice(start, end);
		const at = authority.lastIndexOf("@");
		const encoded = authority.toLowerCase().lastIndexOf("%40");
		// Length of the userinfo plus its `@` / `%40`, or 0 without one.
		const cut = Math.max(at + 1, encoded === -1 ? 0 : encoded + 3);
		if (cut > 0) {
			out += s.slice(from, start);
			from = start + cut;
		}
		i = end - 3;
	}
	return out + s.slice(from);
};

/** scp-like `user:password@host:path` (the password may hold `/`). */
const SCP_WORD = /[^\s"'()<>]+/g;

const stripScpUserinfo = (s: string): string =>
	s.replace(SCP_WORD, (word) => {
		if (word.includes("://")) return word;
		const at = word.indexOf("@");
		const colon = word.indexOf(":");
		return at > 0 &&
			colon > 0 &&
			colon < at - 1 &&
			/^[\w.-]+[:/]/.test(word.slice(at + 1))
			? word.slice(at + 1)
			: word;
	});

const mask = (token: string) => redact(token);

/** Tokens with a well-known prefix (GitHub, GitLab, npm). */
const KNOWN_TOKEN =
	/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|glpat-[\w-]{20,}|npm_[A-Za-z0-9]{30,})/g;

/** JSON Web Tokens. */
const JWT = /\beyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]{6,}/g;

/** HTTP basic credentials, also URL-encoded (`Basic%20…`). */
const BASIC = /\b(Basic(?:\s+|%20))([A-Za-z0-9+/]{8,}={0,2})/gi;

/** Query and fragment parameters; names stop at delimiters. */
const PARAM = /([?#&;])([^=?#&;\s]*)=([^?#&;\s"']*)/g;
const SECRET_NAME = /token|auth|key|secret|passw|pwd|sig|credential/i;

/** A path segment after one that names a credential (`/_authToken/x`, `/t/x`). */
const PATH_TOKEN =
	/\/(_?auth_?token|_?token|access[-_]?token|t|auth|key|secret|api[-_]?key)\/([^/\s?#"']+)/gi;

/** Long runs mixing upper case, lower case and digits: generated tokens. */
const RUN = /[A-Za-z0-9]{20,}/g;
const looksRandom = (run: string) =>
	/[A-Z]/.test(run) && /[a-z]/.test(run) && /\d/.test(run);

/** `s` without userinfo, credential parameters or token-like values. */
export const scrubText = (input: string): string => {
	const s =
		input.length > MAX_SCRUBBED ? `${input.slice(0, MAX_SCRUBBED)}…` : input;
	return stripScpUserinfo(stripUrlUserinfo(s))
		.replace(KNOWN_TOKEN, mask)
		.replace(JWT, mask)
		.replace(BASIC, (_, basic: string, value: string) => basic + mask(value))
		.replace(PARAM, (param, sep: string, name: string, value: string) =>
			SECRET_NAME.test(name) && value ? `${sep}${name}=${mask(value)}` : param,
		)
		.replace(
			PATH_TOKEN,
			(_, name: string, value: string) => `/${name}/${mask(value)}`,
		)
		.replace(RUN, (run) => (looksRandom(run) ? mask(run) : run));
};

const scrubValue = (v: unknown): unknown =>
	typeof v === "string"
		? scrubText(v)
		: Array.isArray(v)
			? v.map(scrubValue)
			: isRecord(v)
				? Object.fromEntries(
						Object.entries(v).map(([k, x]) => [k, scrubValue(x)]),
					)
				: v;

/** A finding with every string in it scrubbed. */
export const scrubFinding = (f: FindingInput): FindingInput =>
	scrubValue(f) as FindingInput;
