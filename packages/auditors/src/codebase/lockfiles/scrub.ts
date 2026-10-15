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
/** Characters a token or URL part can hold, for cutting at a word boundary. */
const WORD_CHAR = /[\w.~+/=%-]/;

/**
 * Characters that end a URL's authority. Not `\`, which other parsers keep,
 * and not tab or newline, which WHATWG deletes from anywhere in a URL.
 */
const AUTHORITY_END = new Set(["/", "?", "#", " ", '"', "'", "<", ">"]);

/** WHATWG special schemes: any run of `/` and `\`, even none, precedes the authority. */
const SPECIAL = new Set(["http", "https", "ws", "wss", "ftp", "file"]);
const SCHEME = /([A-Za-z][A-Za-z0-9+.-]*):([\\/]*)/g;

/** Drops a URL's userinfo, up to the last `@` or `%40` of the authority. */
const stripUrlUserinfo = (s: string): string => {
	let out = "";
	let from = 0;
	SCHEME.lastIndex = 0;
	for (let m = SCHEME.exec(s); m; m = SCHEME.exec(s)) {
		const scheme = (m[1] ?? "").toLowerCase();
		const slashes = m[2] ?? "";
		// Other schemes only have an authority after exactly `//`.
		if (!SPECIAL.has(scheme) && slashes !== "//") continue;
		const start = m.index + m[0].length;
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
		// Linear: never rescan the authority just passed.
		SCHEME.lastIndex = Math.max(end, m.index + 1);
	}
	return out + s.slice(from);
};

/** scp-like `user:password@host:path` (the password may hold `/`). */
const SCP_WORD = /[^\s"'()<>]+/g;

/** A `user:password@` prefix: a colon inside a non-empty user part. */
const hasScpPassword = (colon: number, at: number) =>
	colon > 0 && colon < at - 1;

const stripScpWord = (word: string): string => {
	if (word.includes("://")) return word;
	const at = word.indexOf("@");
	if (at <= 0 || !hasScpPassword(word.indexOf(":"), at)) return word;
	return /^[\w.-]+[:/]/.test(word.slice(at + 1)) ? word.slice(at + 1) : word;
};

const stripScpUserinfo = (s: string): string =>
	s.replace(SCP_WORD, stripScpWord);

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
const SECRET_NAME =
	/token|auth|key|secret|passw|pwd|sig|credential|code|session|sid|ticket/i;

/** A parameter name as a server reads it (`%74oken` is `token`). */
const decodedName = (name: string) => {
	try {
		return decodeURIComponent(name);
	} catch {
		return name;
	}
};

/** UUIDs: classic npm tokens are lower-case v4 UUIDs. */
const UUID =
	/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

/** A path segment after one that names a credential (`/_authToken/x`, `/t/x`). */
const PATH_TOKEN =
	/\/(_?auth_?token|_?token|access[-_]?token|t|auth|key|secret|api[-_]?key)\/([^/\s?#"']+)/gi;

/** Long runs mixing upper case, lower case and digits: generated tokens. */
const RUN = /[A-Za-z0-9]{20,}/g;
const looksRandom = (run: string) =>
	/[A-Z]/.test(run) && /[a-z]/.test(run) && /\d/.test(run);

/** `s` without userinfo, credential parameters or token-like values. */
export const scrubText = (input: string): string => {
	// A token cut by the cap no longer matches its pattern, so the cut drops
	// the whole word it lands in (a backward scan: an anchored regex would
	// backtrack quadratically).
	let s = input;
	if (input.length > MAX_SCRUBBED) {
		let end = MAX_SCRUBBED;
		while (end > 0 && WORD_CHAR.test(input[end - 1] as string)) end--;
		s = `${input.slice(0, end)}…`;
	}
	return stripScpUserinfo(stripUrlUserinfo(s))
		.replace(KNOWN_TOKEN, mask)
		.replace(JWT, mask)
		.replace(UUID, mask)
		.replace(BASIC, (_, basic: string, value: string) => basic + mask(value))
		.replace(PARAM, (param, sep: string, name: string, value: string) =>
			SECRET_NAME.test(decodedName(name)) && value
				? `${sep}${name}=${mask(value)}`
				: param,
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
						Object.entries(v).map(([k, x]) => [scrubText(k), scrubValue(x)]),
					)
				: v;

/** A finding with every string in it scrubbed. */
export const scrubFinding = (f: FindingInput): FindingInput =>
	scrubValue(f) as FindingInput;
