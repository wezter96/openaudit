/** Small parsers shared by the web auditors. */

export interface Cookie {
	readonly name: string;
	readonly value: string;
	/** Attribute names lower-cased; flag attributes map to "". */
	readonly attrs: ReadonlyMap<string, string>;
	readonly raw: string;
}

export const parseSetCookie = (raw: string): Cookie => {
	const [pair = "", ...rest] = raw.split(";");
	const eq = pair.indexOf("=");
	const name = (eq === -1 ? pair : pair.slice(0, eq)).trim();
	const value = eq === -1 ? "" : pair.slice(eq + 1).trim();
	const attrs = new Map<string, string>();
	for (const part of rest) {
		const i = part.indexOf("=");
		const key = (i === -1 ? part : part.slice(0, i)).trim().toLowerCase();
		if (key) attrs.set(key, i === -1 ? "" : part.slice(i + 1).trim());
	}
	return { name, value, attrs, raw };
};

/** Cookie header shown as evidence with its value masked. */
export const cookieEvidence = (c: Cookie): string =>
	`${c.name}=${c.value ? "…" : ""}${[...c.attrs.entries()]
		.map(([k, v]) => `; ${k}${v ? `=${v}` : ""}`)
		.join("")}`;

/** Content-Security-Policy as directive → lower-cased source list. */
export const parseCsp = (header: string): Map<string, string[]> => {
	const out = new Map<string, string[]>();
	for (const part of header.split(";")) {
		const [name, ...values] = part.trim().split(/\s+/);
		if (!name) continue;
		const key = name.toLowerCase();
		// Per spec, only the first occurrence of a directive counts.
		if (!out.has(key))
			out.set(
				key,
				values.map((v) => v.toLowerCase()),
			);
	}
	return out;
};

export const formatBytes = (n: number): string =>
	n >= 1024 * 1024
		? `${(n / 1024 / 1024).toFixed(1)} MB`
		: n >= 1024
			? `${Math.round(n / 1024)} KB`
			: `${n} B`;

export const truncate = (s: string, max = 160): string =>
	s.length > max ? `${s.slice(0, max)}…` : s;

/** Parses `max-age=N` from Cache-Control / HSTS style headers. */
export const maxAgeOf = (header: string | null): number | undefined => {
	const m = header?.match(/max-age\s*=\s*"?(\d+)/i);
	return m?.[1] ? Number(m[1]) : undefined;
};
