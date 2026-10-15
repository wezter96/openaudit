/** Tokens, codes and hashes. Tokens are never logged or stored in clear. */

/** A secret bearer token. */
export type Token = string;

const hex = (bytes: ArrayBuffer | Uint8Array) =>
	[...new Uint8Array(bytes)]
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");

const base64url = (bytes: Uint8Array) =>
	btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");

const random = (length: number) =>
	crypto.getRandomValues(new Uint8Array(length));

/** SHA-256 of the text, as lowercase hex. */
export const sha256 = async (text: string): Promise<string> =>
	hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));

/** A new manage token: 32 random bytes, base64url. */
export const newManageToken = (): Token => `oam_${base64url(random(32))}`;

/** A new public verification code: 128 random bits, so it can't be guessed. */
export const newCode = (): string => `openaudit-verify-${hex(random(16))}`;

/** Compares two strings in time independent of where they differ. */
export const constantTimeEqual = (a: string, b: string): boolean => {
	const x = new TextEncoder().encode(a);
	const y = new TextEncoder().encode(b);
	let diff = x.length ^ y.length;
	for (let i = 0; i < x.length; i++)
		diff |= (x[i] ?? 0) ^ (y[i % y.length] ?? 0);
	return diff === 0;
};

/**
 * A daily-salted hash of the client's address, for the registration limit.
 * Keyed with `secret` when there is one, so the hash can't be reversed by
 * trying every IPv4 address.
 */
export const ipDayHash = async (
	ip: string,
	day: string,
	secret: Token,
): Promise<string> => {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(`openaudit-badge-ip|${secret}`),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = await crypto.subtle.sign(
		"HMAC",
		key,
		new TextEncoder().encode(`${day}|${ip}`),
	);
	return hex(mac);
};
