import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import {
	isPrivateAddress,
	parsePublicUrl,
	SsrfError,
} from "@openaudit/core/ssrf";

import { ScanError } from "./errors";

/** Resolves a hostname to every address it has. Injectable for tests. */
export type Resolver = (hostname: string) => Promise<ReadonlyArray<string>>;

export const dnsResolver: Resolver = async (hostname) =>
	(await lookup(hostname, { all: true, verbatim: true })).map(
		(entry) => entry.address,
	);

/**
 * The site URL as the API stores it: https, a public hostname (no IP literal,
 * `localhost`, `.local`, `.internal` or `.lan`), no credentials, port 443.
 */
export const parseSiteUrl = (input: string): URL => {
	let url: URL;
	try {
		url = parsePublicUrl(input);
	} catch (cause) {
		throw new ScanError(
			cause instanceof SsrfError ? cause.message : "invalid site URL",
		);
	}
	const host = url.hostname.replace(/^\[|\]$/g, "");
	// URL drops a default port, so `https://host:443` has port "".
	if (url.protocol !== "https:" || url.port !== "")
		throw new ScanError("the site must be an https URL on port 443");
	if (isIP(host) !== 0)
		throw new ScanError("the site must use a hostname, not an IP address");
	return url;
};

/**
 * Checks the site and resolves its host, refusing it unless every address is
 * public: private, loopback, link-local, CGNAT (100.64.0.0/10, Tailscale),
 * ULA and metadata addresses are all rejected. Returns the URL to audit.
 */
export const assertPublicSite = async (
	input: string,
	resolve: Resolver = dnsResolver,
): Promise<string> => {
	const url = parseSiteUrl(input);
	const host = url.hostname.replace(/\.$/, "");
	const addresses = await resolve(host).catch(() => []);
	if (addresses.length === 0) throw new ScanError(`could not resolve ${host}`);
	if (addresses.some(isPrivateAddress))
		throw new ScanError(
			`refusing to scan ${host}: it resolves to a private or reserved address`,
		);
	return url.toString();
};
