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
 * public. `isPrivateAddress` from core rejects private, loopback, link-local
 * (incl. metadata 169.254.169.254), CGNAT (100.64.0.0/10, Tailscale), 0/8,
 * multicast and reserved IPv4, and in IPv6 everything outside 2000::/3 (ULA
 * fc00::/7, link-local, loopback) plus IPv4 embedded in mapped (::ffff:),
 * NAT64 and 6to4 addresses. Returns the URL to audit, rebuilt from the
 * checked hostname and path only: no credentials, no port.
 *
 * This is defence in depth, not a guarantee: openaudit resolves the host
 * again and follows redirects, so DNS rebinding or a redirect could still
 * reach another address. The mini PC firewall is the real boundary: it drops
 * traffic from the scanner network (172.30.77.0/24) to the LAN, the tailnet
 * and the host itself.
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
	return `https://${host}${url.pathname}${url.search}`;
};
