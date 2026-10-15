import type { HttpResponse } from "@openaudit/core";

/** A DNS name, e.g. `example.com` or `_dmarc.example.com`. */
type DnsName = string;

/* -------------------------------------------------------------------------- */
/*                              Subdomain takeover                            */
/* -------------------------------------------------------------------------- */

export interface TakeoverService {
	readonly name: string;
	/** CNAME targets (suffix match on the dot-separated name). */
	readonly suffixes: ReadonlyArray<string>;
	/** Unclaimed-resource page, per can-i-take-over-xyz. Absent: NXDOMAIN is the signal. */
	readonly fingerprint?: RegExp;
}

/**
 * Fingerprints follow https://github.com/EdOverflow/can-i-take-over-xyz.
 * CloudFront, Netlify and Fastly are left out on purpose: their "unknown
 * domain" pages also appear on healthy, merely misconfigured, setups and
 * those platforms verify domain ownership, so reporting them would be noise.
 */
const TAKEOVER_SERVICES: ReadonlyArray<TakeoverService> = [
	{
		name: "Heroku",
		suffixes: ["herokuapp.com", "herokudns.com"],
		fingerprint: /No such app/,
	},
	{
		name: "GitHub Pages",
		suffixes: ["github.io"],
		fingerprint: /There isn't a GitHub Pages site here\./,
	},
	{
		name: "AWS S3",
		suffixes: ["s3.amazonaws.com"],
		fingerprint: /The specified bucket does not exist/,
	},
	{
		name: "Shopify",
		suffixes: ["myshopify.com"],
		fingerprint: /Sorry, this shop is currently unavailable\./,
	},
	{
		name: "Surge.sh",
		suffixes: ["surge.sh"],
		fingerprint: /project not found/i,
	},
	{
		name: "Bitbucket",
		suffixes: ["bitbucket.io"],
		fingerprint: /Repository not found/,
	},
	{
		name: "Tumblr",
		suffixes: ["domains.tumblr.com"],
		fingerprint: /Whatever you were looking for doesn't currently exist/,
	},
	{
		name: "Pantheon",
		suffixes: ["pantheonsite.io"],
		fingerprint:
			/The gods are wise, but do not know of the site which you seek/,
	},
	{
		name: "Ghost",
		suffixes: ["ghost.io"],
		fingerprint:
			/The thing you were looking for is no longer here, or never was/,
	},
	// Azure resources are released with their DNS name, so a CNAME to a name
	// that no longer resolves is the whole signal.
	{
		name: "Azure App Service",
		suffixes: ["azurewebsites.net"],
	},
	{
		name: "Azure Cloud Services",
		suffixes: ["cloudapp.net", "cloudapp.azure.com"],
	},
	{
		name: "Azure Traffic Manager",
		suffixes: ["trafficmanager.net"],
	},
	{
		name: "Azure Blob Storage",
		suffixes: ["blob.core.windows.net"],
	},
];

const S3_HOST = /(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$/i;

export const takeoverServiceFor = (
	target: DnsName,
): TakeoverService | undefined => {
	const name = target.toLowerCase().replace(/\.$/, "");
	if (
		S3_HOST.test(name) ||
		/\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/.test(name)
	)
		return TAKEOVER_SERVICES.find((s) => s.name === "AWS S3");
	return TAKEOVER_SERVICES.find((s) =>
		s.suffixes.some((suffix) => name === suffix || name.endsWith(`.${suffix}`)),
	);
};

/** Does an HTTP response look like the service's "nothing here" page? */
export const matchesTakeoverFingerprint = (
	service: TakeoverService,
	res: Pick<HttpResponse, "status" | "body">,
): boolean =>
	service.fingerprint !== undefined &&
	res.status === 404 &&
	service.fingerprint.test(res.body);
