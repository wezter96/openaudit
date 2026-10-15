/** A DNS name, e.g. `example.com` or `_dmarc.example.com`. */
type DnsName = string;

/* -------------------------------------------------------------------------- */
/*                              Registrable domain                            */
/* -------------------------------------------------------------------------- */

/**
 * No public-suffix list is bundled. Instead: a short list of common two-label
 * public suffixes (`co.uk`, `com.au`, ...), otherwise the last two labels.
 * Uncommon multi-label suffixes (e.g. `k12.ca.us`) are therefore mis-split; the
 * DNS checks are then run against the suffix and will mostly report nothing.
 */
const TWO_LABEL_SUFFIXES = new Set(
	`co.uk org.uk me.uk ac.uk gov.uk ltd.uk plc.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au co.nz org.nz net.nz govt.nz ac.nz
co.jp ne.jp or.jp ac.jp go.jp co.in net.in org.in gov.in ac.in
com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn
com.mx com.ar com.co com.pe com.ve com.tr com.sg com.hk com.tw com.my com.ph com.vn
co.kr or.kr co.za org.za co.il co.id co.th co.ke com.ng com.pk com.bd com.eg com.sa
com.ua com.pl com.ru`.split(/\s+/),
);

/**
 * Hosting platforms whose subdomains belong to customers. The platform owns
 * the parent zone, so mail/CAA findings there are not the customer's to fix.
 */
const SHARED_SUFFIXES = [
	"github.io",
	"gitlab.io",
	"herokuapp.com",
	"vercel.app",
	"netlify.app",
	"pages.dev",
	"workers.dev",
	"azurewebsites.net",
	"cloudfront.net",
	"amazonaws.com",
	"appspot.com",
	"web.app",
	"firebaseapp.com",
	"onrender.com",
	"fly.dev",
	"railway.app",
	"surge.sh",
	"ngrok.io",
	"ngrok-free.app",
	"trycloudflare.com",
	"myshopify.com",
	"wordpress.com",
	"blogspot.com",
	"azurestaticapps.net",
	"cloudapp.azure.com",
	"trafficmanager.net",
	"readthedocs.io",
];

const isIp = (host: DnsName) => /^[\d.]+$/.test(host) || host.includes(":");

export type DomainScope =
	| { readonly kind: "domain"; readonly host: string; readonly domain: string }
	| { readonly kind: "shared" | "none"; readonly host: string };

/** Suffixes of names that never resolve in public DNS. */
const LOCAL_SUFFIXES = [".localhost", ".local", ".internal"];

/** Single labels, IP addresses, localhost and local-only names. */
const isLocalName = (host: DnsName) =>
	!host.includes(".") ||
	isIp(host) ||
	host === "localhost" ||
	LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix));

const isSharedHost = (host: DnsName) =>
	SHARED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`));

export const domainScope = (hostname: DnsName): DomainScope => {
	const host = hostname
		.toLowerCase()
		.replace(/^\[|\]$/g, "")
		.replace(/\.$/, "");
	if (isLocalName(host)) return { kind: "none", host };
	if (isSharedHost(host)) return { kind: "shared", host };
	const labels = host.split(".");
	const last2 = labels.slice(-2).join(".");
	const take = TWO_LABEL_SUFFIXES.has(last2) ? 3 : 2;
	if (labels.length < take) return { kind: "none", host };
	return { kind: "domain", host, domain: labels.slice(-take).join(".") };
};
