/**
 * The site's navigation bar for the pages copied in from the CLI (/report/
 * and /architecture/), which have no way back to the rest of the site of
 * their own. Plain HTML and CSS: the report's CSP allows no extra script, so
 * on phones the links fold into a <details> menu, next to a breadcrumb that
 * names the page and leads home.
 */
import { NAV, REPO } from "../src/lib/nav";

/** Height of the bar; the report's sticky tab rail moves down by as much. */
const HEIGHT = "3rem";

const STYLE = `
.oa-bar{--oa-paper:#eef1f4;--oa-ink:#0d1522;--oa-graphite:#4a5668;--oa-hair:#c9d1db;--oa-accent:#2340e8;position:sticky;top:0;z-index:60;height:${HEIGHT};background:var(--oa-paper);background:color-mix(in srgb,var(--oa-paper) 94%,transparent);-webkit-backdrop-filter:saturate(1.4) blur(14px);backdrop-filter:saturate(1.4) blur(14px);border-bottom:1px solid var(--oa-hair);font:550 .875rem/1 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .oa-bar{--oa-paper:#0b111b;--oa-ink:#e7ecf3;--oa-graphite:#9aa7b9;--oa-hair:#2a374c;--oa-accent:#8fa2ff}}
:root[data-theme=dark] .oa-bar{--oa-paper:#0b111b;--oa-ink:#e7ecf3;--oa-graphite:#9aa7b9;--oa-hair:#2a374c;--oa-accent:#8fa2ff}
.oa-bar-in{display:flex;align-items:center;gap:1rem;height:100%;max-width:84rem;margin:0 auto;padding:0 clamp(1rem,.4rem + 2.6vw,2.25rem)}
.oa-bar a{color:var(--oa-graphite);text-decoration:none;border-radius:6px}
.oa-bar a:hover,.oa-bar a[aria-current=page]{color:var(--oa-ink)}
.oa-bar a:focus-visible{outline:2px solid var(--oa-accent);outline-offset:2px}
.oa-bar-brand{display:inline-flex;align-items:center;gap:.5rem;flex:none;font-weight:700;font-size:.9375rem;letter-spacing:-.02em}
.oa-bar .oa-bar-brand{color:var(--oa-ink)}
.oa-bar-brand svg{width:1.2rem;height:1.2rem}
.oa-bar-brand .a{fill:var(--oa-ink)}
.oa-bar-brand .b{fill:none;stroke:var(--oa-paper);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.oa-bar-nav{display:flex;gap:.1rem;margin-left:auto}
.oa-bar-nav a{padding:.45rem .6rem;white-space:nowrap}
.oa-bar-nav a[aria-current=page]{box-shadow:inset 0 -2px 0 var(--oa-ink);border-radius:0}
.oa-bar-crumbs,.oa-bar-menu{display:none}
.oa-bar-crumbs ol{display:flex;align-items:center;gap:.45rem;margin:0;padding:0;list-style:none;white-space:nowrap}
.oa-bar-crumbs li+li::before{content:"/";margin-right:.45rem;color:var(--oa-hair)}
.oa-bar-crumbs [aria-current]{color:var(--oa-ink)}
.oa-bar-menu{position:relative;margin-left:auto}
.oa-bar-menu summary{list-style:none;cursor:pointer;padding:.45rem .75rem;border:1px solid var(--oa-hair);border-radius:6px;color:var(--oa-ink)}
.oa-bar-menu summary::-webkit-details-marker{display:none}
.oa-bar-menu summary:focus-visible{outline:2px solid var(--oa-accent);outline-offset:2px}
.oa-bar-menu[open] summary{border-color:var(--oa-ink)}
.oa-bar-menu:not([open]) nav{display:none}
.oa-bar-menu nav{position:absolute;right:0;top:calc(100% + .45rem);display:grid;min-width:13rem;padding:.35rem;background:var(--oa-paper);border:1px solid var(--oa-hair);border-radius:8px;box-shadow:0 1px 2px rgb(13 21 34/.06),0 10px 28px -14px rgb(13 21 34/.3)}
.oa-bar-menu nav a{padding:.7rem .75rem}
.oa-bar-menu nav a[aria-current=page]{background:color-mix(in srgb,var(--oa-hair) 40%,transparent)}
@media (max-width:50rem){.oa-bar-in{gap:.6rem}.oa-bar-nav{display:none}.oa-bar-crumbs,.oa-bar-menu{display:block}.oa-bar-brand span{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap}}
@media print{.oa-bar{display:none}}
`.trim();

/**
 * The report's own sticky tab rail and scroll offsets assume nothing sits
 * above them; the report reads `scroll-margin-top` on `.frame` for its own
 * scrolling (see packages/core/src/reporters/html/script.ts).
 */
const REPORT_STYLE = `
.frame{scroll-margin-top:${HEIGHT}}
html{scroll-padding-top:calc(4.5rem + ${HEIGHT})}
.rail{top:${HEIGHT}}
@media (min-width:64.0625rem){.rail{max-height:calc(100vh - ${HEIGHT})}}
`.trim();

const LOGO =
	'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path class="a" d="M12 1.5 20.5 4.7v6.1c0 5.3-3.6 9.9-8.5 11.7-4.9-1.8-8.5-6.4-8.5-11.7V4.7z"/><path class="b" d="m8.2 12.1 2.6 2.6 5-5.3"/></svg>';

/**
 * Puts the bar at the top of a copied page: its styles before `</head>`, its
 * markup after the skip link (or `<body>`). Returns the page and the CSS it
 * added, so the caller can hash that into the page's CSP.
 */
export const withSiteBar = (
	page: string,
	{ base, current }: { base: string; current: string },
): { page: string; style: string } => {
	const style = current === "/report/" ? `${STYLE}\n${REPORT_STYLE}` : STYLE;
	const link = (href: string, label: string) =>
		`<a href="${href}"${href === `${base}${current}` ? ' aria-current="page"' : ""}>${label}</a>`;
	const links = [
		...NAV.map((n) => link(`${base}${n.href}`, n.label)),
		link(REPO, "GitHub"),
	].join("");
	const here = NAV.find((n) => n.href === current)?.label ?? "";
	const crumbs = `<nav class="oa-bar-crumbs" aria-label="Breadcrumb"><ol><li><a href="${base}/">Home</a></li><li aria-current="page">${here}</li></ol></nav>`;
	const bar = `<header class="oa-bar"><div class="oa-bar-in"><a class="oa-bar-brand" href="${base}/">${LOGO}<span>openaudit</span></a>${crumbs}<nav class="oa-bar-nav" aria-label="Site">${links}</nav><details class="oa-bar-menu"><summary>Menu</summary><nav aria-label="Site">${links}</nav></details></div></header>`;
	const skip = /<a class="skip"[^>]*>[^<]*<\/a>/.exec(page);
	const body = /<body[^>]*>/.exec(page);
	const anchor = skip ?? body;
	if (!anchor || !page.includes("</head>")) {
		throw new Error("site bar: page has no <head> or <body>");
	}
	const at = anchor.index + anchor[0].length;
	const withBar = `${page.slice(0, at)}\n${bar}${page.slice(at)}`;
	return {
		page: withBar.replace("</head>", `<style>${style}</style>\n</head>`),
		style,
	};
};
