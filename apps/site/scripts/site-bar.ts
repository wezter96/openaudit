/**
 * The site's navigation bar for the pages copied in from the CLI (/report/
 * and /architecture/), which have no way back to the rest of the site of
 * their own. Plain HTML and CSS: the report's CSP allows no extra script, so
 * on phones the bar drops to the logo and the section links (which scroll
 * sideways on the narrowest screens) instead of folding into a menu.
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
.oa-bar-nav{display:flex;gap:.1rem;min-width:0;margin-left:auto;overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch}
.oa-bar-nav::-webkit-scrollbar{display:none}
.oa-bar-nav a{flex:none;padding:.45rem .6rem;white-space:nowrap}
.oa-bar-nav a[aria-current=page]{box-shadow:inset 0 -2px 0 var(--oa-ink);border-radius:0}
@media (max-width:40rem){.oa-bar-in{gap:.35rem}.oa-bar-nav .oa-bar-gh{display:none}.oa-bar-brand span{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap}.oa-bar-nav a{padding:.45rem .5rem}}
@media (max-width:23.5rem){.oa-bar-nav a{padding:.45rem .4rem;font-size:.8125rem}}
@media (max-width:21rem){.oa-bar-nav{-webkit-mask-image:linear-gradient(90deg,#000 calc(100% - 1.25rem),transparent);mask-image:linear-gradient(90deg,#000 calc(100% - 1.25rem),transparent)}}
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
	const links = [
		...NAV.map(
			(n) =>
				`<a href="${base}${n.href}"${n.href === current ? ' aria-current="page"' : ""}>${n.label}</a>`,
		),
		`<a class="oa-bar-gh" href="${REPO}">GitHub</a>`,
	].join("");
	const bar = `<header class="oa-bar"><div class="oa-bar-in"><a class="oa-bar-brand" href="${base}/">${LOGO}<span>openaudit</span></a><nav class="oa-bar-nav" aria-label="Site">${links}</nav></div></header>`;
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
