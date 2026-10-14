/**
 * The site's navigation bar for the page copied in from the CLI (/report/),
 * which has no way back to the rest of the site of its own. It matches the site header: links on wide screens, a burger
 * menu (a <details>, so it works without script) and a breadcrumb on narrow
 * ones, and the theme switch everywhere. The theme script shares the site's
 * `theme` key in localStorage; postbuild hashes it and the styles into each
 * page's CSP.
 */
import { NAV, REPO } from "../src/lib/nav";

/** Height of the bar; the report's sticky tab rail moves down by as much. */
const HEIGHT = "3rem";

const STYLE = `
.oa-bar{--oa-paper:light-dark(#eef1f4,#0b111b);--oa-paper-2:light-dark(#f8fafb,#111a27);--oa-ink:light-dark(#0d1522,#e7ecf3);--oa-graphite:light-dark(#4a5668,#9aa7b9);--oa-hair:light-dark(#c9d1db,#2a374c);--oa-accent:light-dark(#2340e8,#8fa2ff);position:sticky;top:0;z-index:60;height:${HEIGHT};background:var(--oa-paper);background:color-mix(in srgb,var(--oa-paper) 94%,transparent);-webkit-backdrop-filter:saturate(1.4) blur(14px);backdrop-filter:saturate(1.4) blur(14px);border-bottom:1px solid var(--oa-hair);font:550 .875rem/1 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
.oa-bar-in{display:flex;align-items:center;gap:1rem;height:100%;max-width:84rem;margin:0 auto;padding:0 clamp(1rem,.4rem + 2.6vw,2.25rem)}
.oa-bar a{color:var(--oa-graphite);text-decoration:none;border-radius:6px}
.oa-bar a:hover,.oa-bar a[aria-current=page]{color:var(--oa-ink)}
.oa-bar a:focus-visible,.oa-bar button:focus-visible,.oa-bar summary:focus-visible{outline:2px solid var(--oa-accent);outline-offset:2px}
.oa-bar-brand{display:inline-flex;align-items:center;gap:.5rem;flex:none;font-weight:700;font-size:.9375rem;letter-spacing:-.02em}
.oa-bar .oa-bar-brand{color:var(--oa-ink)}
.oa-bar-brand svg{width:1.2rem;height:1.2rem}
.oa-bar-brand .a{fill:var(--oa-ink)}
.oa-bar-brand .b{fill:none;stroke:var(--oa-paper);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.oa-bar-nav{display:flex;gap:.1rem;margin-left:auto}
.oa-bar-nav a{padding:.45rem .6rem;white-space:nowrap}
.oa-bar-nav a[aria-current=page]{box-shadow:inset 0 -2px 0 var(--oa-ink);border-radius:0}
.oa-bar-icon{display:inline-grid;place-items:center;width:2.4rem;height:2.4rem;border:1px solid transparent;border-radius:7px;background:none;color:var(--oa-graphite);cursor:pointer;list-style:none}
.oa-bar-icon:hover,.oa-bar-menu[open] .oa-bar-icon{color:var(--oa-ink);border-color:var(--oa-hair);background:var(--oa-paper-2)}
.oa-bar-icon svg{width:1.15rem;height:1.15rem;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.oa-bar-icon[hidden]{display:none}
.oa-bar-theme .sun,:root[data-theme=dark] .oa-bar-theme .moon{display:none}
:root[data-theme=dark] .oa-bar-theme .sun{display:block}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .oa-bar-theme .moon{display:none}:root:not([data-theme=light]) .oa-bar-theme .sun{display:block}}
.oa-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap}
.oa-bar-crumbs,.oa-bar-menu{display:none}
.oa-bar-crumbs ol{display:flex;align-items:center;gap:.45rem;margin:0;padding:0;list-style:none;white-space:nowrap}
.oa-bar-crumbs li+li::before{content:"/";margin-right:.45rem;color:var(--oa-hair)}
.oa-bar-crumbs [aria-current]{color:var(--oa-ink)}
.oa-bar-menu{position:relative}
.oa-bar-menu summary::-webkit-details-marker{display:none}
.oa-bar-menu:not([open]) nav{display:none}
.oa-bar-menu nav{position:absolute;right:0;top:calc(100% + .45rem);display:grid;width:min(15rem,calc(100vw - 2rem));padding:.35rem;background:var(--oa-paper);border:1px solid var(--oa-hair);border-radius:8px;box-shadow:0 1px 2px rgb(13 21 34/.06),0 10px 28px -14px rgb(13 21 34/.3)}
.oa-bar-menu nav a{padding:.7rem .75rem}
.oa-bar-menu nav a[aria-current=page]{background:color-mix(in srgb,var(--oa-hair) 40%,transparent)}
@media (max-width:50rem){.oa-bar-in{gap:.6rem}.oa-bar-nav{display:none}.oa-bar-crumbs{display:block;margin-right:auto}.oa-bar-menu{display:block}.oa-bar-brand span{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap}}
@media print{.oa-bar{display:none}}
`.trim();

/**
 * Applies a saved theme before the page paints and wires the switch, the
 * same way the site's own header does (src/scripts/site.ts): a choice that
 * matches the system is dropped so the page keeps following the system.
 */
const SCRIPT = `(()=>{var d=document.documentElement,m=matchMedia("(prefers-color-scheme: dark)");try{var t=localStorage.getItem("theme");if(t==="light"||t==="dark")d.dataset.theme=t}catch(e){}
function eff(){return d.dataset.theme||(m.matches?"dark":"light")}
function label(b){b.setAttribute("aria-label",eff()==="dark"?"Switch to light theme":"Switch to dark theme")}
document.addEventListener("DOMContentLoaded",function(){var b=document.querySelector("[data-oa-theme]");if(!b)return;b.hidden=false;label(b);
b.addEventListener("click",function(){var n=eff()==="dark"?"light":"dark",s=m.matches?"dark":"light";if(n===s)delete d.dataset.theme;else d.dataset.theme=n;try{if(n===s)localStorage.removeItem("theme");else localStorage.setItem("theme",n)}catch(e){}label(b)});
m.addEventListener("change",function(){label(b)})})})();`;

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

const icon = (d: string, cls = "") =>
	`<svg${cls ? ` class="${cls}"` : ""} viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${d}"/></svg>`;
const MENU = "M4 7h16M4 12h16M4 17h16";
const MOON = "M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z";
const SUN =
	"M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6 7 7m10 10 1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0z";

const LOGO =
	'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path class="a" d="M12 1.5 20.5 4.7v6.1c0 5.3-3.6 9.9-8.5 11.7-4.9-1.8-8.5-6.4-8.5-11.7V4.7z"/><path class="b" d="m8.2 12.1 2.6 2.6 5-5.3"/></svg>';

/**
 * Puts the bar at the top of a copied page: its styles and theme script before
 * `</head>`, its markup after the skip link (or `<body>`). Returns the page and
 * the CSS and script it added, so the caller can hash them into the page's CSP.
 */
export const withSiteBar = (
	page: string,
	{ base, current }: { base: string; current: string },
): { page: string; style: string; script: string } => {
	const style = current === "/report/" ? `${STYLE}\n${REPORT_STYLE}` : STYLE;
	const link = (href: string, label: string) =>
		`<a href="${href}"${href === `${base}${current}` ? ' aria-current="page"' : ""}>${label}</a>`;
	const links = [
		...NAV.map((n) => link(`${base}${n.href}`, n.label)),
		link(REPO, "GitHub"),
	].join("");
	const here = NAV.find((n) => n.href === current)?.label ?? "";
	const crumbs = `<nav class="oa-bar-crumbs" aria-label="Breadcrumb"><ol><li><a href="${base}/">Home</a></li><li aria-current="page">${here}</li></ol></nav>`;
	const theme = `<button class="oa-bar-icon oa-bar-theme" type="button" aria-label="Switch theme" data-oa-theme hidden>${icon(MOON, "moon")}${icon(SUN, "sun")}</button>`;
	const menu = `<details class="oa-bar-menu"><summary class="oa-bar-icon">${icon(MENU)}<span class="oa-sr">Menu</span></summary><nav aria-label="Site">${links}</nav></details>`;
	const bar = `<header class="oa-bar"><div class="oa-bar-in"><a class="oa-bar-brand" href="${base}/">${LOGO}<span>openaudit</span></a>${crumbs}<nav class="oa-bar-nav" aria-label="Site">${links}</nav>${theme}${menu}</div></header>`;
	const skip = /<a class="skip"[^>]*>[^<]*<\/a>/.exec(page);
	const body = /<body[^>]*>/.exec(page);
	const anchor = skip ?? body;
	if (!anchor || !page.includes("</head>")) {
		throw new Error("site bar: page has no <head> or <body>");
	}
	const at = anchor.index + anchor[0].length;
	const withBar = `${page.slice(0, at)}\n${bar}${page.slice(at)}`;
	return {
		page: withBar.replace(
			"</head>",
			`<style>${style}</style>\n<script>${SCRIPT}</script>\n</head>`,
		),
		style,
		script: SCRIPT,
	};
};
