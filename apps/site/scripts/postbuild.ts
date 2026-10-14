/**
 * Runs after `astro build` on dist/:
 *
 * - Open Graph images: one PNG per page, named by its og:image, drawn from
 *   the page's own og:title next to the self-audit dial.
 * - PNG favicons rendered from the shield.
 * - A Content-Security-Policy <meta> in every page, holding the hashes of
 *   that page's inline styles and scripts (GitHub Pages cannot send headers).
 * - _headers for hosts that can (Cloudflare): the same policy as a header
 *   plus the other security headers and cache rules.
 * - Canonical, Open Graph and Markdown links in the pages copied in from the
 *   CLI (/report/ and /architecture/), which have none of their own.
 * - robots.txt (with content signals), security.txt and, when CUSTOM_DOMAIN
 *   is set, CNAME.
 * - The agent discovery files (scripts/agents.ts).
 * - A link check: every internal href and src must resolve to a file, and so
 *   must every page's Markdown version and the agent files' own links.
 */
import { createHash } from "node:crypto";
import { mkdir, readdir } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { Resvg } from "@resvg/resvg-js";
import { capPoint, clamp, segments, ticks } from "../src/lib/dial";
import { writeAgentFiles } from "./agents";

const site = join(import.meta.dir, "..");
const repo = join(site, "..", "..");
const dist = join(site, "dist");
// Same defaults as astro.config.ts.
const SITE = (process.env.SITE_URL ?? "https://openaudit.se").replace(
	/\/$/,
	"",
);
const BASE = (process.env.BASE_PATH ?? "/").replace(/\/$/, "");
/** dist-relative path of a URL pathname under the base path. */
const unbase = (pathname: string) =>
	BASE && pathname.startsWith(`${BASE}/`)
		? pathname.slice(BASE.length)
		: pathname;
const fonts = join(site, "node_modules", "@expo-google-fonts");
const self = (await Bun.file(
	join(site, "src", "generated", "self-audit.json"),
).json()) as {
	available: boolean;
	score?: number;
	grade?: string;
	categories?: { category: string; score: number; grade: string }[];
};

const walk = async (dir: string): Promise<string[]> => {
	const out: string[] = [];
	for (const e of await readdir(dir, { withFileTypes: true })) {
		const p = join(dir, e.name);
		if (e.isDirectory()) out.push(...(await walk(p)));
		else out.push(p);
	}
	return out;
};
const files = await walk(dist);
const html = files.filter((f) => f.endsWith(".html"));
/** Pages copied in from the CLI, served under their own CSP. */
const copied = (f: string) =>
	/^(report|architecture)\//.test(relative(dist, f));

/* ---------------------------------------------------------------- render */

const C = {
	paper: "#eef1f4",
	paper2: "#f8fafb",
	ink: "#0d1522",
	graphite: "#4a5668",
	hair: "#c9d1db",
	dot: "rgba(13,21,34,0.10)",
	none: "#d5dbe3",
	accent: "#2340e8",
};
const ARC: Record<string, string> = {
	A: "#19a86a",
	B: "#7fb236",
	C: "#f0a22b",
	D: "#e04a1f",
	F: "#a1123a",
};
const GRADE: Record<string, string> = {
	A: "#0b7a4e",
	B: "#4f7a12",
	C: "#8c5600",
	D: "#b4380f",
	F: "#a1123a",
};
const esc = (s: string) =>
	s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const png = (svg: string, width?: number) =>
	new Resvg(svg, {
		fitTo: width ? { mode: "width", value: width } : { mode: "original" },
		font: {
			loadSystemFonts: false,
			fontFiles: [
				join(fonts, "inter", "800ExtraBold", "Inter_800ExtraBold.ttf"),
				join(fonts, "inter", "500Medium", "Inter_500Medium.ttf"),
				join(
					fonts,
					"jetbrains-mono",
					"500Medium",
					"JetBrainsMono_500Medium.ttf",
				),
			],
			defaultFontFamily: "Inter",
		},
	})
		.render()
		.asPng();

const SHIELD =
	'<path d="M12 1.5 20.5 4.7v6.1c0 5.3-3.6 9.9-8.5 11.7-4.9-1.8-8.5-6.4-8.5-11.7V4.7z" fill="FILL"/><path d="m8.2 12.1 2.6 2.6 5-5.3" fill="none" stroke="STROKE" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>';

/**
 * The self-audit dial, drawn at 240 units; the caller scales it. resvg has no
 * `pathLength`, so dashes are real lengths along each arc.
 */
const dial = (): string => {
	const score = self.score ?? 0;
	const grade = self.grade ?? "A";
	const list = self.categories ?? [];
	const span = 360 / Math.max(1, list.length) - (list.length > 1 ? 4 : 0);
	const segLength = (110 * span * Math.PI) / 180;
	const segs = segments(
		list.map((c) => ({ label: c.category, score: c.score, grade: c.grade })),
	)
		.map((s) => {
			const dash = (clamp(s.score ?? 0) / 100) * segLength;
			return `<path d="${s.d}" fill="none" stroke="${C.none}" stroke-width="6"/><path d="${s.d}" fill="none" stroke="${ARC[s.grade ?? "A"]}" stroke-width="6" stroke-dasharray="${dash.toFixed(2)} ${segLength.toFixed(2)}"/>`;
		})
		.join("");
	const ring = 2 * Math.PI * 80;
	const cap = capPoint(120, 80, score);
	return `<circle cx="120" cy="120" r="97" fill="${C.paper2}" stroke="#dce2e9"/>${segs}
<path d="${ticks(120, 93, 96.5, false)}" stroke="${C.graphite}" stroke-width=".8" opacity=".5"/>
<path d="${ticks(120, 92, 97, true)}" stroke="${C.ink}" stroke-width="1.3" opacity=".6"/>
<circle cx="120" cy="120" r="80" fill="none" stroke="${C.none}" stroke-width="15"/>
<circle cx="120" cy="120" r="80" fill="none" stroke="${ARC[grade]}" stroke-width="15" stroke-linecap="round" stroke-dasharray="${((clamp(score) / 100) * ring).toFixed(2)} ${ring.toFixed(2)}" transform="rotate(-90 120 120)"/>
<circle cx="${cap.x}" cy="${cap.y}" r="4" fill="${C.paper2}" stroke="${ARC[grade]}" stroke-width="3"/>
<text x="117" y="146" text-anchor="middle" font-family="Inter" font-weight="800" font-size="92" letter-spacing="-6" fill="${GRADE[grade]}">${grade}</text>
<text x="120" y="170" text-anchor="middle" font-family="JetBrains Mono" font-weight="500" font-size="11" fill="${C.ink}">${clamp(score)}<tspan fill="${C.graphite}" font-size="8.5">/100</tspan></text>`;
};

/**
 * Wrap by an estimated advance width (Inter ExtraBold ≈ 0.55em), then
 * balance: the narrowest measure that needs no more lines than greedy did.
 */
const wrap = (text: string, size: number, width: number): string[] => {
	const words = text.split(/\s+/);
	const fill = (max: number) => {
		const lines: string[] = [];
		let line = "";
		for (const word of words) {
			const next = line ? `${line} ${word}` : word;
			if (next.length > max && line) {
				lines.push(line);
				line = word;
			} else line = next;
		}
		if (line) lines.push(line);
		return lines;
	};
	const max = Math.floor(width / (size * 0.55));
	const greedy = fill(max);
	for (let m = Math.max(...words.map((w) => w.length)); m < max; m++) {
		const lines = fill(m);
		if (lines.length <= greedy.length) return lines;
	}
	return greedy;
};

const ogCard = (title: string, address: string): string => {
	let size = 84;
	let lines = wrap(title, size, 640);
	while (lines.length > 3 && size > 52) {
		size -= 8;
		lines = wrap(title, size, 640);
	}
	const lh = size * 0.98;
	const top = 315 - ((lines.length - 1) * lh) / 2 + size * 0.32;
	const tspans = lines
		.map(
			(l, i) =>
				`<tspan x="72" y="${(top + i * lh).toFixed(1)}">${esc(l)}</tspan>`,
		)
		.join("");
	return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
<defs><pattern id="dots" width="20" height="20" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="${C.dot}"/></pattern></defs>
<rect width="1200" height="630" fill="${C.paper}"/><rect width="1200" height="630" fill="url(#dots)"/>
<g transform="translate(72 64) scale(1.6)">${SHIELD.replace("FILL", C.ink).replace("STROKE", C.paper)}</g>
<text x="120" y="91" font-family="Inter" font-weight="800" font-size="30" letter-spacing="-0.8" fill="${C.ink}">openaudit</text>
<text font-family="Inter" font-weight="800" font-size="${size}" letter-spacing="${(-size * 0.045).toFixed(1)}" fill="${C.ink}">${tspans}</text>
<line x1="72" y1="534" x2="700" y2="534" stroke="${C.ink}" stroke-width="1.5"/>
<text x="72" y="572" font-family="JetBrains Mono" font-weight="500" font-size="22" fill="${C.graphite}">${esc(address.replace(/\/$/, ""))}</text>
${self.available ? `<g transform="translate(726 99) scale(1.8)">${dial()}</g>` : ""}
</svg>`;
};

/* -------------------------------------------------------------- og + icons */

const meta = (page: string, prop: string) =>
	// prop is one of this script's own literals.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	new RegExp(`<meta property="${prop}" content="([^"]*)"`).exec(page)?.[1];
const decodeEntities = (s: string) =>
	s
		.replace(/&#39;/g, "'")
		.replace(/&quot;/g, '"')
		.replace(/&lt;/g, "<")
		.replace(/&gt;/g, ">")
		.replace(/&amp;/g, "&");

/**
 * The copied pages get the same head links and social tags as Astro's pages.
 * Only <link> and <meta> tags are added, so their CSP hashes still hold.
 */
const COPIED: Record<
	string,
	{ path: string; title: string; markdown: string }
> = {
	report: {
		path: "/report/",
		title: "openaudit's audit of itself",
		markdown: "/report/openaudit-report.md",
	},
	architecture: {
		path: "/architecture/",
		title: "openaudit architecture",
		markdown: "/architecture/index.md",
	},
};
const attr = (s: string) => esc(s).replace(/"/g, "&quot;");
for (const f of html.filter(copied)) {
	const info = COPIED[relative(dist, f).split("/")[0] ?? ""];
	if (!info) continue;
	let page = await Bun.file(f).text();
	if (page.includes('rel="canonical"')) continue;
	const description = decodeEntities(
		/<meta name="description" content="([^"]*)"/.exec(page)?.[1] ?? "",
	);
	const url = `${SITE}${BASE}${info.path}`;
	const image = `${SITE}${BASE}/og/${info.path.replace(/^\/|\/$/g, "").replace(/\//g, "-")}.png`;
	const tags = [
		`<link rel="canonical" href="${url}">`,
		`<link rel="alternate" type="text/markdown" href="${BASE}${info.markdown}">`,
		`<link rel="ai-catalog" href="${BASE}/.well-known/ai-catalog.json">`,
		'<meta property="og:type" content="website">',
		'<meta property="og:site_name" content="openaudit">',
		`<meta property="og:title" content="${attr(info.title)}">`,
		`<meta property="og:description" content="${attr(description)}">`,
		`<meta property="og:url" content="${url}">`,
		`<meta property="og:image" content="${image}">`,
		'<meta property="og:image:width" content="1200">',
		'<meta property="og:image:height" content="630">',
		`<meta property="og:image:alt" content="${attr(`openaudit grade dial beside the title “${info.title}”`)}">`,
		'<meta name="twitter:card" content="summary_large_image">',
	].join("\n");
	page = page.replace("</head>", `${tags}\n</head>`);
	await Bun.write(f, page);
}

let og = 0;
const rendered = new Set<string>();
for (const f of html) {
	const page = await Bun.file(f).text();
	const image = meta(page, "og:image");
	const title = meta(page, "og:title");
	if (!image || !title) throw new Error(`${relative(dist, f)}: no og:image`);
	const out = join(dist, unbase(new URL(image).pathname));
	// The report is served under two names that share one image.
	if (rendered.has(out)) continue;
	rendered.add(out);
	await mkdir(dirname(out), { recursive: true });
	const pageUrl = (meta(page, "og:url") ?? SITE).replace(/^https?:\/\//, "");
	await Bun.write(out, png(ogCard(decodeEntities(title), pageUrl)));
	og++;
}

const icon = (size: number, pad: number) =>
	`<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="${-pad} ${-pad} ${24 + 2 * pad} ${24 + 2 * pad}"><rect x="${-pad}" y="${-pad}" width="${24 + 2 * pad}" height="${24 + 2 * pad}" fill="${C.paper}"/>${SHIELD.replace("FILL", C.ink).replace("STROKE", C.paper)}</svg>`;
await Bun.write(join(dist, "apple-touch-icon.png"), png(icon(180, 5)));
await Bun.write(
	join(dist, "favicon-32.png"),
	png(icon(32, 0).replace(/<rect[^>]*\/>/, "")),
);

/* ---------------------------------------------------------- security.txt */

// RFC 9116 wants an expiry within a year; every deploy renews it.
const expires = new Date(Date.now() + 180 * 24 * 3600 * 1000).toISOString();
await Bun.write(
	join(dist, ".well-known", "security.txt"),
	`Contact: https://github.com/wezter96/openaudit/security/advisories/new
Expires: ${expires}
Policy: https://github.com/wezter96/openaudit/blob/main/SECURITY.md
Preferred-Languages: en, sv
Canonical: ${SITE}${BASE}/.well-known/security.txt
`,
);

// Content signals (contentsignals.org) are the owner's choice: the docs are
// open source and agents are welcome, so every use is allowed. Change them
// here. Agentmap points agents at the AI catalog.
await Bun.write(
	join(dist, "robots.txt"),
	`User-agent: *
Content-Signal: search=yes, ai-input=yes, ai-train=yes
Allow: /

Sitemap: ${SITE}${BASE}/sitemap-index.xml
Agentmap: ${SITE}${BASE}/.well-known/ai-catalog.json
`,
);
const agentLinks = await writeAgentFiles({
	dist,
	repo,
	root: `${SITE}${BASE}`,
	base: BASE,
});
// The old Pages site served the diagram at /architecture.html; README links
// still point there.
await Bun.write(
	join(dist, "architecture.html"),
	`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>openaudit architecture</title><meta name="robots" content="noindex"><link rel="canonical" href="${SITE}${BASE}/architecture/"><meta http-equiv="refresh" content="0; url=${BASE}/architecture/"></head><body><a href="${BASE}/architecture/">The architecture page has moved.</a></body></html>\n`,
);
if (process.env.CUSTOM_DOMAIN) {
	await Bun.write(join(dist, "CNAME"), `${process.env.CUSTOM_DOMAIN}\n`);
}

/* ---------------------------------------------------------------- headers */

const sha = (s: string) =>
	`'sha256-${createHash("sha256").update(s).digest("base64")}'`;
const scriptHashes = new Set<string>();
const styleHashes = new Set<string>();
const policy = (scripts: Iterable<string>, styles: Iterable<string>) =>
	[
		"default-src 'none'",
		`script-src 'self' ${[...scripts].join(" ")}`.trim(),
		`style-src 'self' ${[...styles].join(" ")}`.trim(),
		"img-src 'self'",
		"connect-src 'self'",
		"manifest-src 'self'",
		"base-uri 'none'",
		"form-action 'none'",
		"upgrade-insecure-requests",
	].join("; ");
for (const f of html) {
	if (copied(f)) continue;
	let page = await Bun.file(f).text();
	if (/\sstyle="/.test(page)) {
		throw new Error(
			`${relative(dist, f)}: inline style attribute breaks the CSP`,
		);
	}
	const scripts = new Set<string>();
	const styles = new Set<string>();
	for (const m of page.matchAll(
		/<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g,
	)) {
		if (/type="application\/(ld\+)?json"/.test(m[1] ?? "")) continue;
		scripts.add(sha(m[2] ?? ""));
	}
	for (const m of page.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) {
		styles.add(sha(m[1] ?? ""));
	}
	for (const h of scripts) scriptHashes.add(h);
	for (const h of styles) styleHashes.add(h);
	// frame-ancestors is ignored in a <meta>; the header carries it.
	page = page.replace(
		'<meta charset="utf-8">',
		`<meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy(scripts, styles)}">`,
	);
	await Bun.write(f, page);
}
const siteCsp = `${policy(scriptHashes, styleHashes)}; frame-ancestors 'none'`;

/**
 * A copied page's own CSP: its <meta> policy when it has one (the report),
 * otherwise one built from the hashes of its inline script, style and style
 * attributes (the architecture page).
 */
const pageCsp = async (file: string) => {
	const page = await Bun.file(join(dist, file)).text();
	const csp =
		/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(
			page,
		)?.[1];
	if (csp) return `${csp.replace(/;\s*$/, "")}; frame-ancestors 'none'`;
	const scripts = [
		...page.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g),
	].map((m) => sha(m[1] ?? ""));
	const styles = [...page.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map(
		(m) => sha(m[1] ?? ""),
	);
	const attrs = [...page.matchAll(/\sstyle="([^"]*)"/g)].map((m) =>
		sha(m[1] ?? ""),
	);
	return [
		"default-src 'none'",
		`script-src ${scripts.join(" ") || "'none'"}`,
		`style-src ${[...styles, ...(attrs.length ? ["'unsafe-hashes'", ...attrs] : [])].join(" ") || "'none'"}`,
		"img-src 'self' data:",
		"connect-src 'self'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	].join("; ");
};
const reportCsp = await pageCsp("report/index.html");
const archCsp = await pageCsp("architecture/index.html");

const headers = `# Generated by scripts/postbuild.ts.
${BASE}/*
  Content-Security-Policy: ${siteCsp}
  Strict-Transport-Security: max-age=63072000; includeSubDomains
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: accelerometer=(), browsing-topics=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
  X-Frame-Options: DENY

${BASE}/report/
  ! Content-Security-Policy
  ! Referrer-Policy
  Content-Security-Policy: ${reportCsp}
  Referrer-Policy: no-referrer

${BASE}/report/*
  ! Content-Security-Policy
  ! Referrer-Policy
  Content-Security-Policy: ${reportCsp}
  Referrer-Policy: no-referrer

${BASE}/architecture/
  ! Content-Security-Policy
  Content-Security-Policy: ${archCsp}

${BASE}/architecture/*
  ! Content-Security-Policy
  Content-Security-Policy: ${archCsp}

${BASE}/_astro/*
  Cache-Control: public, max-age=31536000, immutable

${BASE}/img/*
  Cache-Control: public, max-age=2592000

${BASE}/favicon.svg
  Cache-Control: public, max-age=2592000

${BASE}/favicon-32.png
  Cache-Control: public, max-age=2592000

${BASE}/apple-touch-icon.png
  Cache-Control: public, max-age=2592000

${BASE}/og/*
  Cache-Control: public, max-age=86400

${BASE}/schema/*
  ! Cross-Origin-Resource-Policy
  Access-Control-Allow-Origin: *
  Cross-Origin-Resource-Policy: cross-origin
  Cache-Control: public, max-age=3600

${BASE}/report/openaudit-report.*
  Cache-Control: public, max-age=300
`;
await Bun.write(join(dist, "_headers"), headers);

/* ------------------------------------------------------------ link check */

const exists = async (url: string): Promise<boolean> => {
	const path = decodeURIComponent(url.split(/[?#]/)[0] ?? "");
	if (!path) return true;
	const p = join(dist, path);
	if (path.endsWith("/")) return Bun.file(join(p, "index.html")).exists();
	return (
		(await Bun.file(p).exists()) || Bun.file(join(p, "index.html")).exists()
	);
};
const broken: string[] = [];
for (const f of html) {
	if (copied(f)) continue;
	const page = await Bun.file(f).text();
	for (const m of page.matchAll(/\s(?:href|src)="(\/[^"]*)"/g)) {
		const url = (m[1] ?? "").replace(/&amp;/g, "&");
		if (url.startsWith("//")) continue;
		const ok =
			(!BASE || url.startsWith(`${BASE}/`)) && (await exists(unbase(url)));
		if (!ok) broken.push(`${relative(dist, f)} -> ${url}`);
	}
}
// The copied pages' own links are theirs; the tags added above are checked.
for (const f of html.filter(copied)) {
	const page = await Bun.file(f).text();
	for (const m of page.matchAll(
		/<link rel="(?:alternate|ai-catalog)"[^>]*\shref="(\/[^"]*)"/g,
	)) {
		if (!(await exists(unbase(m[1] ?? ""))))
			broken.push(`${relative(dist, f)} -> ${m[1]}`);
	}
}
// Every site link in llms.txt and the discovery files.
const llms = await Bun.file(join(dist, "llms.txt")).text();
const prefix = `${SITE}${BASE}`;
for (const url of [
	...[...llms.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1] ?? ""),
	...agentLinks.map((p) => `${prefix}${p}`),
]) {
	if (!url.startsWith(`${prefix}/`)) continue;
	const path = url.slice(prefix.length);
	if (!(await exists(path))) broken.push(`agent files -> ${url}`);
}
// Docs search results (remote MCP) link to headings: each id must exist.
const docsData = (await Bun.file(join(dist, "data", "docs.json")).json()) as {
	sections: { url: string }[];
};
for (const { url } of docsData.sections) {
	const { pathname, hash } = new URL(url);
	if (!hash) continue;
	const page = await Bun.file(
		join(dist, unbase(pathname), "index.html"),
	).text();
	if (!page.includes(`id="${decodeURIComponent(hash.slice(1))}"`))
		broken.push(`data/docs.json -> ${url}`);
}
if (broken.length) {
	throw new Error(`Broken internal links:\n${broken.join("\n")}`);
}

const all = await walk(dist);
const bytes = all.reduce((n, f) => n + Bun.file(f).size, 0);
console.log(
	`postbuild: ${html.length} pages, ${og} OG images, ${scriptHashes.size} inline script hash(es), links ok, ${all.length} files, ${(bytes / 1024 / 1024).toFixed(2)} MB`,
);
