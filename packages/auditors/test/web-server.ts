import { fixture } from "./helpers";

/** A local fixture site on a random port; no test touches the public internet. */
export interface Site {
	readonly url: string;
	readonly requests: string[];
	readonly stop: () => void;
}

type Handler = (req: Request) => Response | Promise<Response>;

const html = (name: string, init: ResponseInit = {}) =>
	new Response(Bun.file(fixture("web", name)), {
		...init,
		headers: { "content-type": "text/html; charset=utf-8", ...init.headers },
	});

const gzip = (body: string, headers: Record<string, string>) =>
	new Response(Bun.gzipSync(body), {
		headers: { ...headers, "content-encoding": "gzip" },
	});

export const serve = (
	routes: Record<string, Handler>,
	fallback: Handler,
): Site => {
	const requests: string[] = [];
	const server = Bun.serve({
		port: 0,
		hostname: "127.0.0.1",
		fetch(req) {
			const { pathname } = new URL(req.url);
			requests.push(`${req.method} ${pathname}`);
			return (routes[pathname] ?? fallback)(req);
		},
	});
	return {
		url: `http://127.0.0.1:${server.port}/`,
		requests,
		stop: () => server.stop(true),
	};
};

const APP_JS = `// fixture bundle\n${"console.log('padding');\n".repeat(80)}//# sourceMappingURL=app.js.map\n`;

/** A site with a little bit of everything wrong. */
export const badSite = (): Site =>
	serve(
		{
			"/": (req) => {
				const headers = new Headers({
					"content-type": "text/html; charset=utf-8",
					server: "Apache/2.4.41 (Ubuntu)",
					"x-powered-by": "Express",
				});
				headers.append("set-cookie", "sessionid=abc123; Path=/");
				headers.append("set-cookie", "_ga=GA1.2.3.4; Max-Age=63072000; Path=/");
				const origin = req.headers.get("origin");
				if (origin) {
					headers.set("access-control-allow-origin", origin);
					headers.set("access-control-allow-credentials", "true");
				}
				return new Response(Bun.file(fixture("web", "bad", "index.html")), {
					headers,
				});
			},
			"/about.html": () => html("bad/about.html"),
			"/contact.html": () => html("bad/contact.html"),
			"/robots.txt": () =>
				new Response("User-agent: *\nDisallow: /\n", {
					headers: { "content-type": "text/plain" },
				}),
			"/.git/HEAD": () => new Response("ref: refs/heads/main\n"),
			"/.env": () =>
				new Response(
					"DB_PASSWORD=supersecretpassword\nAPI_KEY=sk_live_abcdef123456\n",
				),
			"/static/app.js": () =>
				new Response(APP_JS, {
					headers: { "content-type": "application/javascript" },
				}),
			"/static/app.js.map": () =>
				Response.json({
					version: 3,
					sources: ["src/app.ts"],
					sourcesContent: ["const secret = 1"],
					mappings: "AAAA",
				}),
			"/static/": () =>
				new Response(
					'<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><a href="app.js">app.js</a></body></html>',
					{
						headers: { "content-type": "text/html" },
					},
				),
			"/static/hero.png": () =>
				new Response(new Uint8Array(2048), {
					headers: { "content-type": "image/png" },
				}),
		},
		() =>
			new Response(
				"<html><body><h1>Server Error</h1><pre>Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 12, in handler\nKeyError: 'x'</pre></body></html>",
				{ status: 404, headers: { "content-type": "text/html" } },
			),
	);

const GOOD_HEADERS = {
	"content-type": "text/html; charset=utf-8",
	"content-security-policy":
		"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
	"x-content-type-options": "nosniff",
	"referrer-policy": "strict-origin-when-cross-origin",
	"permissions-policy": "camera=(), microphone=(), geolocation=()",
	"cross-origin-opener-policy": "same-origin",
	"cross-origin-resource-policy": "same-origin",
	"cache-control": "no-cache",
	etag: '"v1"',
};
const ASSET_HEADERS = {
	"cache-control": "public, max-age=31536000, immutable",
	"x-content-type-options": "nosniff",
	"cross-origin-resource-policy": "same-origin",
};

const goodPage = (name: string) => async () =>
	gzip(await Bun.file(fixture("web", "good", name)).text(), {
		...GOOD_HEADERS,
		"set-cookie": "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
	});

/** A healthy site: every check should pass (only informational notes allowed). */
export const goodSite = (): Site =>
	serve(
		{
			"/": goodPage("index.html"),
			"/about.html": goodPage("about.html"),
			"/privacy.html": goodPage("privacy.html"),
			"/robots.txt": (req) =>
				new Response(
					`User-agent: *\nAllow: /\nSitemap: ${new URL("/sitemap.xml", req.url)}\n`,
					{
						headers: { "content-type": "text/plain" },
					},
				),
			"/sitemap.xml": () =>
				new Response(
					'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/</loc></url></urlset>',
					{
						headers: { "content-type": "application/xml" },
					},
				),
			"/.well-known/security.txt": () =>
				new Response(
					"Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n",
					{ headers: { "content-type": "text/plain" } },
				),
			"/static/app.js": () =>
				gzip(APP_JS.replace("//# sourceMappingURL=app.js.map\n", ""), {
					...ASSET_HEADERS,
					"content-type": "application/javascript",
				}),
			"/static/site.css": () =>
				gzip(`body{margin:0}\n${".x{color:red}\n".repeat(100)}`, {
					...ASSET_HEADERS,
					"content-type": "text/css",
				}),
			"/static/logo.png": () =>
				new Response(new Uint8Array(1024), {
					headers: { ...ASSET_HEADERS, "content-type": "image/png" },
				}),
		},
		// SPA-style soft 404: 200 + HTML for everything else. Probes must not be fooled.
		goodPage("about.html"),
	);

/** A page that misbehaves at runtime, for the browser auditor. */
export const browserSite = (): Site =>
	serve(
		{ "/": () => html("browser/index.html") },
		() => new Response("not found", { status: 404 }),
	);
