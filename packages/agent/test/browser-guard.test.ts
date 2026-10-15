import { afterAll, describe, expect, test } from "bun:test";
import { createRequire } from "node:module";
import { join } from "node:path";

import {
	browserGuardFiles,
	installOriginGuard,
	ORIGIN_ENV,
} from "../src/browser-guard";

// playwright-core is an optional dependency of @openaudit/auditors.
const loadChromium = async () => {
	try {
		const require = createRequire(
			join(import.meta.dir, "../../auditors/package.json"),
		);
		// Typed loosely: playwright-core is not a dependency of this package.
		// biome-ignore lint/suspicious/noExplicitAny: optional cross-package import
		const pw: any = await import(require.resolve("playwright-core"));
		// biome-ignore lint/suspicious/noExplicitAny: see above
		const browser: any = await pw.chromium
			.launch()
			.catch(() => pw.chromium.launch({ channel: "chrome" }));
		return browser;
	} catch {
		return undefined;
	}
};

const html = (body: string) =>
	new Response(body, { headers: { "content-type": "text/html" } });

describe("browser origin guard", async () => {
	const elsewhereHits: string[] = [];
	let flips = 0;
	let finalHits = 0;
	const elsewhere = Bun.serve({
		port: 0,
		fetch: (req) => {
			elsewhereHits.push(new URL(req.url).pathname);
			return new Response("elsewhere", {
				headers: { "content-type": "text/html" },
			});
		},
	});
	const leak = (path: string) =>
		Response.redirect(`${elsewhere.url}leak${path}`, 302);
	const routes = new Map<string, () => Response>([
		["/hop.png", () => leak("/hop.png")],
		["/nav", () => leak("/nav")],
		["/same", () => Response.redirect("/page", 302)],
		// Stateful: first request redirects on-origin, later ones off-origin.
		[
			"/flip",
			() => {
				flips++;
				return flips === 1
					? Response.redirect("/flip-final", 302)
					: leak("/flip");
			},
		],
		[
			"/flip-final",
			() => {
				finalHits++;
				return finalHits === 1 ? html("<h1>final</h1>") : leak("/final");
			},
		],
		[
			"/ws-page",
			() =>
				html(
					`<html><body><script>new WebSocket("${elsewhere.url.toString().replace("http", "ws")}sock")</script></body></html>`,
				),
		],
	]);
	const page = () =>
		html(
			`<html><body><h1>page</h1><img src="/hop.png"><img src="${elsewhere.url}direct.png"><script src="${elsewhere.url}x.js"></script></body></html>`,
		);
	const target = Bun.serve({
		port: 0,
		fetch: (req) => (routes.get(new URL(req.url).pathname) ?? page)(),
	});
	const browser = await loadChromium();
	afterAll(async () => {
		await browser?.close();
		target.stop(true);
		elsewhere.stop(true);
	});
	const origin = target.url.origin;

	test.skipIf(!browser)(
		"blocks other origins, including via redirects and subresources",
		async () => {
			const context = await browser.newContext({
				permissions: ["local-network-access"],
			});
			await installOriginGuard(context, origin);
			const page = await context.newPage();

			await page.goto(`${origin}/page`);
			expect(await page.textContent("h1")).toBe("page");
			await page.waitForLoadState("networkidle");

			// Same-origin redirects still work; the verified final body is served.
			await page.goto(`${origin}/same`);
			expect(await page.textContent("h1")).toBe("page");

			// A server that changes its answer between requests gets no second,
			// unrouted request from the browser.
			await page.goto(`${origin}/flip`);
			expect(await page.textContent("h1")).toBe("final");

			// WebSockets to other origins are refused.
			await page.goto(`${origin}/ws-page`);
			await page.waitForTimeout(300);

			// Redirect to another origin and direct navigation both fail.
			await expect(page.goto(`${origin}/nav`)).rejects.toThrow();
			await expect(page.goto(`${elsewhere.url}`)).rejects.toThrow();
			await context.close();

			expect(elsewhereHits).toEqual([]);
		},
		// Chromium starts slowly on shared CI runners.
		30_000,
	);

	test.skipIf(!browser)(
		"the generated init-page installs the same guard",
		async () => {
			process.env[ORIGIN_ENV] = origin;
			const mod = (await import(browserGuardFiles().initPage)) as {
				default: (arg: { page: unknown }) => Promise<void>;
			};
			const context = await browser.newContext({
				permissions: ["local-network-access"],
			});
			const page = await context.newPage();
			await mod.default({ page });
			await expect(page.goto(`${elsewhere.url}`)).rejects.toThrow();
			await context.close();
			expect(elsewhereHits).toEqual([]);
		},
	);
});
