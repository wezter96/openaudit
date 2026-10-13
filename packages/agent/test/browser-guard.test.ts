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
	const target = Bun.serve({
		port: 0,
		fetch: (req) => {
			const path = new URL(req.url).pathname;
			if (path === "/hop.png" || path === "/nav")
				return Response.redirect(`${elsewhere.url}leak${path}`, 302);
			if (path === "/same") return Response.redirect("/page", 302);
			// Stateful: first request redirects on-origin, later ones off-origin.
			if (path === "/flip") {
				flips++;
				return flips === 1
					? Response.redirect("/flip-final", 302)
					: Response.redirect(`${elsewhere.url}leak/flip`, 302);
			}
			if (path === "/flip-final") {
				finalHits++;
				return finalHits === 1
					? new Response("<h1>final</h1>", {
							headers: { "content-type": "text/html" },
						})
					: Response.redirect(`${elsewhere.url}leak/final`, 302);
			}
			if (path === "/ws-page")
				return new Response(
					`<html><body><script>new WebSocket("${elsewhere.url.toString().replace("http", "ws")}sock")</script></body></html>`,
					{ headers: { "content-type": "text/html" } },
				);
			return new Response(
				`<html><body><h1>page</h1><img src="/hop.png"><img src="${elsewhere.url}direct.png"><script src="${elsewhere.url}x.js"></script></body></html>`,
				{ headers: { "content-type": "text/html" } },
			);
		},
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
