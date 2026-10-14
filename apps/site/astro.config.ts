import sitemap from "@astrojs/sitemap";
import { defineConfig } from "astro/config";

/*
 * Where the site is served: https://openaudit.se at the root by default.
 * Override SITE_URL and BASE_PATH to host it elsewhere (CUSTOM_DOMAIN writes
 * a CNAME file for GitHub Pages, see scripts/postbuild.ts).
 */
const site = process.env.SITE_URL ?? "https://openaudit.se";
const base = (process.env.BASE_PATH ?? "/").replace(/\/$/, "");

export default defineConfig({
	site,
	base: base || "/",
	trailingSlash: "always",
	build: {
		format: "directory",
		// One request less before first paint; postbuild hashes each inline
		// style and script into the page's CSP.
		inlineStylesheets: "always",
	},
	vite: { build: { assetsInlineLimit: 0 } },
	devToolbar: { enabled: false },
	integrations: [
		sitemap({
			// Copied in from the CLI rather than rendered by Astro.
			customPages: [`${site}${base}/report/`],
			filter: (page) => !page.includes("/404"),
		}),
	],
});
