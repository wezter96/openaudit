import sitemap from "@astrojs/sitemap";
import { defineConfig } from "astro/config";

/*
 * Where the site is served. GitHub Pages by default; for openaudit.se set
 * SITE_URL=https://openaudit.se and BASE_PATH=/ (and CUSTOM_DOMAIN for the
 * CNAME file, see scripts/postbuild.ts).
 */
const site = process.env.SITE_URL ?? "https://wezter96.github.io";
const base = (process.env.BASE_PATH ?? "/openaudit").replace(/\/$/, "");

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
			customPages: [`${site}${base}/report/`, `${site}${base}/architecture/`],
			filter: (page) => !page.includes("/404"),
		}),
	],
});
