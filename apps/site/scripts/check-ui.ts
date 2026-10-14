/**
 * Checks the built site in real browsers, the way a phone or laptop sees it:
 *
 * - nothing scrolls sideways;
 * - a link home is on screen, even scrolled to the bottom (sticky nav);
 * - scrolled to the bottom, the whole footer is on screen;
 * - opening a menu (site menu, the report's Download menu, the bar's Menu)
 *   moves nothing on the page;
 * - no console errors or uncaught exceptions.
 *
 * Usage: bun scripts/check-ui.ts [base URL]   (default http://localhost:4321,
 * which is `bunx astro preview` after `bun run build`). Needs the browsers
 * once: `bunx playwright install webkit chromium`.
 */
import {
	type Browser,
	type BrowserType,
	chromium,
	type Page,
	webkit,
} from "playwright";

const base = (process.argv[2] ?? "http://localhost:4321").replace(/\/$/, "");

const PAGES = [
	"/",
	"/docs/",
	"/developers/",
	"/docs/cli/",
	"/docs/configuration/",
	"/docs/ci/",
	"/docs/agents/",
	"/docs/api/",
	"/docs/report/",
	"/docs/safety/",
	"/docs/contributing/",
	"/auditors/",
	"/auditors/code.lockfiles/",
	"/report/",
	"/guides/mcp-security/",
];
const WIDTHS = [
	{ width: 375, height: 667 },
	// the largest phones: wide enough for buttons to share a row with a title
	{ width: 430, height: 932 },
	{ width: 768, height: 1024 },
	{ width: 1280, height: 800 },
];
/**
 * Menus that open over the page, by trigger and the panel it opens; each must
 * leave the page where it was and fit on screen. Disclosures that open in place (FAQ, "All N wrapped tools") push
 * the content below them down on purpose, so they are not listed.
 */
const MENUS: Record<string, string> = {
	"[data-menu]": "#site-nav",
	"#dl-button": "#dl-menu",
	".oa-bar-menu summary": ".oa-bar-menu nav",
};
/** Theme switches: one click must change the theme, a second puts it back. */
const THEMES = ["[data-theme-toggle]", "[data-oa-theme]"];

const failures: string[] = [];
const fail = (where: string, what: string) =>
	failures.push(`${where}: ${what}`);

/** Where the page's main parts are, to compare before and after a menu opens. */
const layout = (page: Page) =>
	page.evaluate(() => {
		const box = (el: Element | null) => {
			if (!el) return null;
			const r = el.getBoundingClientRect();
			return [Math.round(r.left), Math.round(r.top), Math.round(r.width)];
		};
		return JSON.stringify({
			x: Math.round(window.scrollX),
			y: Math.round(window.scrollY),
			sw: document.documentElement.scrollWidth,
			h1: box(document.querySelector("h1")),
			main: box(document.querySelector("main")),
		});
	});

const open = async (page: Page, path: string) => {
	// WebKit never fires load on http://localhost pages whose CSP upgrades
	// requests; the page is usable once the DOM is there.
	await page.goto(base + path, { waitUntil: "commit", timeout: 30_000 });
	await page
		.waitForLoadState("domcontentloaded", { timeout: 10_000 })
		.catch(() => {});
	await page.waitForTimeout(400);
};

const checkPage = async (page: Page, where: string, path: string) => {
	await open(page, path);

	const wide = await page.evaluate(() => {
		const doc = document.documentElement;
		return doc.scrollWidth > doc.clientWidth + 1
			? `${doc.scrollWidth}px wide in a ${doc.clientWidth}px viewport`
			: "";
	});
	if (wide) fail(where, `scrolls sideways (${wide})`);

	for (const [selector, panel] of Object.entries(MENUS)) {
		const trigger = page.locator(selector).first();
		if (!(await trigger.isVisible().catch(() => false))) continue;
		await trigger.scrollIntoViewIfNeeded();
		await page.waitForTimeout(150);
		const before = await layout(page);
		await trigger.click();
		await page.waitForTimeout(500);
		const after = await layout(page);
		if (before !== after) fail(where, `opening ${selector} moved the page`);
		const off = await page.evaluate((sel) => {
			const el = document.querySelector(sel);
			if (!el) return "";
			const r = el.getBoundingClientRect();
			if (r.width === 0) return "";
			return r.left < -1 || r.right > window.innerWidth + 1
				? `${Math.round(r.left)} to ${Math.round(r.right)} in a ${window.innerWidth}px viewport`
				: "";
		}, panel);
		if (off) fail(where, `${panel} opens off screen (${off})`);
		await page.keyboard.press("Escape");
		if (selector !== "#dl-button") {
			// Escape doesn't close these; click again so the next check starts
			// from the same page
			if (await trigger.isVisible().catch(() => false)) await trigger.click();
		}
		await page.waitForTimeout(200);
	}

	for (const selector of THEMES) {
		const button = page.locator(selector).first();
		if (!(await button.isVisible().catch(() => false))) continue;
		const theme = () =>
			page.evaluate(() => {
				const d = document.documentElement;
				return (
					d.dataset.theme ??
					(matchMedia("(prefers-color-scheme: dark)").matches
						? "dark"
						: "light")
				);
			});
		const first = await theme();
		await button.click();
		const second = await theme();
		await button.click();
		if (first === second) fail(where, `${selector} doesn't switch the theme`);
		else if ((await theme()) !== first)
			fail(where, `${selector} doesn't switch the theme back`);
	}

	await page.evaluate(() => {
		document.documentElement.style.scrollBehavior = "auto";
		window.scrollTo(0, document.documentElement.scrollHeight);
	});
	await page.waitForTimeout(500);
	const bottom = await page.evaluate(() => {
		const out: string[] = [];
		const vh = window.innerHeight;
		const home = [...document.querySelectorAll<HTMLAnchorElement>("a[href]")]
			.filter((a) => new URL(a.href).pathname === "/")
			.some((a) => {
				const r = a.getBoundingClientRect();
				if (r.width === 0 || r.bottom <= 0 || r.top >= vh) return false;
				const hit = document.elementFromPoint(
					r.left + r.width / 2,
					r.top + r.height / 2,
				);
				return !!hit && (a === hit || a.contains(hit));
			});
		if (!home) out.push("no link home on screen at the bottom of the page");
		const foot = document.querySelector("footer:last-of-type");
		if (foot) {
			let lowest = foot.getBoundingClientRect().bottom;
			for (const el of foot.querySelectorAll("*")) {
				const r = el.getBoundingClientRect();
				if (r.height > 0) lowest = Math.max(lowest, r.bottom);
			}
			if (lowest > vh + 1) {
				out.push(
					`footer ends ${Math.round(lowest - vh)}px below the screen at the bottom`,
				);
			}
		}
		return out;
	});
	for (const b of bottom) fail(where, b);
};

const run = async (name: string, type: BrowserType) => {
	let browser: Browser;
	try {
		browser = await type.launch();
	} catch (e) {
		fail(name, `cannot start (${(e as Error).message.split("\n")[0]})`);
		return;
	}
	await Promise.all(
		WIDTHS.map(async (viewport) => {
			const context = await browser.newContext({
				viewport,
				hasTouch: viewport.width < 800,
				reducedMotion: "reduce",
			});
			const page = await context.newPage();
			let current = "";
			page.on("pageerror", (e) => fail(current, `uncaught ${e.message}`));
			page.on("console", (m) => {
				if (m.type() === "error") fail(current, `console: ${m.text()}`);
			});
			for (const path of PAGES) {
				current = `${name} ${viewport.width}px ${path}`;
				await checkPage(page, current, path).catch((e: Error) =>
					fail(current, e.message.split("\n")[0] ?? "error"),
				);
			}
			await context.close();
		}),
	);
	await browser.close();
};

// A dev server for another project can hold the default port.
const home = await fetch(`${base}/`).then(
	(r) => r.text(),
	() => "",
);
if (!home.includes("openaudit")) {
	console.error(
		`check-ui: ${base}/ is not the openaudit site (is the preview on another port?)`,
	);
	process.exit(1);
}

const started = Date.now();
await Promise.all([run("webkit", webkit), run("chromium", chromium)]);
const took = ((Date.now() - started) / 1000).toFixed(0);
if (failures.length) {
	console.error(
		`check-ui: ${failures.length} problem(s) on ${base} (${took} s)\n${failures.map((f) => `  ${f}`).join("\n")}`,
	);
	process.exit(1);
}
console.log(
	`check-ui: ${PAGES.length} pages × ${WIDTHS.length} widths × 2 browsers ok on ${base} (${took} s)`,
);
