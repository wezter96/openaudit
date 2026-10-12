import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Minimal slice of Playwright's BrowserContext/Route used by the guard. */
interface GuardResponse {
	status(): number;
	headers(): Record<string, string>;
}
interface GuardRoute {
	request(): { url(): string };
	abort(errorCode?: string): Promise<void>;
	fetch(options: {
		url?: string;
		maxRedirects: number;
	}): Promise<GuardResponse>;
	fulfill(options: {
		response?: GuardResponse;
		status?: number;
		headers?: Record<string, string>;
	}): Promise<void>;
}
interface GuardContext {
	route(
		url: string,
		handler: (route: GuardRoute) => Promise<void>,
	): Promise<void>;
}

/**
 * Confines a browser context to one origin at the network layer. Requests to
 * any other origin are aborted. Same-origin requests are fetched hop by hop
 * without following redirects, and every hop's origin is checked: Chromium
 * does not route the follow-up request of a fulfilled redirect, so the chain
 * must be walked here. A chain that stays on the origin is answered with one
 * redirect to its verified final URL; one that leaves it is aborted.
 *
 * Unlike Playwright MCP's `--allowed-origins` (documented as not a security
 * boundary), this covers redirects, links and page scripts. It is
 * self-contained on purpose: its source is written into the init-page file
 * that Playwright MCP evaluates in its own process.
 */
export async function installOriginGuard(
	context: GuardContext,
	origin: string,
): Promise<void> {
	if (!origin || origin === "null") throw new Error("openaudit: no origin");
	const marked = context as GuardContext & { __openauditGuard?: boolean };
	if (marked.__openauditGuard) return;
	marked.__openauditGuard = true;
	const sameOrigin = (url: string) => {
		try {
			return new URL(url).origin === origin;
		} catch {
			return false;
		}
	};
	await context.route("**/*", async (route) => {
		const first = route.request().url();
		let url = first;
		try {
			for (let hop = 0; hop < 10; hop++) {
				if (!sameOrigin(url)) return await route.abort("blockedbyclient");
				const response = await route.fetch({ url, maxRedirects: 0 });
				const status = response.status();
				const location = response.headers().location;
				if (status >= 300 && status < 400 && location) {
					url = new URL(location, url).toString();
					continue;
				}
				if (url === first) return await route.fulfill({ response });
				return await route.fulfill({ status: 302, headers: { location: url } });
			}
			return await route.abort("failed");
		} catch {
			return await route.abort("failed");
		}
	});
}

/** Env var through which the allowed origin reaches the init-page script. */
export const ORIGIN_ENV = "OPENAUDIT_ALLOWED_ORIGIN";

let initPagePath: string | undefined;

/**
 * Writes the init-page script for Playwright MCP (`--init-page <path>`) once
 * per process. Written at runtime so it also works from a compiled binary.
 */
export const browserGuardInitPage = (): string => {
	if (initPagePath) return initPagePath;
	const dir = mkdtempSync(join(tmpdir(), "openaudit-browser-"));
	initPagePath = join(dir, "origin-guard.ts");
	writeFileSync(
		initPagePath,
		`const installOriginGuard = ${installOriginGuard.toString()};\n` +
			`export default async ({ page }) => installOriginGuard(page.context(), process.env.${ORIGIN_ENV});\n`,
		{ mode: 0o600 },
	);
	return initPagePath;
};
