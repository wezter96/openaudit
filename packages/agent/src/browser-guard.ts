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
interface GuardWebSocketRoute {
	url(): string;
	connectToServer(): unknown;
	close(options?: { code?: number; reason?: string }): Promise<void>;
}
interface GuardContext {
	route(
		url: string,
		handler: (route: GuardRoute) => Promise<void>,
	): Promise<void>;
	routeWebSocket(
		url: (url: URL) => boolean,
		handler: (ws: GuardWebSocketRoute) => unknown,
	): Promise<void>;
}

/**
 * Confines a browser context to one origin at the network layer. Requests to
 * any other origin are aborted. Same-origin requests are fetched hop by hop
 * without following redirects, and every hop's origin is checked: Chromium
 * does not route the follow-up request of a fulfilled redirect, so the chain
 * is walked here and the verified final response is served directly (under the
 * original URL). Answering with a redirect instead would let the browser make
 * an unrouted second request that a stateful server could send elsewhere.
 * WebSockets are routed separately and held to the same origin. WebRTC and DNS
 * prefetch are disabled through launch flags (see `browserGuardFiles`).
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
			const u = new URL(url);
			// ws(s):// shares the origin of http(s):// on the same host and port.
			if (u.protocol === "ws:") u.protocol = "http:";
			if (u.protocol === "wss:") u.protocol = "https:";
			return u.origin === origin;
		} catch {
			return false;
		}
	};
	await context.routeWebSocket(
		() => true,
		(ws) =>
			sameOrigin(ws.url())
				? ws.connectToServer()
				: ws.close({ code: 1008, reason: "blocked by openaudit" }),
	);
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
				return await route.fulfill({ response });
			}
			return await route.abort("failed");
		} catch {
			return await route.abort("failed");
		}
	});
}

/** Env var through which the allowed origin reaches the init-page script. */
export const ORIGIN_ENV = "OPENAUDIT_ALLOWED_ORIGIN";

/** Chromium flags closing channels that request routing does not see. */
export const GUARD_LAUNCH_ARGS = [
	"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
	"--webrtc-ip-handling-policy=disable_non_proxied_udp",
	"--dns-prefetch-disable",
	"--disable-features=NetworkPrediction,DnsOverHttps",
];

let files: { initPage: string; config: string } | undefined;

/**
 * Writes the init-page script and config file for Playwright MCP
 * (`--init-page`, `--config`) once per process. Written at runtime so they
 * also work from a compiled binary.
 */
export const browserGuardFiles = (): { initPage: string; config: string } => {
	if (files) return files;
	const dir = mkdtempSync(join(tmpdir(), "openaudit-browser-"));
	const initPage = join(dir, "origin-guard.ts");
	const config = join(dir, "playwright-mcp.json");
	writeFileSync(
		initPage,
		`const installOriginGuard = ${installOriginGuard.toString()};\n` +
			`export default async ({ page }) => installOriginGuard(page.context(), process.env.${ORIGIN_ENV});\n`,
		{ mode: 0o600 },
	);
	writeFileSync(
		config,
		JSON.stringify({
			browser: {
				launchOptions: { args: GUARD_LAUNCH_ARGS },
				contextOptions: { serviceWorkers: "block" },
			},
		}),
		{ mode: 0o600 },
	);
	files = { initPage, config };
	return files;
};
