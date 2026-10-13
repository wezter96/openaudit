/**
 * The site is static; this Worker only sends www.openaudit.se to the apex
 * (static assets cannot redirect by host). Everything else is served from
 * dist/ by the assets binding, with dist/_headers applied.
 */
interface Env {
	readonly ASSETS: { fetch: (request: Request) => Promise<Response> };
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		if (url.hostname.startsWith("www.")) {
			url.hostname = url.hostname.slice(4);
			return Response.redirect(url.toString(), 301);
		}
		return env.ASSETS.fetch(request);
	},
};
