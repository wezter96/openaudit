import { OpenAPIGenerator } from "@orpc/openapi";
import { ZodToJsonSchemaConverter } from "@orpc/zod/zod4";

import { appRouter } from "./routers/index";

/**
 * The API's OpenAPI document, generated from the router the same way
 * apps/server's reference plugin does. The website publishes it at
 * /openapi.json for discovery; openaudit.se itself does not serve the API.
 */
export const openApiDocument = (options: {
	readonly version: string;
	readonly servers: ReadonlyArray<{ url: string; description?: string }>;
}) =>
	new OpenAPIGenerator({
		schemaConverters: [new ZodToJsonSchemaConverter()],
	}).generate(appRouter, {
		info: {
			title: "openaudit HTTP API (self-hosted)",
			version: options.version,
			description:
				"The HTTP API in apps/server and packages/api: run URL audits and read the auditor and playbook catalogue. You run it yourself; openaudit.se does not host it, so the server below is a local default. It has no authentication. URL audits are rate limited per client and server-wide, and refuse private, loopback and link-local targets unless the server is started with ALLOW_PRIVATE_TARGETS.",
			license: { name: "MIT", url: "https://opensource.org/licenses/MIT" },
		},
		servers: options.servers.map((s) => ({ ...s })),
		externalDocs: {
			description: "Source and setup",
			url: "https://github.com/wezter96/openaudit/tree/main/apps/server",
		},
	});
