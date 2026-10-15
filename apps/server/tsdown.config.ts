import { readFileSync } from "node:fs";
import { defineConfig } from "tsdown";

export default defineConfig({
	entry: "./src/index.ts",
	format: "esm",
	outDir: "./dist",
	clean: true,
	deps: {
		alwaysBundle: [/@openaudit\/.*/],
	},
	plugins: [
		{
			// The HTML report's browser script is plain JavaScript that core
			// imports with `{ type: "text" }`, which Bun understands natively.
			name: "report-script-as-text",
			load: {
				filter: { id: /reporters\/html\/report\.js$/ },
				handler: (id) => ({
					code: readFileSync(id, "utf8"),
					moduleType: "text",
				}),
			},
		},
	],
});
