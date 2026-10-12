import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	baseName,
	extOf,
	fullLineAt,
	isCommentLine,
	isFixturePath,
	isGeneratedPath,
	isRecord,
	isTestPath,
	lineLocator,
	parseJsonc,
	readTextFiles,
	type SourceFile,
	truncate,
} from "./util";

const KB = 1024;
const IMAGE_EXT = new Set([
	"png",
	"jpg",
	"jpeg",
	"gif",
	"bmp",
	"tif",
	"tiff",
	"webp",
	"avif",
	"svg",
]);
const LEGACY_IMAGE_EXT = new Set([
	"png",
	"jpg",
	"jpeg",
	"gif",
	"bmp",
	"tif",
	"tiff",
]);
const VIDEO_EXT = new Set(["mp4", "mov", "webm", "avi", "mkv", "m4v", "ogv"]);
const FONT_EXT = new Set(["ttf", "otf", "woff", "woff2", "eot"]);
const LEGACY_FONT_EXT = new Set(["ttf", "otf", "eot"]);

const IMAGE_LIMIT = 300 * KB;
const LEGACY_IMAGE_LIMIT = 100 * KB;
const VIDEO_LIMIT = 1024 * KB;
const FONT_LIMIT = 200 * KB;

/** Directories whose contents are shipped to browsers. */
const WEB_ASSET_DIR =
	/(^|\/)(public|static|assets|images|img|media|www|wwwroot|web|res|resources|src)\//;

const fmt = (bytes: number) =>
	bytes >= 1024 * KB
		? `${(bytes / 1024 / KB).toFixed(1)} MB`
		: `${Math.round(bytes / KB)} KB`;

const PERF_REFS = {
	images: "https://web.dev/articles/choose-the-right-image-format",
	video: "https://web.dev/articles/replace-gifs-with-videos",
	fonts: "https://web.dev/articles/reduce-webfont-size",
	bundle:
		"https://web.dev/articles/reduce-javascript-payloads-with-tree-shaking",
};

/** Large images, videos and fonts committed to web-served directories. */
export const assetFindings = (path: string, size: number): FindingInput[] => {
	const ext = extOf(path);
	if (!WEB_ASSET_DIR.test(path) || isFixturePath(path)) return [];
	const base = {
		category: "performance" as const,
		location: { file: path },
		evidence: `${baseName(path)} (${fmt(size)})`,
	};
	if (IMAGE_EXT.has(ext) && size > IMAGE_LIMIT)
		return [
			{
				...base,
				ruleId: "code.performance/large-image",
				title: `Large image (${fmt(size)})`,
				severity: size > 1024 * KB ? "medium" : "low",
				message: `${path} is ${fmt(size)}. Large images dominate page weight and delay Largest Contentful Paint.`,
				remediation: LEGACY_IMAGE_EXT.has(ext)
					? "Resize to the displayed dimensions and convert to WebP or AVIF (e.g. with sharp/squoosh); serve responsive sizes via srcset."
					: ext === "svg"
						? "Optimize the SVG with SVGO, or rasterize very complex vectors."
						: "Resize to the displayed dimensions and serve responsive sizes via srcset.",
				references: [PERF_REFS.images],
				confidence: "high",
			},
		];
	if (LEGACY_IMAGE_EXT.has(ext) && size > LEGACY_IMAGE_LIMIT)
		return [
			{
				...base,
				ruleId: "code.performance/legacy-image-format",
				title: `Image could use a modern format (${ext.toUpperCase()})`,
				severity: "info",
				message: `${path} (${fmt(size)}) is ${ext.toUpperCase()}; WebP/AVIF are typically 25–50% smaller at equal quality.`,
				remediation:
					ext === "gif"
						? "Replace animated GIFs with muted, looping <video> (MP4/WebM); convert static GIFs to WebP."
						: "Convert to WebP or AVIF, or let your framework's image component do it (next/image, @astrojs/image).",
				references: [PERF_REFS.images],
				confidence: "high",
			},
		];
	if (VIDEO_EXT.has(ext) && size > VIDEO_LIMIT)
		return [
			{
				...base,
				ruleId: "code.performance/large-video",
				title: `Large video committed (${fmt(size)})`,
				severity: size > 10 * 1024 * KB ? "medium" : "low",
				message: `${path} is ${fmt(size)}. Videos bloat the repository and are expensive to serve from the app origin.`,
				remediation:
					'Compress (H.264/VP9/AV1 at an appropriate bitrate), use preload="none" or a poster, and host large media on a CDN or video platform.',
				references: [PERF_REFS.video],
				confidence: "high",
			},
		];
	if (FONT_EXT.has(ext) && (size > FONT_LIMIT || LEGACY_FONT_EXT.has(ext)))
		return [
			{
				...base,
				ruleId: "code.performance/heavy-font",
				title:
					size > FONT_LIMIT
						? `Large font file (${fmt(size)})`
						: `Legacy font format (${ext.toUpperCase()})`,
				severity: size > FONT_LIMIT ? "low" : "info",
				message: `${path} is a ${fmt(size)} ${ext.toUpperCase()} font. Fonts block text rendering until loaded.`,
				remediation:
					"Serve WOFF2 only, subset to the glyphs you use (e.g. glyphhanger, fonttools pyftsubset), and use font-display: swap.",
				references: [PERF_REFS.fonts],
				confidence: "high",
			},
		];
	return [];
};

/** Heavy runtime packages with lighter alternatives. */
const HEAVY_DEPS: ReadonlyArray<{
	readonly name: string;
	readonly alternative: string;
	readonly when?: (deps: Record<string, unknown>) => boolean;
}> = [
	{
		name: "moment",
		alternative:
			"date-fns, dayjs, Luxon or the Intl/Temporal APIs (moment is in maintenance mode and ~70 KB gzip)",
	},
	{
		name: "moment-timezone",
		alternative: "date-fns-tz, Luxon, or Intl.DateTimeFormat with timeZone",
	},
	{
		name: "lodash",
		alternative:
			"lodash-es (tree-shakeable), per-method imports, or native Array/Object methods",
	},
	{ name: "underscore", alternative: "native Array/Object methods" },
	{
		name: "jquery",
		alternative:
			"native DOM APIs; mixing jQuery with a component framework duplicates work and bundle size",
		when: (deps) =>
			["react", "vue", "svelte", "@angular/core", "solid-js", "preact"].some(
				(d) => d in deps,
			),
	},
	{
		name: "core-js",
		alternative:
			"targeted polyfills via @babel/preset-env useBuiltIns: 'usage' or browserslist-driven builds",
	},
	{
		name: "aws-sdk",
		alternative:
			"modular AWS SDK v3 clients (@aws-sdk/client-*); v2 is end-of-life and very large",
	},
	{ name: "bluebird", alternative: "native Promise and async/await" },
	{
		name: "crypto-js",
		alternative: "the Web Crypto API (crypto.subtle) or node:crypto",
	},
	{
		name: "request",
		alternative: "native fetch, undici or ky (request is deprecated)",
	},
];

export const checkPackageJsonDeps = (file: SourceFile): FindingInput[] => {
	const json = parseJsonc(file.text);
	if (!isRecord(json) || !isRecord(json.dependencies)) return [];
	const deps = json.dependencies;
	const lineOf = lineLocator(file.text);
	return HEAVY_DEPS.filter(
		(h) => h.name in deps && (h.when?.(deps) ?? true),
	).map((h) => {
		const i = file.text.indexOf(`"${h.name}"`);
		return {
			ruleId: "code.performance/heavy-dependency",
			title: `Heavy dependency: ${h.name}`,
			severity: "low",
			category: "performance",
			message: `${h.name} is a large runtime dependency that inflates bundles and install size.`,
			location: { file: file.path, line: i === -1 ? undefined : lineOf(i) },
			evidence: `"${h.name}": "${String(deps[h.name])}"`,
			remediation: `Consider ${h.alternative}.`,
			references: [
				`https://bundlephobia.com/package/${h.name}`,
				"https://github.com/es-tooling/module-replacements",
			],
			confidence: "medium",
		};
	});
};

const FULL_IMPORTS: ReadonlyArray<readonly [RegExp, string]> = [
	[
		/\bimport\s+(?:\*\s+as\s+)?[\w$]+\s+from\s+["']lodash["']|\brequire\(\s*["']lodash["']\s*\)/g,
		"Import single functions (`lodash/debounce`) or use lodash-es so unused code is tree-shaken.",
	],
	[
		/\bimport\s*\{[^}]*\}\s*from\s+["']lodash["']/g,
		"The `lodash` package is CommonJS and not tree-shakeable; switch to lodash-es or per-method imports.",
	],
	[
		/\bimport\s+\*\s+as\s+[\w$]+\s+from\s+["'](?:@mui\/icons-material|@material-ui\/icons|react-icons\/\w+|lucide-react|@fortawesome\/[\w-]+-svg-icons|date-fns|rxjs)["']/g,
		"Import only the members you use; namespace imports of large libraries defeat tree-shaking in many bundlers.",
	],
	[
		/\bimport\s+["']core-js["']|\brequire\(\s*["']core-js["']\s*\)/g,
		"Import only the polyfills you need (or let preset-env inject them by usage).",
	],
];

const SERVER_HINT =
	/\b(?:app|router|server|fastify)\.(?:get|post|put|patch|delete|use|all|route)\s*\(|createServer\s*\(|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|loader|action|handler)\b|Bun\.serve\s*\(|new\s+Hono\b|@(?:Get|Post|Controller)\(/;

const SYNC_CALL =
	/\b(?:fs\.)?(?:readFileSync|writeFileSync|appendFileSync|existsSync|readdirSync|statSync|lstatSync|mkdirSync|copyFileSync|unlinkSync|execSync|spawnSync)\s*\(/g;

const JS_EXT = new Set([
	"js",
	"jsx",
	"mjs",
	"cjs",
	"ts",
	"tsx",
	"mts",
	"cts",
	"vue",
	"svelte",
]);
const NON_PRODUCTION =
	/(^|\/)(scripts?|bin|tools|examples?|docs?|benchmarks?|config|\.storybook|cli)\/|\.config\.[cm]?[jt]s$|(^|\/)(cli|bin)\.[cm]?[jt]s$/;

export interface ConsoleCount {
	readonly path: string;
	readonly count: number;
	readonly firstLine: number;
}

/** Per-file source checks; console.log counts are aggregated by the caller. */
export const scanPerformanceSource = (
	file: SourceFile,
): { findings: FindingInput[]; console?: ConsoleCount } => {
	const { path, text } = file;
	const lineOf = lineLocator(text);
	const findings: FindingInput[] = [];
	for (const [re, remediation] of FULL_IMPORTS) {
		for (const m of text.matchAll(re)) {
			findings.push({
				ruleId: "code.performance/full-library-import",
				title: "Whole-library import",
				severity: "low",
				category: "performance",
				message:
					"This import pulls in an entire library, increasing bundle size for code that is never used.",
				location: { file: path, line: lineOf(m.index ?? 0) },
				evidence: truncate(m[0]),
				remediation,
				references: [PERF_REFS.bundle],
				confidence: "medium",
			});
		}
	}

	if (SERVER_HINT.test(text)) {
		for (const m of text.matchAll(SYNC_CALL)) {
			const index = m.index ?? 0;
			const line = fullLineAt(text, index);
			// Top-level calls run once at startup, which is fine.
			if (!/^\s+/.test(line) || isCommentLine(line)) continue;
			findings.push({
				ruleId: "code.performance/sync-io-in-handler",
				title: "Synchronous I/O in server code",
				severity: "low",
				category: "performance",
				message:
					"A blocking *Sync call appears inside a function in server code. If it runs per request it stalls the event loop for every concurrent request.",
				location: { file: path, line: lineOf(index) },
				evidence: truncate(line),
				remediation:
					"Use the async variant (fs.promises / await Bun.file().text()) inside request handlers, or hoist one-time reads to module startup.",
				references: [
					"https://nodejs.org/en/learn/asynchronous-work/dont-block-the-event-loop",
				],
				confidence: "low",
			});
		}
	}

	let count = 0;
	let firstIndex = -1;
	for (const m of text.matchAll(/\bconsole\.(?:log|debug|trace)\s*\(/g)) {
		if (isCommentLine(fullLineAt(text, m.index ?? 0))) continue;
		if (firstIndex === -1) firstIndex = m.index ?? 0;
		count++;
	}
	return {
		findings,
		console:
			count > 0 ? { path, count, firstLine: lineOf(firstIndex) } : undefined,
	};
};

const CONSOLE_THRESHOLD = 10;

export const consoleFinding = (
	counts: ReadonlyArray<ConsoleCount>,
): FindingInput | undefined => {
	const total = counts.reduce((n, c) => n + c.count, 0);
	if (total < CONSOLE_THRESHOLD) return undefined;
	const top = [...counts].sort((a, b) => b.count - a.count);
	const worst = top[0];
	return {
		ruleId: "code.performance/console-logging",
		title: `${total} console.log calls in production source`,
		severity: "info",
		category: "performance",
		message: `Found ${total} console.log/debug/trace calls across ${counts.length} files (most in ${top
			.slice(0, 3)
			.map((c) => `${c.path} (${c.count})`)
			.join(
				", ",
			)}). Logging in hot paths costs CPU and can leak data to browser consoles.`,
		location: worst ? { file: worst.path, line: worst.firstLine } : undefined,
		remediation:
			"Use a leveled logger, and strip debug logging from production builds (e.g. esbuild `drop: ['console']`, terser drop_console, or a lint rule like no-console).",
		confidence: "high",
	};
};

const isProductionSource = (path: string) =>
	JS_EXT.has(extOf(path)) &&
	!isTestPath(path) &&
	!isFixturePath(path) &&
	!isGeneratedPath(path) &&
	!NON_PRODUCTION.test(path);

export const performanceAuditor = defineAuditor({
	id: "code.performance",
	title: "Performance (static)",
	description:
		"Flags large committed images/videos/fonts, legacy asset formats, heavy dependencies, whole-library imports, synchronous I/O in server handlers and leftover console logging.",
	categories: ["performance"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const all = yield* ws.files;
			const findings: FindingInput[] = [];

			const assets = all
				.filter((f) => {
					const ext = extOf(f);
					return IMAGE_EXT.has(ext) || VIDEO_EXT.has(ext) || FONT_EXT.has(ext);
				})
				.slice(0, 5000);
			const sizes = yield* Effect.forEach(
				assets,
				(path) =>
					Effect.map(ws.size(path), (size) => [path, size] as const).pipe(
						Effect.orElseSucceed(() => [path, 0] as const),
					),
				{ concurrency: 16 },
			);
			for (const [path, size] of sizes)
				findings.push(...assetFindings(path, size));

			const manifests = yield* readTextFiles(
				ws,
				(p) => baseName(p) === "package.json" && !isFixturePath(p),
			);
			findings.push(...manifests.flatMap(checkPackageJsonDeps));

			const sources = yield* readTextFiles(ws, isProductionSource);
			const consoleCounts: ConsoleCount[] = [];
			for (const file of sources) {
				const result = scanPerformanceSource(file);
				findings.push(...result.findings);
				if (result.console) consoleCounts.push(result.console);
			}
			const logging = consoleFinding(consoleCounts);
			if (logging) findings.push(logging);
			return findings;
		}),
});
