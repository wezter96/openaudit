import { stat } from "node:fs/promises";
import { basename, dirname, extname, resolve } from "node:path";
import { Effect } from "effect";

import type { AuditOptions } from "./auditor";
import { TargetError } from "./errors";
import type { TargetInfo, TargetKind } from "./model";
import type { Workspace } from "./services";

/** What the user passed as the target: a URL, `image:…`, `cloud:…` or a path. */
type TargetInput = string;
type AbsolutePath = string;
type FileName = string;
/** A lowercase file extension with its dot, like `.tf`. */
type Extension = string;

const MOBILE_ARTIFACTS = new Set([".apk", ".aab", ".ipa"]);

/** Technology markers: file glob → technology tag. */
const TECH_MARKERS: ReadonlyArray<readonly [RegExp, string]> = [
	[/(^|\/)package\.json$/, "node"],
	[/(^|\/)tsconfig\.json$/, "typescript"],
	[/(^|\/)(requirements\.txt|pyproject\.toml|Pipfile)$/, "python"],
	[/(^|\/)go\.mod$/, "go"],
	[/(^|\/)Cargo\.toml$/, "rust"],
	[/(^|\/)(pom\.xml|build\.gradle(\.kts)?)$/, "jvm"],
	[/(^|\/)Gemfile$/, "ruby"],
	[/(^|\/)composer\.json$/, "php"],
	[/\.csproj$/, "dotnet"],
	[/(^|\/)(next\.config\.[cm]?[jt]s)$/, "nextjs"],
	[/(^|\/)(vite\.config\.[cm]?[jt]s)$/, "vite"],
	[/\.(jsx|tsx)$/, "react"],
	[/\.vue$/, "vue"],
	[/\.svelte$/, "svelte"],
	[/\.html?$/, "html"],
	[
		/(^|\/)(Dockerfile|Containerfile)(\.(?!(?:dockerignore|[cm]?[jt]sx?|py|go|rb|rs|java|kt|swift|php|cs|md|mdx|json|ya?ml|toml|txt|sh|snap|map)$)[\w-]+)?$|\.dockerfile$/i,
		"docker",
	],
	[/(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$/, "docker-compose"],
	[/\.tf$/, "terraform"],
	[/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/, "github-actions"],
	[/(^|\/)(Chart\.yaml|kustomization\.ya?ml)$/, "kubernetes"],
	[/(^|\/)AndroidManifest\.xml$/, "android"],
	[/(^|\/)Info\.plist$|\.xcodeproj\//, "ios"],
	[/(^|\/)pubspec\.yaml$/, "flutter"],
	[/(^|\/)app\.json$|(^|\/)app\.config\.[jt]s$/, "expo"],
];

/** Target kinds a directory adds when it contains any of these technologies. */
const KINDS_BY_TECH: ReadonlyArray<
	readonly [TargetKind, ReadonlyArray<string>]
> = [
	["container", ["docker", "docker-compose"]],
	["iac", ["terraform", "github-actions", "kubernetes"]],
	["mobile", ["android", "ios", "flutter"]],
];

const kindsForTech = (tech: ReadonlySet<string>): TargetKind[] => [
	"codebase",
	...KINDS_BY_TECH.filter(([, techs]) => techs.some((t) => tech.has(t))).map(
		([kind]) => kind,
	),
];

/** Detects technologies from a file list. Exported for tests. */
export const detectTechnologies = (
	files: ReadonlyArray<string>,
): ReadonlyArray<string> => {
	const found = new Set<string>();
	for (const file of files) {
		for (const [re, tech] of TECH_MARKERS) {
			if (re.test(file)) found.add(tech);
		}
	}
	return [...found].sort();
};

/** Cheap check for Kubernetes manifests among YAML files. */
const hasKubernetesManifests = (ws: Workspace) =>
	Effect.gen(function* () {
		const yamls = (yield* ws.glob("**/*.{yaml,yml}")).slice(0, 300);
		for (const file of yamls) {
			const text = yield* ws
				.readText(file)
				.pipe(Effect.orElseSucceed(() => ""));
			if (/^apiVersion:\s*\S+/m.test(text) && /^kind:\s*\S+/m.test(text))
				return true;
		}
		return false;
	});

export interface ResolvedTarget {
	readonly info: TargetInfo;
	/** Directory to open as the workspace, if any. */
	readonly root: string | undefined;
}

/**
 * Turns user input into a target:
 * - `http(s)://…` → url (+ webapp when `browser` is set)
 * - `image:<ref>` → container image
 * - `cloud:<provider>` → a live cloud account (aws, azure, gcp, kubernetes)
 * - a directory → codebase, plus container/iac/mobile when detected
 * - a `.apk`/`.aab`/`.ipa` → mobile; a Dockerfile → container; `.tf`/`.yaml` → iac
 */
const CLOUD_PROVIDERS = new Set(["aws", "azure", "gcp", "kubernetes"]);

export const resolveTarget = (
	input: string,
	options: AuditOptions,
	openWorkspace: (root: string) => Workspace,
): Effect.Effect<ResolvedTarget, TargetError> => {
	if (/^https?:\/\//i.test(input)) return urlTarget(input, options);
	if (input.startsWith("image:")) return imageTarget(input);
	if (input.startsWith("cloud:")) return cloudTarget(input);
	return pathTarget(input, openWorkspace);
};

const urlTarget = (input: TargetInput, options: AuditOptions) =>
	Effect.gen(function* () {
		const url = yield* Effect.try({
			try: () => new URL(input).toString(),
			catch: () => new TargetError({ message: `Invalid URL: ${input}` }),
		});
		const kinds: TargetKind[] = options.browser ? ["url", "webapp"] : ["url"];
		return {
			root: undefined,
			info: { input, type: "url", kinds, url, technologies: [] },
		} satisfies ResolvedTarget;
	});

const imageTarget = (input: TargetInput) =>
	Effect.gen(function* () {
		const image = input.slice("image:".length);
		if (!image)
			return yield* new TargetError({ message: "Missing image reference" });
		return {
			root: undefined,
			info: {
				input,
				type: "image",
				kinds: ["container"],
				image,
				technologies: ["docker"],
			},
		} satisfies ResolvedTarget;
	});

const cloudTarget = (input: TargetInput) =>
	Effect.gen(function* () {
		const cloud = input.slice("cloud:".length).toLowerCase();
		if (!CLOUD_PROVIDERS.has(cloud))
			return yield* new TargetError({
				message: `Unknown cloud provider "${cloud}". Use cloud:aws, cloud:azure, cloud:gcp or cloud:kubernetes.`,
			});
		return {
			root: undefined,
			info: {
				input,
				type: "cloud",
				kinds: ["cloud"],
				cloud,
				technologies: [],
			},
		} satisfies ResolvedTarget;
	});

const pathTarget = (
	input: TargetInput,
	openWorkspace: (root: string) => Workspace,
) =>
	Effect.gen(function* () {
		const path = resolve(input);
		const stats = yield* Effect.tryPromise({
			try: () => stat(path),
			catch: () =>
				new TargetError({
					message: `Target not found: ${input}. Pass a directory, file, URL or image:<ref>.`,
				}),
		});
		if (stats.isDirectory())
			return yield* directoryTarget(input, path, openWorkspace(path));
		return fileTarget(input, path);
	});

const directoryTarget = (
	input: TargetInput,
	path: AbsolutePath,
	ws: Workspace,
) =>
	Effect.gen(function* () {
		const files = yield* ws.files.pipe(Effect.orElseSucceed(() => []));
		const tech = new Set(detectTechnologies(files));
		if (!tech.has("kubernetes")) {
			const k8s = yield* hasKubernetesManifests(ws).pipe(
				Effect.orElseSucceed(() => false),
			);
			if (k8s) tech.add("kubernetes");
		}
		return {
			root: path,
			info: {
				input,
				type: "directory",
				root: path,
				kinds: kindsForTech(tech),
				technologies: [...tech].sort(),
			},
		} satisfies ResolvedTarget;
	});

const IAC_EXTENSIONS = new Set([".tf", ".yaml", ".yml"]);

const isContainerFile = (name: FileName): boolean =>
	detectTechnologies([name]).includes("docker") ||
	/(docker-)?compose.*\.ya?ml$/.test(name);

const fileKinds = (name: FileName, ext: Extension): TargetKind[] => {
	if (MOBILE_ARTIFACTS.has(ext)) return ["mobile"];
	if (isContainerFile(name)) return ["container"];
	return IAC_EXTENSIONS.has(ext) ? ["iac"] : ["codebase"];
};

const fileTarget = (input: TargetInput, path: AbsolutePath): ResolvedTarget => {
	const name = basename(path);
	return {
		root: dirname(path),
		info: {
			input,
			type: "file",
			root: dirname(path),
			file: name,
			kinds: fileKinds(name, extname(path).toLowerCase()),
			technologies: detectTechnologies([name]),
		},
	};
};
