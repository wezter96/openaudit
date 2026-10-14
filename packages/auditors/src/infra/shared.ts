import {
	type AuditContext,
	type AuditorError,
	requireWorkspace,
	type SkipAudit,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import {
	isMap,
	isPair,
	isScalar,
	isSeq,
	LineCounter,
	type Node,
	parseAllDocuments,
} from "yaml";

/**
 * Workspace files matching `pattern`. For single-file targets only the target
 * file is considered (and only when it matches).
 */
export const targetFiles = (
	ctx: AuditContext,
	pattern: RegExp,
): Effect.Effect<
	{ readonly ws: Workspace; readonly files: ReadonlyArray<string> },
	AuditorError | SkipAudit
> =>
	Effect.gen(function* () {
		const ws = yield* requireWorkspace(ctx);
		if (ctx.target.type === "file") {
			const file = ctx.target.file;
			return { ws, files: file && pattern.test(file) ? [file] : [] };
		}
		const all = yield* ws.files;
		return { ws, files: all.filter((f) => pattern.test(f)) };
	});

/** GitHub Actions workflow files. */
export const WORKFLOW_RE = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;

/**
 * GitHub Actions files matching `pattern` (workflows by default). For
 * single-file targets any YAML file is considered.
 */
export const workflowFiles = (ctx: AuditContext, pattern = WORKFLOW_RE) =>
	targetFiles(ctx, ctx.target.type === "file" ? /\.ya?ml$/ : pattern);

/** Reads a text file, yielding `undefined` when it cannot be read. */
export const readOptional = (ws: Workspace, file: string) =>
	ws.readText(file).pipe(Effect.orElseSucceed(() => undefined));

/** YAML that is clearly not a Kubernetes manifest. */
const NOT_K8S_RE =
	/(^|\/)(\.github\/|\.gitlab-ci|(docker-)?compose[^/]*\.ya?ml$|pnpm-lock|\.pre-commit|mkdocs|openapi|swagger)/;

/**
 * Plain Kubernetes manifests (YAML with top-level `apiVersion` and `kind`),
 * keyed by path with their text. Helm templates (`{{`) are not valid YAML and
 * are left out.
 */
export const kubernetesManifests = (ctx: AuditContext) =>
	Effect.gen(function* () {
		const { ws, files } = yield* targetFiles(ctx, /\.ya?ml$/);
		const manifests = new Map<string, string>();
		for (const file of files) {
			if (ctx.target.type !== "file" && NOT_K8S_RE.test(file)) continue;
			const text = yield* readOptional(ws, file);
			if (
				text === undefined ||
				!/^apiVersion:\s*\S/m.test(text) ||
				!/^kind:\s*\S/m.test(text) ||
				text.includes("{{")
			)
				continue;
			manifests.set(file, text);
		}
		return { ws, manifests };
	});

export type YamlPath = ReadonlyArray<string | number>;

export interface YamlDoc {
	/** Plain JS value of the document. */
	readonly value: unknown;
	/** 1-based line of the key (or item) at `path`; falls back to the closest ancestor. */
	readonly lineOf: (path: YamlPath) => number | undefined;
}

export interface ParsedYaml {
	readonly docs: ReadonlyArray<YamlDoc>;
	/** True when any document had a syntax error. */
	readonly hasErrors: boolean;
}

const nodeStart = (node: unknown): number | undefined =>
	(node as Node | undefined)?.range?.[0];

/** Parses (multi-document) YAML and keeps enough source info to report lines. */
export const parseYaml = (text: string): ParsedYaml => {
	const counter = new LineCounter();
	let hasErrors = false;
	const docs: YamlDoc[] = [];
	for (const doc of parseAllDocuments(text, { lineCounter: counter })) {
		if (doc.errors.length > 0) {
			hasErrors = true;
			continue;
		}
		let value: unknown;
		try {
			value = doc.toJS({ maxAliasCount: 1000 });
		} catch {
			hasErrors = true;
			continue;
		}
		const lineOf = (path: YamlPath): number | undefined => {
			let node: unknown = doc.contents;
			let offset = nodeStart(node);
			for (const key of path) {
				if (isMap(node)) {
					const pair = node.items.find(
						(p) =>
							isPair(p) &&
							(isScalar(p.key) ? String(p.key.value) : String(p.key)) ===
								String(key),
					);
					if (!pair) break;
					offset = nodeStart(pair.key) ?? offset;
					node = pair.value;
				} else if (isSeq(node) && typeof key === "number") {
					const item = node.items[key];
					if (item === undefined) break;
					offset = nodeStart(item) ?? offset;
					node = item;
				} else break;
			}
			return offset === undefined ? undefined : counter.linePos(offset).line;
		};
		docs.push({ value, lineOf });
	}
	return { docs, hasErrors };
};

/** Narrows an unknown YAML value to a plain object. */
export const asRecord = (v: unknown): Record<string, unknown> | undefined =>
	v !== null && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: undefined;

/** Narrows an unknown YAML value to an array (empty otherwise). */
export const asArray = (v: unknown): ReadonlyArray<unknown> =>
	Array.isArray(v) ? v : [];

/** Variable names that usually hold credentials. */
export const SECRET_NAME_RE =
	/pass(word|wd)?$|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credentials?$/i;

/** True when a value is empty, a variable reference or an obvious placeholder. */
export const isPlaceholderValue = (value: string): boolean => {
	const v = value.trim().replace(/^["']|["']$/g, "");
	return (
		v === "" ||
		/^\$\{?[\w:-]+\}?$/.test(v) ||
		/^(changeme|change_me|xxx+|\*+|<.*>|your[_-].*|example|placeholder|dummy|none|null|false|true)$/i.test(
			v,
		)
	);
};

export interface ImageRef {
	readonly name: string;
	readonly tag: string | undefined;
	readonly digest: string | undefined;
}

/** Splits `registry:5000/repo/name:tag@sha256:…` into its parts. */
export const parseImageRef = (ref: string): ImageRef => {
	const at = ref.indexOf("@");
	const digest = at === -1 ? undefined : ref.slice(at + 1);
	const rest = at === -1 ? ref : ref.slice(0, at);
	const slash = rest.lastIndexOf("/");
	const colon = rest.lastIndexOf(":");
	return colon > slash
		? { name: rest.slice(0, colon), tag: rest.slice(colon + 1), digest }
		: { name: rest, tag: undefined, digest };
};

/** No tag (implicitly `latest`) or an explicit `:latest`, and no digest. */
export const isMutableTag = (ref: ImageRef): boolean =>
	ref.digest === undefined && (ref.tag === undefined || ref.tag === "latest");
