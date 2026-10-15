import {
	type AuditContext,
	type AuditorError,
	requireWorkspace,
	type SkipAudit,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import {
	type Document,
	isMap,
	isPair,
	isScalar,
	isSeq,
	LineCounter,
	type Node,
	parseAllDocuments,
	type YAMLMap,
	type YAMLSeq,
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

/** Readable YAML with top-level `apiVersion` and `kind`, and no Helm templating. */
const isPlainManifest = (text: string | undefined): text is string => {
	if (text === undefined || text.includes("{{")) return false;
	return /^apiVersion:\s*\S/m.test(text) && /^kind:\s*\S/m.test(text);
};

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
			if (isPlainManifest(text)) manifests.set(file, text);
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

/** A YAML node together with the source offset of the closest located ancestor. */
interface Cursor {
	readonly node: unknown;
	readonly offset: number | undefined;
}

const keyText = (key: unknown): string =>
	isScalar(key) ? String(key.value) : String(key);

const mapChild = (
	map: YAMLMap,
	key: string | number,
	cursor: Cursor,
): Cursor | undefined => {
	const pair = map.items.find(
		(p) => isPair(p) && keyText(p.key) === String(key),
	);
	if (!pair) return undefined;
	return { node: pair.value, offset: nodeStart(pair.key) ?? cursor.offset };
};

const seqChild = (
	seq: YAMLSeq,
	index: number,
	cursor: Cursor,
): Cursor | undefined => {
	const item = seq.items[index];
	if (item === undefined) return undefined;
	return { node: item, offset: nodeStart(item) ?? cursor.offset };
};

/** The child of `cursor` at `key`, or `undefined` when there is none. */
const childAt = (cursor: Cursor, key: string | number): Cursor | undefined => {
	const { node } = cursor;
	if (isMap(node)) return mapChild(node, key, cursor);
	if (isSeq(node) && typeof key === "number")
		return seqChild(node, key, cursor);
	return undefined;
};

/** Offset of the key (or item) at `path`, falling back to the closest ancestor. */
const offsetAt = (root: unknown, path: YamlPath): number | undefined => {
	let cursor: Cursor = { node: root, offset: nodeStart(root) };
	for (const key of path) {
		const next = childAt(cursor, key);
		if (!next) break;
		cursor = next;
	}
	return cursor.offset;
};

/** Plain JS value of a document, or `undefined` when it has errors or cannot be converted. */
const documentValue = (
	doc: Document.Parsed,
): { readonly value: unknown } | undefined => {
	if (doc.errors.length > 0) return undefined;
	try {
		return { value: doc.toJS({ maxAliasCount: 1000 }) };
	} catch {
		return undefined;
	}
};

const yamlDoc = (
	doc: Document.Parsed,
	counter: LineCounter,
): YamlDoc | undefined => {
	const converted = documentValue(doc);
	if (!converted) return undefined;
	const lineOf = (path: YamlPath): number | undefined => {
		const offset = offsetAt(doc.contents, path);
		return offset === undefined ? undefined : counter.linePos(offset).line;
	};
	return { value: converted.value, lineOf };
};

/** Parses (multi-document) YAML and keeps enough source info to report lines. */
export const parseYaml = (text: string): ParsedYaml => {
	const counter = new LineCounter();
	const parsed = parseAllDocuments(text, { lineCounter: counter }).map((doc) =>
		yamlDoc(doc, counter),
	);
	const docs = parsed.filter((doc): doc is YamlDoc => doc !== undefined);
	return { docs, hasErrors: docs.length < parsed.length };
};

/** Narrows an unknown YAML value to a plain object. */
export const asRecord = (v: unknown): Record<string, unknown> | undefined =>
	isObject(v) && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;

const isObject = (v: unknown): v is object =>
	v !== null && typeof v === "object";

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
