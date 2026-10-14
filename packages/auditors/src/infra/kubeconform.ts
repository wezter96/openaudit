import {
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
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

import { isRecord, truncate } from "../codebase/util";
import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { kubernetesManifests } from "./shared";

const ID = "iac.kubeconform";

/**
 * Community JSON schemas for popular CRDs (cert-manager, Argo, Istio, ...),
 * tried after the built-in Kubernetes schemas. Kubeconform's documented setup
 * for CRDs.
 */
export const CRDS_CATALOG =
	"https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json";

const DOCS = "https://github.com/yannh/kubeconform#readme";
const API_REFERENCE = "https://kubernetes.io/docs/reference/kubernetes-api/";

interface Rule {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly category: Category;
	readonly remediation: string;
}

const RULES = {
	unknownField: {
		id: "unknown-field",
		title: "Field not in the resource schema",
		severity: "medium",
		category: "reliability",
		remediation:
			"Fix the field name or indentation. Unknown fields are a typo or a misplaced key: kubectl's strict validation rejects them and other clients silently drop them, so the setting never takes effect.",
	},
	wrongType: {
		id: "wrong-type",
		title: "Field has the wrong type",
		severity: "high",
		category: "reliability",
		remediation:
			"Use the type the API expects (for example an unquoted integer for replicas or ports). The API server rejects the manifest as it is.",
	},
	missingField: {
		id: "missing-required-field",
		title: "Required field missing",
		severity: "high",
		category: "reliability",
		remediation:
			"Add the required field. The API server rejects the manifest as it is.",
	},
	invalidValue: {
		id: "invalid-value",
		title: "Value not allowed by the schema",
		severity: "high",
		category: "reliability",
		remediation:
			"Use a value the API accepts (allowed values, format, range or length). The API server rejects the manifest as it is.",
	},
	schemaViolation: {
		id: "schema-violation",
		title: "Resource does not match its schema",
		severity: "medium",
		category: "reliability",
		remediation:
			"Make the resource match the Kubernetes API schema for its kind and apiVersion.",
	},
	duplicateKey: {
		id: "duplicate-key",
		title: "Duplicate key in manifest",
		severity: "medium",
		category: "reliability",
		remediation:
			"Remove the duplicate key. YAML parsers disagree on which value wins, so the applied resource may not be the one you reviewed.",
	},
	invalidYaml: {
		id: "invalid-yaml",
		title: "Manifest is not valid YAML",
		severity: "high",
		category: "reliability",
		remediation: "Fix the YAML syntax error; the manifest cannot be applied.",
	},
	missingSchema: {
		id: "missing-schema",
		title: "Resource kind not validated (no schema)",
		severity: "info",
		category: "best-practices",
		remediation:
			"Resources of this kind were not schema-checked: neither the Kubernetes schemas nor the CRDs-catalog know it. Usually a custom resource; publish its CRD schema to validate it, or ignore this note.",
	},
	error: {
		id: "error",
		title: "Resource could not be validated",
		severity: "low",
		category: "reliability",
		remediation: "Check the manifest; kubeconform could not process it.",
	},
} satisfies Record<string, Rule>;

/** Maps one JSON-schema validation message to a rule. */
const ruleOfViolation = (msg: string): Rule => {
	if (msg.startsWith("additional propert")) return RULES.unknownField;
	if (msg.startsWith("missing propert")) return RULES.missingField;
	if (/^got \S+, want /.test(msg)) return RULES.wrongType;
	if (
		/^value must be|does not match pattern|is not valid '|^(minimum|maximum|exclusiveMinimum|exclusiveMaximum): got|^(length|minItems|maxItems|minProperties|maxProperties)/.test(
			msg,
		)
	)
		return RULES.invalidValue;
	return RULES.schemaViolation;
};

/** Finds the 1-based line of a resource (or a JSON-pointer path inside it). */
export type ResourceLocator = (
	file: string,
	resource: { kind?: string; name?: string },
	pointer?: string,
	/** A line number relative to the resource's YAML document. */
	docLine?: number,
) => number | undefined;

const nodeStart = (node: unknown): number | undefined =>
	(node as Node | undefined)?.range?.[0];

/**
 * Builds a locator over manifest texts. Documents are matched by kind and
 * metadata.name, as kubeconform reports them (duplicate keys allowed, last
 * one wins, like kubeconform's parser).
 */
export const kubeconformLocator = (
	texts: ReadonlyMap<string, string>,
): ResourceLocator => {
	const parsed = new Map<
		string,
		ReadonlyArray<{
			kind?: string;
			name?: string;
			/** Line of the `---` marker, or 0 for an unmarked first document. */
			base: number;
			lineOf: (path: ReadonlyArray<string>) => number | undefined;
		}>
	>();
	const docsOf = (file: string) => {
		const cached = parsed.get(file);
		if (cached) return cached;
		const text = texts.get(file);
		if (text === undefined) return [];
		const counter = new LineCounter();
		const docs = parseAllDocuments(text, {
			lineCounter: counter,
			uniqueKeys: false,
		});
		const entries = (Array.isArray(docs) ? docs : []).map((doc) => {
			let value: unknown;
			try {
				value = doc.toJS({ maxAliasCount: 100 });
			} catch {
				value = undefined;
			}
			const meta = isRecord(value) ? value.metadata : undefined;
			const start = doc.range[0];
			const base = text.startsWith("---", start)
				? counter.linePos(start).line
				: 0;
			const lineOf = (path: ReadonlyArray<string>) => {
				let node: unknown = doc.contents;
				let offset = nodeStart(node);
				for (const key of path) {
					if (isMap(node)) {
						const pair = node.items.find(
							(p) =>
								isPair(p) &&
								(isScalar(p.key) ? String(p.key.value) : String(p.key)) === key,
						);
						if (!pair) break;
						offset = nodeStart(pair.key) ?? offset;
						node = pair.value;
					} else if (isSeq(node) && /^\d+$/.test(key)) {
						const item = node.items[Number(key)];
						if (item === undefined) break;
						offset = nodeStart(item) ?? offset;
						node = item;
					} else break;
				}
				return offset === undefined ? undefined : counter.linePos(offset).line;
			};
			return {
				kind: isRecord(value) ? str(value.kind) : undefined,
				name: isRecord(meta) ? str(meta.name) : undefined,
				base,
				lineOf,
			};
		});
		parsed.set(file, entries);
		return entries;
	};

	return (file, resource, pointer, docLine) => {
		const docs = docsOf(file);
		const doc = resource.kind
			? docs.find((d) => d.kind === resource.kind && d.name === resource.name)
			: // Unparseable resources carry no kind; only a single-document file is unambiguous.
				docs.length === 1
				? docs[0]
				: undefined;
		if (!doc) return undefined;
		if (docLine !== undefined) return doc.base + docLine;
		const path = (pointer ?? "")
			.split("/")
			.filter(Boolean)
			.map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
		return doc.lineOf(path);
	};
};

const DOWNLOAD_FAILED_RE = /^failed downloading schema/;
const MISSING_SCHEMA_RE = /^could not find schema for/;

/** Messages of resources whose schema could not be downloaded (offline, proxy, outage). */
export const kubeconformDownloadFailures = (json: unknown): string[] =>
	isRecord(json)
		? arr(json.resources).flatMap((r) =>
				isRecord(r) &&
				r.status === "statusError" &&
				DOWNLOAD_FAILED_RE.test(str(r.msg) ?? "")
					? [str(r.msg) ?? ""]
					: [],
			)
		: [];

/** Parses `kubeconform -output json -summary` output. */
export const parseKubeconformReport = (
	json: unknown,
	root: string,
	locate: ResourceLocator = () => undefined,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	// Kinds without a schema are reported once per kind, not once per resource.
	const missing = new Map<
		string,
		{ files: string[]; first: FindingInput["location"]; count: number }
	>();

	const resources = arr(json.resources)
		.filter(isRecord)
		.map((r) => ({
			file: relPath(root, str(r.filename)) ?? "",
			kind: str(r.kind) || undefined,
			name: str(r.name) || undefined,
			version: str(r.version) || undefined,
			status: str(r.status),
			msg: str(r.msg) ?? "",
			errors: arr(r.validationErrors).filter(isRecord),
		}))
		// kubeconform validates concurrently, so its output order is not stable.
		.sort(
			(a, b) =>
				a.file.localeCompare(b.file) ||
				(a.kind ?? "").localeCompare(b.kind ?? "") ||
				(a.name ?? "").localeCompare(b.name ?? ""),
		);

	for (const r of resources) {
		const label = [r.kind, r.name].filter(Boolean).join("/");
		const push = (
			rule: Rule,
			message: string,
			line: number | undefined,
			evidence: string | undefined,
		) =>
			findings.push({
				ruleId: `${ID}/${rule.id}`,
				title: label ? `${rule.title}: ${label}` : rule.title,
				severity: rule.severity,
				category: rule.category,
				message: truncate(message, 300),
				remediation: rule.remediation,
				location: { file: r.file, line },
				// Kind, name and JSON path only: never a field value.
				evidence: evidence ? truncate(evidence) : undefined,
				references: [DOCS, API_REFERENCE],
				tags: ["kubeconform", "kubernetes", rule.id],
			});

		if (r.status === "statusInvalid") {
			const errors = (
				r.errors.length > 0 ? r.errors : [{ path: "", msg: r.msg }]
			).sort((a, b) => (str(a.path) ?? "").localeCompare(str(b.path) ?? ""));
			for (const e of errors) {
				const pointer = str(e.path) ?? "";
				const msg = str(e.msg) ?? r.msg;
				// Point at the unknown key itself rather than its parent.
				const extra = /^additional propert\w+ '([^'/~]+)'/.exec(msg)?.[1];
				const path = extra ? `${pointer}/${extra}` : pointer;
				push(
					ruleOfViolation(msg),
					`${label || "Resource"}${pointer ? ` at ${pointer}` : ""}: ${msg}`,
					locate(r.file, r, path),
					`${label} ${path}`.trim(),
				);
			}
		} else if (r.status === "statusError") {
			if (DOWNLOAD_FAILED_RE.test(r.msg)) continue;
			if (MISSING_SCHEMA_RE.test(r.msg)) {
				const key = `${r.kind}@${r.version}`;
				const entry = missing.get(key);
				if (entry) {
					entry.count++;
					if (!entry.files.includes(r.file)) entry.files.push(r.file);
				} else
					missing.set(key, {
						files: [r.file],
						first: { file: r.file, line: locate(r.file, r) },
						count: 1,
					});
				continue;
			}
			const yamlLine = /line (\d+):/.exec(r.msg)?.[1];
			const duplicate = /already set in map|duplicate key/i.test(r.msg);
			const unparseable = /error (unmarshalling|converting) /.test(r.msg);
			push(
				duplicate
					? RULES.duplicateKey
					: unparseable
						? RULES.invalidYaml
						: RULES.error,
				`${label || "Document"}: ${r.msg.replace(/\s+/g, " ")}`,
				locate(
					r.file,
					r,
					undefined,
					yamlLine === undefined ? undefined : Number(yamlLine),
				),
				label || undefined,
			);
		}
	}

	for (const [key, entry] of missing) {
		const [kind, version] = key.split("@");
		const rule = RULES.missingSchema;
		const files =
			entry.files.length > 3
				? `${entry.files.slice(0, 3).join(", ")} and ${entry.files.length - 3} more`
				: entry.files.join(", ");
		findings.push({
			ruleId: `${ID}/${rule.id}`,
			title: `${rule.title}: ${kind}`,
			severity: rule.severity,
			category: rule.category,
			message: `${entry.count} ${kind} resource${entry.count === 1 ? "" : "s"} (${version}) not validated: no JSON schema found. Files: ${files}.`,
			remediation: rule.remediation,
			location: entry.first,
			evidence: `${kind} ${version}`,
			references: ["https://github.com/datreeio/CRDs-catalog", DOCS],
			tags: ["kubeconform", "kubernetes", rule.id],
		});
	}
	return findings;
};

const VERSION_RE = /^(master|\d+\.\d+\.\d+)$/;

/** Wraps kubeconform, which validates Kubernetes manifests against the API schemas. */
export const kubeconform = defineAuditor({
	id: ID,
	title: "kubeconform",
	description:
		'Validates plain Kubernetes manifests against the official API schemas with kubeconform (-strict: unknown fields and duplicate keys are errors): wrong types, missing required fields, typos that kubectl rejects or silently drops. Custom resources are checked against the datree CRDs-catalog when it has a schema; kinds without one are reported once as info. Schemas are downloaded from GitHub (raw.githubusercontent.com), so the API groups and kinds in use, custom ones included, appear in those request URLs; manifest contents are never sent. Helm templates are skipped. settings["iac.kubeconform"].kubernetesVersion (e.g. "1.31.0", default "master") picks the API version.',
	categories: ["reliability", "best-practices"],
	targets: ["iac"],
	engine: "external",
	tool: "kubeconform",
	network: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, manifests } = yield* kubernetesManifests(ctx);
			if (manifests.size === 0)
				return yield* skip("No Kubernetes manifests found");
			const bin = yield* requireTool(
				ctx,
				"kubeconform",
				"Install: brew install kubeconform or go install github.com/yannh/kubeconform/cmd/kubeconform@latest (https://github.com/yannh/kubeconform#installation).",
			);
			const version = ctx.options.settings?.[ID]?.kubernetesVersion;
			if (
				version !== undefined &&
				(typeof version !== "string" || !VERSION_RE.test(version))
			)
				return yield* new AuditorError({
					message: `settings["${ID}"].kubernetesVersion must be "master" or a full version such as "1.31.0"`,
				});
			const res = yield* runTool(
				ctx,
				[
					bin,
					"-output",
					"json",
					"-summary",
					"-strict",
					...(version ? ["-kubernetes-version", version] : []),
					"-schema-location",
					"default",
					"-schema-location",
					CRDS_CATALOG,
					// "./" keeps hostile file names from being read as flags.
					...[...manifests.keys()].map((f) => `./${f}`),
				],
				ws.root,
				// 1 = some resources are invalid or errored; the report is still on stdout.
				[0, 1],
			);
			if (!res.stdout.trim())
				return yield* new AuditorError({
					message: `kubeconform produced no output: ${truncate(res.stderr, 300)}`,
				});
			const json = yield* parseJson(res.stdout, "kubeconform");
			const failures = kubeconformDownloadFailures(json);
			const summary =
				isRecord(json) && isRecord(json.summary) ? json.summary : {};
			if (
				failures.length > 0 &&
				(num(summary.valid) ?? 0) + (num(summary.invalid) ?? 0) === 0
			)
				return yield* new AuditorError({
					message: `kubeconform could not download any schema (network access to raw.githubusercontent.com is needed): ${truncate(failures[0] ?? "", 200)}`,
				});
			if (failures.length > 0)
				yield* ctx.log(
					`kubeconform: ${failures.length} resource(s) not validated, schema download failed`,
				);
			return parseKubeconformReport(
				json,
				ws.root,
				kubeconformLocator(manifests),
			);
		}),
});
