import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, str } from "../tool";
import { isManifest } from "./dependencies";
import {
	compareVersions,
	type Declaration,
	findDeclarations,
	isEolSource,
} from "./eol-sources";
import { isFixturePath, isRecord, readTextFiles } from "./util";

/*
 * End-of-life runtimes and frameworks. Version files, manifests and lockfiles
 * name a runtime or framework release; endoflife.date says whether its cycle
 * still gets security fixes. One GET per product, per run.
 */

export const EOL_ID = "code.eol";
export const EOL_API = "https://endoflife.date/api/v1/products";
/** A cycle whose end of life is this close is reported as ending soon. */
const SOON_DAYS = 90;
const DAY = 86_400_000;

export { findDeclarations, lowestVersion } from "./eol-sources";

/* -------------------------------------------------------------------------- */
/*                               endoflife.date                               */
/* -------------------------------------------------------------------------- */

export interface Release {
	/** The cycle, e.g. `3.8` or `18`. */
	readonly name: string;
	readonly isEol: boolean;
	/** ISO date the cycle stops getting security fixes. */
	readonly eolFrom?: string;
}

export interface Product {
	readonly label: string;
	readonly link?: string;
	readonly releases: ReadonlyArray<Release>;
}

const releaseOf = (r: unknown): Release[] => {
	const name = isRecord(r) ? str(r.name) : undefined;
	if (!isRecord(r) || !name) return [];
	return [{ name, isEol: r.isEol === true, eolFrom: str(r.eolFrom) }];
};

/** Parses an endoflife.date v1 `products/<id>` response. */
export const parseProduct = (json: unknown): Product | undefined => {
	const result = isRecord(json) ? json.result : undefined;
	if (!isRecord(result)) return undefined;
	const links = isRecord(result.links) ? result.links : {};
	return {
		label: str(result.label) ?? str(result.name) ?? "",
		link: str(links.html),
		releases: arr(result.releases).flatMap(releaseOf),
	};
};

type Lookup = { readonly product: Product } | { readonly error: string };

const fetchProduct = (
	http: AuditContext["http"],
	id: string,
): Effect.Effect<Lookup> =>
	http(`${EOL_API}/${id}`, { timeoutMs: 20_000 }).pipe(
		Effect.flatMap((res) =>
			res.status === 200
				? Effect.try({
						try: () => parseProduct(JSON.parse(res.body)),
						catch: () => new AuditorError({ message: "invalid JSON" }),
					})
				: Effect.fail(new AuditorError({ message: `HTTP ${res.status}` })),
		),
		Effect.map(
			(product): Lookup =>
				product ? { product } : { error: `${id}: unexpected response` },
		),
		Effect.catch((e) => Effect.succeed({ error: `${id}: ${e.message}` })),
	);

/* -------------------------------------------------------------------------- */
/*                                 Assessment                                 */
/* -------------------------------------------------------------------------- */

/** The release cycle a version belongs to: `3.8.10` is in `3.8`, `18.17` in `18`. */
export const cycleOf = (
	product: Product,
	version: string,
): Release | undefined => {
	const parts = version.split(".");
	for (let n = parts.length; n > 0; n--) {
		const name = parts.slice(0, n).join(".");
		const hit = product.releases.find((r) => r.name === name);
		if (hit) return hit;
	}
	return undefined;
};

const eolTime = (r: Release) =>
	r.eolFrom ? Date.parse(r.eolFrom) : Number.NaN;

const isPastEol = (r: Release, now: number) => {
	const at = eolTime(r);
	return Number.isFinite(at) ? at <= now : r.isEol;
};

/** The oldest cycle that still gets security fixes. */
export const oldestSupported = (
	product: Product,
	now: number,
): string | undefined =>
	product.releases
		.filter((r) => !isPastEol(r, now) && /^\d+(\.\d+)*$/.test(r.name))
		.map((r) => r.name)
		.sort(compareVersions)[0];

/** A range only allows an old release, so it ranks below a pin of one. */
const severityOf = (d: Declaration): Severity =>
	d.kind === "runtime" && !d.range ? "high" : "medium";

const declared = (d: Declaration, label: string) =>
	d.range
		? `\`${d.file}\` allows ${label} \`${d.raw}\` (lowest: ${d.version})`
		: `\`${d.file}\` declares ${label} \`${d.raw}\``;

const remediationFor = (d: Declaration, product: Product, now: number) => {
	const target = oldestSupported(product, now);
	return `Upgrade to a supported ${product.label} release${target ? ` (${target} or newer)` : ""} and update \`${d.file}\`${d.range ? ", raising the lowest version the range allows" : ""}.`;
};

interface Status {
	readonly cycle: Release;
	readonly past: boolean;
	readonly daysLeft: number;
}

/** Where the declared cycle stands, or undefined while it's well supported. */
const statusOf = (
	d: Declaration,
	product: Product,
	now: number,
): Status | undefined => {
	const cycle = cycleOf(product, d.version);
	if (!cycle) return undefined;
	const past = isPastEol(cycle, now);
	const daysLeft = Math.ceil((eolTime(cycle) - now) / DAY);
	return past || daysLeft <= SOON_DAYS ? { cycle, past, daysLeft } : undefined;
};

const titleOf = (label: string, { cycle, past }: Status) =>
	past
		? `${label} ${cycle.name} is end-of-life`
		: `${label} ${cycle.name} reaches end-of-life soon`;

const messageOf = (d: Declaration, label: string, s: Status) => {
	const on = s.cycle.eolFrom ? ` on ${s.cycle.eolFrom}` : "";
	return s.past
		? `${declared(d, label)}. The ${s.cycle.name} release line stopped getting security fixes${on}.`
		: `${declared(d, label)}. The ${s.cycle.name} release line stops getting security fixes${on}, in ${s.daysLeft} days.`;
};

/** The finding for one declaration, or none while its cycle is supported. */
export const assessDeclaration = (
	d: Declaration,
	product: Product,
	now: number,
): FindingInput[] => {
	const status = statusOf(d, product, now);
	if (!status) return [];
	return [
		{
			ruleId: status.past ? `${EOL_ID}/${d.kind}-eol` : `${EOL_ID}/eol-soon`,
			title: titleOf(product.label, status),
			severity: status.past ? severityOf(d) : "low",
			category: "supply-chain",
			message: messageOf(d, product.label, status),
			remediation: remediationFor(d, product, now),
			location: { file: d.file, line: d.line },
			evidence: d.raw,
			references: [product.link ?? "https://endoflife.date/"],
			confidence: d.confidence,
			tags: ["cwe-1104"],
		},
	];
};

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

/** One lookup per product the declarations name, at most four at once. */
const lookupAll = (
	http: AuditContext["http"],
	declarations: ReadonlyArray<Declaration>,
) =>
	Effect.map(
		Effect.forEach(
			[...new Set(declarations.map((d) => d.product))].sort(),
			(id) => Effect.map(fetchProduct(http, id), (l) => [id, l] as const),
			{ concurrency: 4 },
		),
		(lookups) => {
			const products = new Map<string, Product>();
			const errors: string[] = [];
			for (const [id, l] of lookups)
				if ("product" in l) products.set(id, l.product);
				else errors.push(l.error);
			return { products, errors };
		},
	);

const isEolFile = (path: string) =>
	!isFixturePath(path) && (isEolSource(path) || isManifest(path));

export const eol = defineAuditor({
	id: EOL_ID,
	title: "End-of-life runtimes and frameworks",
	description:
		"Reads the runtime versions a repository declares (Node.js, Python, Go, Ruby, Java, PHP and .NET, from version files such as .nvmrc and .tool-versions, package.json, pyproject.toml, go.mod, Gemfile, pom.xml, composer.json, global.json and project files) and the framework versions its lockfiles pin (Angular, Django, Laravel, Next.js, Rails, Spring Boot, Vue), and flags those whose release line is past end-of-life or ends within 90 days, per endoflife.date. One request per product; ranges are judged by their lowest allowed version.",
	categories: ["supply-chain"],
	targets: ["codebase"],
	engine: "builtin",
	network: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, isEolFile, {
				maxBytes: 20 * 1024 * 1024,
				allowMinified: true,
			});
			const declarations = findDeclarations(files);
			if (declarations.length === 0)
				return yield* skip("No runtime or framework versions declared");
			const { products, errors } = yield* lookupAll(ctx.http, declarations);
			if (products.size === 0)
				return yield* skip(
					`endoflife.date could not be reached (${errors.slice(0, 3).join("; ")})`,
				);
			if (errors.length > 0)
				yield* ctx.log(`${EOL_ID}: lookups failed: ${errors.join("; ")}`);
			const now = Date.now();
			return declarations.flatMap((d) => {
				const product = products.get(d.product);
				return product ? assessDeclaration(d, product, now) : [];
			});
		}),
});
