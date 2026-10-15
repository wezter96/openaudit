import {
	type AuditContext,
	type AuditorError,
	requireWorkspace,
	type SkipAudit,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import { type UnzipFileInfo, unzipSync } from "fflate";

export type ArtifactType = "apk" | "aab" | "ipa";

/** Zip-bomb guards for a single `extract` call. */
export interface ExtractLimits {
	/** Max declared uncompressed size of one entry. */
	readonly maxEntryBytes: number;
	/** Max declared uncompressed bytes across all extracted entries. */
	readonly maxTotalBytes: number;
}

export const DEFAULT_EXTRACT_LIMITS: ExtractLimits = {
	maxEntryBytes: 64 * 1024 * 1024,
	maxTotalBytes: 256 * 1024 * 1024,
};

/** A built mobile artifact (zip) whose entries are extracted on demand. */
export interface MobileArtifact {
	readonly kind: "artifact";
	readonly type: ArtifactType;
	/** File name of the artifact inside the workspace. */
	readonly file: string;
	/** Names of all entries in the archive. */
	readonly names: ReadonlyArray<string>;
	/**
	 * Extracts only entries accepted by `filter`, within `limits`. Entries over
	 * budget, with an implausible compression ratio or an unknown compression
	 * method are skipped.
	 */
	readonly extract: (
		filter: (name: string, info: UnzipFileInfo) => boolean,
		limits?: ExtractLimits,
	) => Record<string, Uint8Array>;
}

/** A mobile source tree (or a single source file such as Info.plist). */
export interface MobileSource {
	readonly kind: "source";
	readonly ws: Workspace;
	/** Candidate files (just the target file for single-file targets). */
	readonly files: ReadonlyArray<string>;
}

export type MobileTarget = MobileArtifact | MobileSource;

const ARTIFACT_RE = /\.(apk|aab|ipa)$/i;

const listEntries = (bytes: Uint8Array): string[] | undefined => {
	const names: string[] = [];
	try {
		unzipSync(bytes, {
			filter: (info) => {
				names.push(info.name);
				return false;
			},
		});
		return names;
	} catch {
		return undefined;
	}
};

/**
 * True when the compressed size is plausible for the declared size and the
 * compression method is one fflate inflates (stored or deflate).
 */
const plausibleCompression = (info: UnzipFileInfo): boolean => {
	const declared = info.originalSize;
	if (info.compression === 0) return info.size === declared;
	// Deflate never grows data by more than a few bytes per 16 KB block.
	if (info.compression === 8)
		return info.size <= declared + declared / 100 + 1024;
	return false;
};

/**
 * Wraps an entry filter with zip-bomb checks made on the declared sizes before
 * anything is inflated. fflate inflates into a buffer of exactly the declared
 * size, so the declared size bounds memory; the compressed size bounds CPU.
 */
export const budgetedFilter = (
	filter: (name: string, info: UnzipFileInfo) => boolean,
	limits: ExtractLimits = DEFAULT_EXTRACT_LIMITS,
): ((info: UnzipFileInfo) => boolean) => {
	let total = 0;
	return (info) => {
		if (!filter(info.name, info)) return false;
		const declared = info.originalSize;
		if (declared > limits.maxEntryBytes) return false;
		if (total + declared > limits.maxTotalBytes) return false;
		if (!plausibleCompression(info)) return false;
		total += declared;
		return true;
	};
};

/** Opens the target either as a built artifact or as a source tree. */
export const loadMobileTarget = (
	ctx: AuditContext,
): Effect.Effect<MobileTarget, AuditorError | SkipAudit> =>
	Effect.gen(function* () {
		const ws = yield* requireWorkspace(ctx);
		const file = ctx.target.type === "file" ? ctx.target.file : undefined;
		if (!file) return { kind: "source", ws, files: yield* ws.files } as const;
		const match = ARTIFACT_RE.exec(file);
		if (!match) return { kind: "source", ws, files: [file] } as const;
		const bytes = yield* ws.readBytes(file);
		const names = listEntries(bytes);
		if (!names) return yield* skip(`${file} is not a readable zip archive`);
		return {
			kind: "artifact",
			type: (match[1] ?? "apk").toLowerCase() as ArtifactType,
			file,
			names,
			extract: (filter, limits) => {
				try {
					return unzipSync(bytes, { filter: budgetedFilter(filter, limits) });
				} catch {
					return {};
				}
			},
		} as const;
	});

/** Decodes bytes as UTF-8 (lossy). */
export const utf8 = (bytes: Uint8Array): string =>
	new TextDecoder("utf-8", { fatal: false }).decode(bytes);
