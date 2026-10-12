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

/** A built mobile artifact (zip) whose entries are extracted on demand. */
export interface MobileArtifact {
	readonly kind: "artifact";
	readonly type: ArtifactType;
	/** File name of the artifact inside the workspace. */
	readonly file: string;
	/** Names of all entries in the archive. */
	readonly names: ReadonlyArray<string>;
	/** Extracts only entries accepted by `filter` (keeps memory bounded). */
	readonly extract: (
		filter: (name: string, info: UnzipFileInfo) => boolean,
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
			extract: (filter) => {
				try {
					return unzipSync(bytes, {
						filter: (info) => filter(info.name, info),
					});
				} catch {
					return {};
				}
			},
		} as const;
	});

/** Decodes bytes as UTF-8 (lossy). */
export const utf8 = (bytes: Uint8Array): string =>
	new TextDecoder("utf-8", { fatal: false }).decode(bytes);
