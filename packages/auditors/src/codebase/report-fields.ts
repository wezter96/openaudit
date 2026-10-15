import { arr, str } from "../tool";
import { isRecord } from "./util";

/**
 * Readers for fields of external tools' JSON reports. A missing or mistyped
 * field reads as empty, so parsers need no type checks of their own.
 */

/** The object in `v`, or an empty one. */
export const recordOf = (v: unknown): Record<string, unknown> =>
	isRecord(v) ? v : {};

/** The string entries of an array field. */
export const stringsOf = (v: unknown): string[] =>
	arr(v).filter((s): s is string => typeof s === "string");

/** A field that holds either one string or an array of strings. */
export const oneOrMany = (v: unknown): string[] =>
	stringsOf(v).concat(str(v) ?? []);

/** A non-empty string field as a one-item list, for spreading into lists. */
export const listOf = (v: unknown): string[] => {
	const s = str(v);
	return s ? [s] : [];
};
