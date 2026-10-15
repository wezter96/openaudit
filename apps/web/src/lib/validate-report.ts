import { Report } from "@openaudit/core/model";
import { Result, Schema } from "effect";

/*
 * Loaded lazily by the report viewer so Effect Schema only ships to visitors
 * who open a report. Imports model.ts directly: the rest of @openaudit/core
 * uses Bun APIs and must never reach the browser bundle.
 */

const decode = Schema.decodeUnknownResult(Report, { errors: "all" });

export type ValidationResult =
	| { readonly ok: true; readonly report: Report }
	| { readonly ok: false; readonly error: string };

/** A JSON object that declares a schemaVersion other than "1". */
const hasOtherVersion = (json: unknown): json is { schemaVersion: unknown } =>
	typeof json === "object" &&
	json !== null &&
	"schemaVersion" in json &&
	json.schemaVersion !== "1";

export const validateReport = (text: string): ValidationResult => {
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch (e) {
		return {
			ok: false,
			error: `This is not valid JSON: ${e instanceof Error ? e.message : String(e)}`,
		};
	}
	if (hasOtherVersion(json))
		return {
			ok: false,
			error: `Unsupported schemaVersion ${JSON.stringify(json.schemaVersion)}. This viewer reads version "1"; update the site or re-export the report.`,
		};
	const result = decode(json);
	return Result.isSuccess(result)
		? { ok: true, report: result.success }
		: {
				ok: false,
				error: `This JSON is not an openaudit report:\n${result.failure.message}`,
			};
};
