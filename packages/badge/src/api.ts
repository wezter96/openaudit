/**
 * The verified-badge JSON API, shared by the openaudit.se Worker (server) and
 * the badge scanner (client). Definitions only: no server code lives here.
 */

import type { Redacted } from "effect";
import { Context, Schema } from "effect";
import {
	HttpApi,
	HttpApiEndpoint,
	HttpApiGroup,
	HttpApiMiddleware,
	HttpApiSchema,
	HttpApiSecurity,
	OpenApi,
} from "effect/http-api";

/** Error and report text is cut to this many characters. */
export const MAX_ERROR_LENGTH = 500;
/** The scanner's report upload is refused above this many bytes. */
export const MAX_REPORT_BYTES = 25 * 1024 * 1024;

export const ProjectId = Schema.String.check(
	Schema.isPattern(/^[a-z0-9][a-z0-9-]{0,159}$/),
);
export type ProjectId = typeof ProjectId.Type;

export const ScanId = Schema.String.check(
	Schema.isPattern(
		/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
	),
);
export type ScanId = typeof ScanId.Type;

/** `owner/name` on GitHub. */
export type RepoSlug = string;
/** A normalised `https:` origin plus path. */
export type SiteUrl = string;
/** The public verification code a project puts in its repo and site. */
export type VerificationCode = string;

export const ProjectStatus = Schema.Literals(["pending", "active"]);
export type ProjectStatus = typeof ProjectStatus.Type;

export const ScanStatus = Schema.Literals(["ok", "failed"]);
export type ScanStatus = typeof ScanStatus.Type;

export const Grade = Schema.Literals(["A", "B", "C", "D", "F"]);
export type Grade = typeof Grade.Type;

const Count = Schema.Int;

/** The headline numbers of one openaudit report. */
export const TargetSummary = Schema.Struct({
	score: Schema.Number,
	grade: Grade,
	severities: Schema.Struct({
		critical: Count,
		high: Count,
		medium: Count,
		low: Count,
		info: Count,
	}),
	categories: Schema.Array(
		Schema.Struct({
			category: Schema.String,
			score: Schema.Number,
			grade: Grade,
		}),
	),
	auditors: Schema.Struct({
		passed: Count,
		failed: Count,
		skipped: Count,
		error: Count,
	}),
	/** Findings hidden by suppressions (project config or baseline). */
	suppressed: Count,
	/** Whether the repository's own openaudit config was applied. */
	configApplied: Schema.Boolean,
	openauditVersion: Schema.String,
});
export type TargetSummary = typeof TargetSummary.Type;

/** One finished scan. Times are Unix seconds. */
export const ScanSummary = Schema.Struct({
	id: ScanId,
	status: ScanStatus,
	startedAt: Count,
	finishedAt: Count,
	commit: Schema.NullOr(Schema.String),
	openauditVersion: Schema.NullOr(Schema.String),
	codebase: Schema.NullOr(TargetSummary),
	site: Schema.NullOr(TargetSummary),
	error: Schema.NullOr(Schema.String),
});
export type ScanSummary = typeof ScanSummary.Type;

export const Verification = Schema.Struct({
	code: Schema.String,
	repoFile: Schema.Literal(".openaudit-badge"),
	siteFile: Schema.Literal("/.well-known/openaudit-badge.txt"),
	/** `_openaudit-badge.<host>`, or null without a site. */
	dnsName: Schema.NullOr(Schema.String),
});
export type Verification = typeof Verification.Type;

export const RegisterPayload = Schema.Struct({
	repo: Schema.String.check(Schema.isMaxLength(200)),
	site: Schema.optional(Schema.String.check(Schema.isMaxLength(2000))),
});
export type RegisterPayload = typeof RegisterPayload.Type;

export const Registration = Schema.Struct({
	id: ProjectId,
	repo: Schema.String,
	site: Schema.NullOr(Schema.String),
	verification: Verification,
	/** Shown once. Only its SHA-256 is stored. */
	manageToken: Schema.String,
});
export type Registration = typeof Registration.Type;

export const VerifyResult = Schema.Struct({
	status: ProjectStatus,
	repoVerified: Schema.Boolean,
	siteVerified: Schema.Boolean,
});
export type VerifyResult = typeof VerifyResult.Type;

export const ProjectState = Schema.Struct({
	id: ProjectId,
	repo: Schema.String,
	site: Schema.NullOr(Schema.String),
	status: ProjectStatus,
	repoVerified: Schema.Boolean,
	siteVerified: Schema.Boolean,
	nextScanAt: Schema.NullOr(Count),
	/** The newest successful scan. */
	latest: Schema.optional(ScanSummary),
	/** The newest finished scan, successful or not. */
	lastScan: Schema.optional(ScanSummary),
});
export type ProjectState = typeof ProjectState.Type;

export const Job = Schema.Struct({
	id: ScanId,
	projectId: ProjectId,
	repo: Schema.String,
	/** Present only when the site is verified. */
	site: Schema.NullOr(Schema.String),
	code: Schema.String,
});
export type Job = typeof Job.Type;

export const ClaimResult = Schema.Struct({ job: Schema.NullOr(Job) });
export type ClaimResult = typeof ClaimResult.Type;

/** An openaudit run's JSON and HTML reports, as text. */
export const ReportFiles = Schema.Struct({
	json: Schema.String,
	html: Schema.String,
});
export type ReportFiles = typeof ReportFiles.Type;

export const JobReport = Schema.Struct({
	status: ScanStatus,
	error: Schema.optional(
		Schema.String.check(Schema.isMaxLength(MAX_ERROR_LENGTH)),
	),
	commit: Schema.optional(Schema.String.check(Schema.isMaxLength(64))),
	openauditVersion: Schema.optional(
		Schema.String.check(Schema.isMaxLength(64)),
	),
	codebase: Schema.optional(ReportFiles),
	site: Schema.optional(ReportFiles),
});
export type JobReport = typeof JobReport.Type;

const message = { message: Schema.String };

export class InvalidInput extends Schema.TaggedError<InvalidInput>()(
	"InvalidInput",
	message,
	{ httpApiStatus: 422 },
) {}
export class RepoNotFound extends Schema.TaggedError<RepoNotFound>()(
	"RepoNotFound",
	message,
	{ httpApiStatus: 404 },
) {}
export class RepoTooLarge extends Schema.TaggedError<RepoTooLarge>()(
	"RepoTooLarge",
	message,
	{ httpApiStatus: 422 },
) {}
export class AlreadyRegistered extends Schema.TaggedError<AlreadyRegistered>()(
	"AlreadyRegistered",
	message,
	{ httpApiStatus: 409 },
) {}
export class Full extends Schema.TaggedError<Full>()("Full", message, {
	httpApiStatus: 503,
}) {}
export class RateLimited extends Schema.TaggedError<RateLimited>()(
	"RateLimited",
	message,
	{ httpApiStatus: 429 },
) {}
export class Unauthorized extends Schema.TaggedError<Unauthorized>()(
	"Unauthorized",
	message,
	{ httpApiStatus: 401 },
) {}
export class NotFound extends Schema.TaggedError<NotFound>()(
	"NotFound",
	message,
	{ httpApiStatus: 404 },
) {}

/** The bearer manage token of the request, checked by the handler. */
export class ManageToken extends Context.Service<
	ManageToken,
	Redacted.Redacted<string>
>()("@openaudit/badge/ManageToken") {}

/** Reads the project's manage token; the handler compares its hash. */
export class ManageAuth extends HttpApiMiddleware.Service<
	ManageAuth,
	{ provides: ManageToken; requires: never }
>()("@openaudit/badge/ManageAuth", {
	requiredForClient: true,
	security: { bearer: HttpApiSecurity.bearer },
	error: Unauthorized,
}) {}

/** Admits only the scanner's `SCANNER_TOKEN`. */
export class ScannerAuth extends HttpApiMiddleware.Service<ScannerAuth>()(
	"@openaudit/badge/ScannerAuth",
	{
		requiredForClient: true,
		security: { bearer: HttpApiSecurity.bearer },
		error: Unauthorized,
	},
) {}

const idParams = { id: ProjectId };

export class ProjectsApi extends HttpApiGroup.make("projects")
	.add(
		HttpApiEndpoint.post("register", "/", {
			payload: RegisterPayload,
			success: Registration.pipe(HttpApiSchema.status(201)),
			error: [
				InvalidInput,
				RepoNotFound,
				RepoTooLarge,
				AlreadyRegistered,
				Full,
				RateLimited,
			],
		}),
		HttpApiEndpoint.post("verify", "/:id/verify", {
			params: idParams,
			success: VerifyResult,
			error: NotFound,
		}),
		HttpApiEndpoint.get("get", "/:id", {
			params: idParams,
			success: ProjectState,
			error: NotFound,
		}),
		HttpApiEndpoint.post("rescan", "/:id/rescan", {
			params: idParams,
			success: HttpApiSchema.Accepted,
			error: [NotFound, RateLimited],
		}).middleware(ManageAuth),
		HttpApiEndpoint.delete("remove", "/:id", {
			params: idParams,
			success: HttpApiSchema.NoContent,
			error: NotFound,
		}).middleware(ManageAuth),
	)
	.prefix("/api/badges") {}

export class ScannerApi extends HttpApiGroup.make("scanner")
	.add(
		HttpApiEndpoint.post("claim", "/claim", { success: ClaimResult }),
		HttpApiEndpoint.post("report", "/jobs/:id", {
			params: { id: ScanId },
			payload: JobReport,
			success: HttpApiSchema.NoContent,
			error: [NotFound, InvalidInput],
		}),
	)
	.middleware(ScannerAuth)
	.prefix("/api/scanner") {}

export class BadgeApi extends HttpApi.make("openaudit-badges")
	.add(ProjectsApi)
	.add(ScannerApi)
	.annotateMerge(OpenApi.annotations({ title: "openaudit verified badges" })) {}
