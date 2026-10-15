/**
 * Serves the badge JSON API (`BadgeApi` from @openaudit/badge) with
 * `HttpRouter.toWebHandler`. The handler is built once per isolate; each
 * request brings its bindings, time and client address as the `Badge`
 * service.
 */
import {
	BadgeApi,
	ManageAuth,
	ManageToken,
	ScannerAuth,
	Unauthorized,
} from "@openaudit/badge";
import { Context, Effect, Layer, Option, Redacted } from "effect";
import { HttpRouter, HttpServer } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";
import { constantTimeEqual } from "./crypto";
import { Badge, type BadgeRequest } from "./env";
import { getState, remove, rescan, verify } from "./manage";
import { register } from "./register";
import { claim, report } from "./scanner";

/**
 * The request's `Badge` service. It comes from the per-request context the
 * Worker passes to the web handler, not from a layer, so it is looked up
 * rather than required.
 */
const current = Effect.serviceOption(Badge).pipe(
	Effect.flatMap(
		Option.match({
			onNone: () => Effect.die("badge request context missing"),
			onSome: Effect.succeed,
		}),
	),
);

const withRequest = <A, E, R>(
	f: (req: BadgeRequest) => Effect.Effect<A, E, R>,
) => Effect.flatMap(current, f);

const ProjectsLive = HttpApiBuilder.group(BadgeApi, "projects", (handlers) =>
	handlers
		.handle("register", ({ payload }) =>
			withRequest((req) => register(req, payload)),
		)
		.handle("verify", ({ params }) =>
			withRequest((req) => verify(req, params.id)),
		)
		.handle("get", ({ params }) =>
			withRequest((req) => getState(req, params.id)),
		)
		.handle("rescan", ({ params }) =>
			withRequest((req) => rescan(req, params.id)),
		)
		.handle("remove", ({ params }) =>
			withRequest((req) => remove(req, params.id)),
		),
);

const ScannerLive = HttpApiBuilder.group(BadgeApi, "scanner", (handlers) =>
	handlers
		.handle("claim", () => withRequest(claim))
		.handle("report", ({ params, payload }) =>
			withRequest((req) => report(req, params.id, payload)),
		),
);

const unauthorized = () =>
	new Unauthorized({ message: "Missing or wrong bearer token." });

const ManageAuthLive = Layer.succeed(ManageAuth)({
	bearer: (httpEffect, { credential }) =>
		Redacted.value(credential) === ""
			? Effect.fail(unauthorized())
			: Effect.provideService(httpEffect, ManageToken, credential),
});

const scannerTokenMatches = (req: BadgeRequest, token: string) => {
	const expected = req.env.SCANNER_TOKEN ?? "";
	return expected !== "" && constantTimeEqual(token, expected);
};

const ScannerAuthLive = Layer.succeed(ScannerAuth)({
	bearer: (httpEffect, { credential }) =>
		Effect.gen(function* () {
			const req = yield* current;
			if (!scannerTokenMatches(req, Redacted.value(credential)))
				return yield* unauthorized();
			return yield* httpEffect;
		}),
});

const ApiLive = HttpApiBuilder.layer(BadgeApi).pipe(
	Layer.provide([ProjectsLive, ScannerLive]),
	Layer.provide([ManageAuthLive, ScannerAuthLive]),
	Layer.provide(HttpServer.layerServices),
);

const makeWeb = () => HttpRouter.toWebHandler(ApiLive, { disableLogger: true });

let web: ReturnType<typeof makeWeb> | undefined;

/** Answers one /api/badges or /api/scanner request. */
export const handleApi = (request: Request, req: BadgeRequest) => {
	web ??= makeWeb();
	return web.handler(request, Context.make(Badge, req));
};
