import { BadgeApi, ScannerAuth } from "@openaudit/badge/api";
import { Effect, Layer, Redacted, Schedule } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";
import { HttpApiClient, HttpApiMiddleware } from "effect/http-api";

import type { ScannerConfig } from "./config";
import type { ScannerClient } from "./types";

/** No single API call may hang the loop. */
const REQUEST_TIMEOUT = "2 minutes";

/** Sends `SCANNER_TOKEN` as the bearer token on every scanner endpoint. */
const scannerAuthLayer = (token: Redacted.Redacted<string>) =>
	HttpApiMiddleware.layerClient(ScannerAuth, ({ next, request }) =>
		next(HttpClientRequest.bearerToken(request, Redacted.value(token))),
	);

/** Retries network errors and 5xx a few times, so one blip does not lose a report. */
const resilient = (client: HttpClient.HttpClient) =>
	client.pipe(
		HttpClient.retryTransient({
			schedule: Schedule.exponential("2 seconds"),
			times: 4,
		}),
	);

const makeScannerApi = (apiUrl: string) =>
	Effect.flatMap(HttpClient.HttpClient, (httpClient) =>
		HttpApiClient.group(BadgeApi, {
			group: "scanner",
			httpClient: resilient(httpClient),
			baseUrl: apiUrl,
		}),
	);

type ScannerApi = Effect.Success<ReturnType<typeof makeScannerApi>>;

/**
 * Runs one API call. Redirects are never followed (a 3xx fails the call),
 * so the bearer token only ever goes to `API_URL` itself (https, or http on
 * localhost; see config.ts).
 */
const call = <A, E>(effect: Effect.Effect<A, E>): Promise<A> =>
	Effect.runPromise(
		effect.pipe(
			Effect.timeout(REQUEST_TIMEOUT),
			Effect.provideService(FetchHttpClient.RequestInit, {
				redirect: "manual",
			}),
		),
	);

const adapt = (api: ScannerApi): ScannerClient => ({
	claim: async () => (await call(api.claim())).job,
	report: async (id, payload) => {
		await call(api.report({ params: { id }, payload }));
	},
});

/** The generated `HttpApiClient` for the scanner group, as a `ScannerClient`. */
export const makeScannerClient = async (
	config: ScannerConfig,
): Promise<ScannerClient> => {
	const layer = Layer.mergeAll(
		FetchHttpClient.layer,
		scannerAuthLayer(Redacted.make(config.token)),
	);
	const api = await Effect.runPromise(
		makeScannerApi(config.apiUrl).pipe(Effect.provide(layer)),
	);
	return adapt(api);
};
