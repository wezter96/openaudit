/**
 * The Cloudflare bindings the badge service uses, typed as narrowly as the
 * code needs them so tests can fake them (worker/badge/test/fakes.ts).
 */
import { Context } from "effect";

export interface D1Result<T> {
	readonly results: ReadonlyArray<T>;
	readonly meta: { readonly changes: number };
}

export interface D1Statement {
	bind(...values: ReadonlyArray<unknown>): D1Statement;
	first<T>(): Promise<T | null>;
	all<T>(): Promise<D1Result<T>>;
	run(): Promise<D1Result<unknown>>;
}

export interface D1 {
	prepare(sql: string): D1Statement;
	batch(statements: ReadonlyArray<D1Statement>): Promise<unknown>;
}

export interface R2Object {
	readonly body: ReadableStream;
}

export interface R2 {
	put(
		key: string,
		value: string,
		options: { httpMetadata: { contentType: string } },
	): Promise<unknown>;
	get(key: string): Promise<R2Object | null>;
	delete(keys: string | ReadonlyArray<string>): Promise<void>;
}

export interface BadgeBindings {
	readonly BADGES: D1;
	readonly BADGE_REPORTS: R2;
	/** The scanner's bearer token (a Worker secret). */
	readonly SCANNER_TOKEN?: string;
}

/** Unix seconds. */
export type Seconds = number;

/** One API request's bindings, time and client address. */
export interface BadgeRequest {
	readonly env: BadgeBindings;
	readonly now: Seconds;
	/** `CF-Connecting-IP`, or "" when absent. */
	readonly ip: string;
}

export class Badge extends Context.Service<Badge, BadgeRequest>()(
	"openaudit-site/Badge",
) {}

export const nowSeconds = (): Seconds => Math.floor(Date.now() / 1000);
