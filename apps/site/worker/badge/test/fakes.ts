/**
 * Test doubles for the badge bindings: D1 backed by an in-memory bun:sqlite
 * database with the real schema.sql, R2 backed by a Map, and a fetch that
 * answers from a table of URLs.
 */
import { Database, type SQLQueryBindings } from "bun:sqlite";
import { join } from "node:path";
import type { D1, D1Statement, R2 } from "../env";

const schema = await Bun.file(join(import.meta.dir, "..", "schema.sql")).text();

class Statement implements D1Statement {
	constructor(
		private readonly db: Database,
		private readonly sql: string,
		private readonly values: ReadonlyArray<SQLQueryBindings> = [],
	) {}
	bind(...values: ReadonlyArray<unknown>) {
		return new Statement(this.db, this.sql, values as SQLQueryBindings[]);
	}
	async first<T>() {
		return (this.db.query(this.sql).get(...this.values) as T | null) ?? null;
	}
	async all<T>() {
		const results = this.db.query(this.sql).all(...this.values) as T[];
		return { results, meta: { changes: 0 } };
	}
	runSync() {
		const { changes } = this.db.query(this.sql).run(...this.values);
		return { results: [], meta: { changes } };
	}
	async run() {
		return this.runSync();
	}
}

export interface FakeD1 extends D1 {
	readonly sqlite: Database;
	/** Every statement prepared, in order. */
	readonly queries: string[];
}

export const fakeD1 = (): FakeD1 => {
	const sqlite = new Database(":memory:");
	sqlite.run(schema);
	const queries: string[] = [];
	return {
		sqlite,
		queries,
		prepare: (sql) => {
			queries.push(sql);
			return new Statement(sqlite, sql);
		},
		// Synchronous, like D1's single transaction: nothing interleaves.
		batch: async (statements) =>
			sqlite.transaction(() =>
				statements.map((s) => (s as Statement).runSync()),
			)(),
	};
};

export interface StoredObject {
	readonly value: string;
	readonly contentType: string;
}

export interface FakeR2 extends R2 {
	readonly objects: Map<string, StoredObject>;
}

export const fakeR2 = (): FakeR2 => {
	const objects = new Map<string, StoredObject>();
	return {
		objects,
		put: async (key, value, { httpMetadata }) => {
			objects.set(key, { value, contentType: httpMetadata.contentType });
		},
		get: async (key) => {
			const object = objects.get(key);
			return object
				? { body: new Response(object.value).body as ReadableStream }
				: null;
		},
		delete: async (keys) => {
			for (const key of typeof keys === "string" ? [keys] : keys)
				objects.delete(key);
		},
	};
};

/** Answers for fetch, by exact URL; anything else is a 404. */
export type Routes = Record<string, () => Response>;

export const fakeFetch = (routes: Routes) => {
	const calls: string[] = [];
	const fetch = async (input: string | URL | Request) => {
		const url = input instanceof Request ? input.url : String(input);
		calls.push(url);
		return routes[url]?.() ?? new Response("not found", { status: 404 });
	};
	return { fetch: fetch as typeof globalThis.fetch, calls };
};
