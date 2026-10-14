import { describe, expect, test } from "bun:test";
import { parseJsonc, stripJsonc } from "../src/jsonc";

describe("parseJsonc", () => {
	test("accepts comments and trailing commas", () => {
		const text = `{
	// line comment
	"a": [1, 2,], /* block */
	"b": { "c": "x", },
}`;
		expect(parseJsonc(text)).toEqual({ a: [1, 2], b: { c: "x" } });
	});

	test("drops a trailing comma followed by a comment", () => {
		expect(parseJsonc('{"a": 1, // last\n}')).toEqual({ a: 1 });
		expect(parseJsonc('["a", /* x */ ]')).toEqual(["a"]);
	});

	test("leaves comment markers and commas inside strings alone", () => {
		expect(
			parseJsonc('{"url": "https://x.dev/a,]", "q": "\\"/*", "g": "**/*"}'),
		).toEqual({ url: "https://x.dev/a,]", q: '"/*', g: "**/*" });
	});

	test("rejects what is not JSONC", () => {
		expect(parseJsonc("[1,,2]")).toBeUndefined();
		expect(parseJsonc("{},")).toBeUndefined();
		expect(parseJsonc('{"a": 1 /* open')).toBeUndefined();
		expect(parseJsonc("{a: 1}")).toBeUndefined();
	});

	test("keeps line numbers", () => {
		expect(stripJsonc("/* a\nb */1").split("\n")).toHaveLength(2);
	});
});
