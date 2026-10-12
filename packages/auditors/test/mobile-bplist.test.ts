import { describe, expect, test } from "bun:test";

import { isBinaryPlist, parseBinaryPlist } from "../src/mobile/bplist";
import {
	extractEmbeddedPlist,
	parsePlist,
	parseXmlPlist,
} from "../src/mobile/plist";
import { encodeBplist, xmlPlist } from "./mobile-plist-encoder";

const sample = {
	CFBundleIdentifier: "com.example.demo",
	CFBundleDisplayName: "Démo ✓",
	Version: 42,
	Big: 70000,
	Huge: 5_000_000_000,
	Negative: -7,
	Ratio: 1.5,
	Enabled: true,
	Disabled: false,
	Blob: new Uint8Array([1, 2, 3, 255]),
	Created: new Date("2024-05-01T12:00:00.000Z"),
	LongString: "x".repeat(40),
	CFBundleURLTypes: [{ CFBundleURLSchemes: ["demo", "demo-auth"] }],
	NSAppTransportSecurity: { NSAllowsArbitraryLoads: true },
	Empty: [],
};

describe("bplist00 parser", () => {
	test("round-trips every supported object type", () => {
		const bytes = encodeBplist(sample);
		expect(isBinaryPlist(bytes)).toBe(true);
		expect(parseBinaryPlist(bytes)).toEqual(sample);
		expect(parsePlist(bytes)).toEqual(sample);
	});

	test("rejects truncated or foreign input", () => {
		const bytes = encodeBplist(sample);
		expect(() => parseBinaryPlist(bytes.subarray(0, 30))).toThrow();
		expect(parsePlist(bytes.subarray(0, bytes.length - 10))).toBeUndefined();
		expect(parsePlist(new TextEncoder().encode("hello"))).toBeUndefined();
	});

	test("rejects out-of-range object references", () => {
		const bytes = encodeBplist(["a"]);
		// Point the array's single ref at a non-existent object.
		const corrupt = bytes.slice();
		corrupt[9] = 200;
		expect(() => parseBinaryPlist(corrupt)).toThrow();
	});
});

describe("XML plist parser", () => {
	test("parses dicts, arrays, scalars and entities", () => {
		const value = {
			Name: "A & B <c>",
			Count: 3,
			Pi: 3.25,
			On: true,
			Off: false,
			List: ["x", { Nested: "y" }],
			Empty: "",
		};
		expect(parseXmlPlist(xmlPlist(value))).toEqual(value);
	});

	test("decodes <data> and <date>", () => {
		const xml =
			"<plist><dict><key>D</key><data>AQID</data><key>T</key><date>2024-01-02T03:04:05Z</date></dict></plist>";
		expect(parseXmlPlist(xml)).toEqual({
			D: new Uint8Array([1, 2, 3]),
			T: new Date("2024-01-02T03:04:05Z"),
		});
	});

	test("extracts a plist embedded in signed bytes", () => {
		const xml = xmlPlist({ Entitlements: { "get-task-allow": true } });
		const bytes = new Uint8Array([
			0x30,
			0x82,
			0xff,
			0x00,
			...new TextEncoder().encode(xml),
			0x00,
			0xa0,
		]);
		expect(extractEmbeddedPlist(bytes)).toEqual({
			Entitlements: { "get-task-allow": true },
		});
	});
});
