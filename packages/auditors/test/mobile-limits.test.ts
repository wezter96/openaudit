import { describe, expect, test } from "bun:test";
import { type UnzipFileInfo, unzipSync, zipSync } from "fflate";

import { decodeAxml, decodeProtoXml, parseXmlText } from "../src/mobile/axml";
import { parseBinaryPlist } from "../src/mobile/bplist";
import { parsePlist } from "../src/mobile/plist";
import { budgetedFilter } from "../src/mobile/shared";
import { type El, encodeAxml, encodeProtoXml } from "./mobile-encoders";

/**
 * A bplist where object k is an array of `fanout` refs to object k-1 and
 * object 0 is the string "x": a few hundred bytes that expand to
 * fanout^depth nodes if shared references are materialised naively.
 */
const exponentialBplist = (fanout: number, depth: number): Uint8Array => {
	const objects: number[][] = [[0x51, 0x78]];
	for (let k = 1; k <= depth; k++)
		objects.push([0xa0 | fanout, ...Array<number>(fanout).fill(k - 1)]);
	const out = [...new TextEncoder().encode("bplist00")];
	const offsets: number[] = [];
	for (const obj of objects) {
		offsets.push(out.length);
		out.push(...obj);
	}
	const tableOffset = out.length;
	for (const o of offsets) out.push(o >> 8, o & 0xff);
	const u64 = (n: number) => [0, 0, 0, 0, 0, 0, (n >> 8) & 0xff, n & 0xff];
	out.push(0, 0, 0, 0, 0, 0, 2, 1);
	out.push(...u64(objects.length), ...u64(depth), ...u64(tableOffset));
	return Uint8Array.from(out);
};

const nested = (depth: number): El =>
	depth === 0
		? { name: "leaf" }
		: { name: "node", children: [nested(depth - 1)] };

const timed = <T>(fn: () => T): [T, number] => {
	const start = performance.now();
	const value = fn();
	return [value, performance.now() - start];
};

describe("mobile decode limits", () => {
	test("bplist: shared-reference expansion fails fast", () => {
		const bytes = exponentialBplist(10, 20);
		expect(bytes.length).toBeLessThan(400);
		const [error, ms] = timed(() => {
			try {
				parseBinaryPlist(bytes);
				return undefined;
			} catch (e) {
				return e;
			}
		});
		expect(error).toBeInstanceOf(Error);
		expect(String(error)).toContain("nodes");
		expect(ms).toBeLessThan(1000);
		expect(parsePlist(bytes)).toBeUndefined();
	});

	test("bplist: modest shared references still parse", () => {
		const value = parseBinaryPlist(exponentialBplist(3, 4));
		let leaves = 0;
		const walk = (v: unknown) => {
			if (Array.isArray(v)) for (const c of v) walk(c);
			else if (v === "x") leaves++;
		};
		walk(value);
		expect(leaves).toBe(81);
	});

	test("XML plist: excessive nesting is rejected", () => {
		const deep = `<plist>${"<array>".repeat(300)}${"</array>".repeat(300)}</plist>`;
		expect(parsePlist(new TextEncoder().encode(deep))).toBeUndefined();
		const ok = `<plist>${"<array>".repeat(20)}${"</array>".repeat(20)}</plist>`;
		expect(parsePlist(new TextEncoder().encode(ok))).toBeDefined();
	});

	test("AXML, protobuf and text XML: excessive nesting is rejected", () => {
		expect(decodeAxml(encodeAxml(nested(300)))).toBeUndefined();
		expect(decodeProtoXml(encodeProtoXml(nested(300)))).toBeUndefined();
		const text = `${"<a>".repeat(300)}${"</a>".repeat(300)}`;
		expect(parseXmlText(text)).toBeUndefined();
		expect(decodeAxml(encodeAxml(nested(50)))?.name).toBe("node");
		expect(decodeProtoXml(encodeProtoXml(nested(50)))?.name).toBe("node");
	});

	test("AXML: attribute table larger than its chunk is rejected", () => {
		const bytes = encodeAxml({ name: "manifest", attrs: { package: "a.b" } });
		const view = new DataView(bytes.buffer, bytes.byteOffset);
		// Find the start-element chunk and claim 65535 zero-sized attributes.
		let p = view.getUint16(2, true);
		while (view.getUint16(p, true) !== 0x0102) p += view.getUint32(p + 4, true);
		const ext = p + view.getUint16(p + 2, true);
		view.setUint16(ext + 10, 0, true);
		view.setUint16(ext + 12, 0xffff, true);
		const [root, ms] = timed(() => decodeAxml(bytes));
		expect(root).toBeUndefined();
		expect(ms).toBeLessThan(1000);
	});

	test("zip: entries over budget or with implausible ratios are not inflated", () => {
		const noise = Uint8Array.from({ length: 64 * 1024 }, (_, i) =>
			Math.floor(Math.abs(Math.sin(i + 1)) * 256),
		);
		const zip = zipSync({
			"a.bin": new Uint8Array(100),
			"b.bin": new Uint8Array(100),
			"noise.bin": noise,
		});
		const all = () => true;
		const names = (limits: { maxEntryBytes: number; maxTotalBytes: number }) =>
			Object.keys(unzipSync(zip, { filter: budgetedFilter(all, limits) }));
		expect(names({ maxEntryBytes: 1 << 20, maxTotalBytes: 150 })).toEqual([
			"a.bin",
		]);
		expect(names({ maxEntryBytes: 1000, maxTotalBytes: 1 << 20 })).toEqual([
			"a.bin",
			"b.bin",
		]);

		// Lie about the uncompressed size in the central directory.
		const view = new DataView(zip.buffer, zip.byteOffset);
		for (let i = 0; i + 46 < zip.length; i++) {
			if (view.getUint32(i, true) !== 0x02014b50) continue;
			const nameLen = view.getUint16(i + 28, true);
			const name = new TextDecoder().decode(
				zip.subarray(i + 46, i + 46 + nameLen),
			);
			if (name === "noise.bin") view.setUint32(i + 24, 10, true);
		}
		const info = (
			name: string,
			size: number,
			originalSize: number,
		): UnzipFileInfo => ({ name, size, originalSize, compression: 8 });
		expect(budgetedFilter(all)(info("x", 60_000, 10))).toBe(false);
		expect(budgetedFilter(all)(info("x", 10, 60_000))).toBe(true);
		expect(budgetedFilter(all)({ ...info("x", 10, 10), compression: 14 })).toBe(
			false,
		);
		expect(
			Object.keys(
				unzipSync(zip, {
					filter: budgetedFilter(all, {
						maxEntryBytes: 1 << 20,
						maxTotalBytes: 1 << 20,
					}),
				}),
			),
		).toEqual(["a.bin", "b.bin"]);
	});
});
