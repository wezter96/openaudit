/**
 * Minimal `bplist00` (binary property list) reader. Supports the object types
 * found in Info.plist and entitlements: null/bool, int, real, date, data,
 * ASCII/UTF-16/UTF-8 strings, UID, array, set and dict.
 */

import { makeBudget } from "./limits";

export type PlistValue =
	| string
	| number
	| boolean
	| Date
	| Uint8Array
	| null
	| PlistValue[]
	| PlistDict;

export interface PlistDict {
	[key: string]: PlistValue;
}

/** Seconds between the Unix epoch and the Core Data epoch (2001-01-01). */
const APPLE_EPOCH_MS = Date.UTC(2001, 0, 1);

const MAGIC = [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30]; // "bplist00"

export const isBinaryPlist = (bytes: Uint8Array): boolean =>
	bytes.length >= MAGIC.length && MAGIC.every((b, i) => bytes[i] === b);

/**
 * Parses a binary plist; throws on malformed input. Objects are memoised by
 * ref, and every ref resolution (including repeats) counts against a node
 * budget, so shared-reference "billion laughs" plists fail fast.
 */
export const parseBinaryPlist = (bytes: Uint8Array): PlistValue => {
	if (!isBinaryPlist(bytes) || bytes.length < 8 + 32)
		throw new Error("Not a bplist00 file");
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

	const need = (pos: number, n: number) => {
		if (pos < 0 || n < 0 || pos + n > bytes.length)
			throw new Error("Truncated binary plist");
	};
	const uint = (pos: number, size: number): number => {
		need(pos, size);
		let v = 0;
		for (let i = 0; i < size; i++) v = v * 256 + (bytes[pos + i] ?? 0);
		return v;
	};

	const trailer = bytes.length - 32;
	const offsetSize = bytes[trailer + 6] ?? 0;
	const refSize = bytes[trailer + 7] ?? 0;
	const numObjects = uint(trailer + 8, 8);
	const topObject = uint(trailer + 16, 8);
	const tableOffset = uint(trailer + 24, 8);
	if (offsetSize === 0 || refSize === 0 || topObject >= numObjects)
		throw new Error("Invalid binary plist trailer");
	need(tableOffset, numObjects * offsetSize);

	const offsetOf = (ref: number): number => {
		if (ref >= numObjects) throw new Error(`Object ref ${ref} out of range`);
		return uint(tableOffset + ref * offsetSize, offsetSize);
	};

	/** Length nibble, or a following int object when the nibble is 0xF. */
	const lengthAt = (pos: number, info: number): [number, number] => {
		if (info !== 0xf) return [info, pos + 1];
		const marker = bytes[pos + 1] ?? 0;
		if (marker >> 4 !== 0x1) throw new Error("Invalid length marker");
		const size = 1 << (marker & 0xf);
		return [uint(pos + 2, size), pos + 2 + size];
	};

	const budget = makeBudget();
	// ref → parsed value and the logical size of its subtree.
	const memo = new Map<number, { value: PlistValue; size: number }>();
	const active = new Set<number>();
	const parse = (ref: number): PlistValue => {
		const cached = memo.get(ref);
		if (cached) {
			budget.node(cached.size);
			return cached.value;
		}
		if (active.has(ref)) throw new Error("Cyclic binary plist");
		budget.depth(active.size);
		const before = budget.nodes;
		budget.node();
		const value = parseObject(ref);
		memo.set(ref, { value, size: budget.nodes - before });
		return value;
	};
	const parseObject = (ref: number): PlistValue => {
		const pos = offsetOf(ref);
		need(pos, 1);
		const marker = bytes[pos] ?? 0;
		const type = marker >> 4;
		const info = marker & 0xf;
		switch (type) {
			case 0x0:
				return info === 0x9 ? true : info === 0x8 ? false : null;
			case 0x1: {
				const size = 1 << info;
				need(pos + 1, size);
				if (size === 8) return Number(view.getBigInt64(pos + 1));
				if (size === 16) return Number(view.getBigInt64(pos + 9));
				return uint(pos + 1, size);
			}
			case 0x2: {
				const size = 1 << info;
				need(pos + 1, size);
				if (size === 4) return view.getFloat32(pos + 1);
				if (size === 8) return view.getFloat64(pos + 1);
				throw new Error(`Unsupported real size ${size}`);
			}
			case 0x3:
				need(pos + 1, 8);
				return new Date(APPLE_EPOCH_MS + view.getFloat64(pos + 1) * 1000);
			case 0x4: {
				const [len, start] = lengthAt(pos, info);
				need(start, len);
				budget.bytes(len);
				return bytes.slice(start, start + len);
			}
			case 0x5: {
				const [len, start] = lengthAt(pos, info);
				need(start, len);
				budget.bytes(len);
				return new TextDecoder("latin1").decode(
					bytes.subarray(start, start + len),
				);
			}
			case 0x6: {
				const [len, start] = lengthAt(pos, info);
				need(start, len * 2);
				budget.bytes(len * 2);
				let s = "";
				for (let i = 0; i < len; i++)
					s += String.fromCharCode(view.getUint16(start + i * 2));
				return s;
			}
			case 0x7: {
				const [len, start] = lengthAt(pos, info);
				need(start, len);
				budget.bytes(len);
				return new TextDecoder().decode(bytes.subarray(start, start + len));
			}
			case 0x8:
				return uint(pos + 1, info + 1);
			case 0xa:
			case 0xc: {
				const [len, start] = lengthAt(pos, info);
				need(start, len * refSize);
				active.add(ref);
				const out: PlistValue[] = [];
				for (let i = 0; i < len; i++)
					out.push(parse(uint(start + i * refSize, refSize)));
				active.delete(ref);
				return out;
			}
			case 0xd: {
				const [len, start] = lengthAt(pos, info);
				need(start, len * 2 * refSize);
				active.add(ref);
				const out: PlistDict = Object.create(null);
				for (let i = 0; i < len; i++) {
					const key = parse(uint(start + i * refSize, refSize));
					out[String(key)] = parse(uint(start + (len + i) * refSize, refSize));
				}
				active.delete(ref);
				return out;
			}
			default:
				throw new Error(
					`Unsupported bplist object type 0x${type.toString(16)}`,
				);
		}
	};

	return parse(topObject);
};
