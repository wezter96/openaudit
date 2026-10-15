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

/** An object's position in the file and the low nibble of its marker. */
interface ObjectHeader {
	readonly ref: number;
	readonly pos: number;
	readonly info: number;
}

const outOfBounds = (pos: number, n: number, length: number) =>
	pos < 0 || n < 0 || pos + n > length;

/** Reads objects from one binary plist, memoised by ref and budgeted. */
class BplistReader {
	readonly view: DataView;
	readonly budget = makeBudget();
	// ref → parsed value and the logical size of its subtree.
	private readonly memo = new Map<
		number,
		{ value: PlistValue; size: number }
	>();
	private readonly active = new Set<number>();
	readonly refSize: number;
	private readonly offsetSize: number;
	private readonly numObjects: number;
	private readonly topObject: number;
	private readonly tableOffset: number;

	constructor(readonly bytes: Uint8Array) {
		this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		const trailer = bytes.length - 32;
		this.offsetSize = bytes[trailer + 6] ?? 0;
		this.refSize = bytes[trailer + 7] ?? 0;
		this.numObjects = this.uint(trailer + 8, 8);
		this.topObject = this.uint(trailer + 16, 8);
		this.tableOffset = this.uint(trailer + 24, 8);
		if (this.invalidTrailer()) throw new Error("Invalid binary plist trailer");
		this.need(this.tableOffset, this.numObjects * this.offsetSize);
	}

	private invalidTrailer() {
		return (
			this.offsetSize === 0 ||
			this.refSize === 0 ||
			this.topObject >= this.numObjects
		);
	}

	need(pos: number, n: number) {
		if (outOfBounds(pos, n, this.bytes.length))
			throw new Error("Truncated binary plist");
	}

	uint(pos: number, size: number): number {
		this.need(pos, size);
		let v = 0;
		for (let i = 0; i < size; i++) v = v * 256 + (this.bytes[pos + i] ?? 0);
		return v;
	}

	/** Length nibble, or a following int object when the nibble is 0xF. */
	lengthAt(pos: number, info: number): [number, number] {
		if (info !== 0xf) return [info, pos + 1];
		const marker = this.bytes[pos + 1] ?? 0;
		if (marker >> 4 !== 0x1) throw new Error("Invalid length marker");
		const size = 1 << (marker & 0xf);
		return [this.uint(pos + 2, size), pos + 2 + size];
	}

	/** Length and start of a payload of `unit`-byte items, charged as bytes. */
	payload(o: ObjectHeader, unit: number): [number, number] {
		const [len, start] = this.lengthAt(o.pos, o.info);
		this.need(start, len * unit);
		this.budget.bytes(len * unit);
		return [len, start];
	}

	/** The object at the `i`th ref of a ref list starting at `start`. */
	refAt(start: number, i: number): PlistValue {
		return this.parse(this.uint(start + i * this.refSize, this.refSize));
	}

	/** Runs `fn` with `ref` marked as being parsed, to detect cycles. */
	nested<A>(ref: number, fn: () => A): A {
		this.active.add(ref);
		const out = fn();
		this.active.delete(ref);
		return out;
	}

	parseTop(): PlistValue {
		return this.parse(this.topObject);
	}

	private offsetOf(ref: number): number {
		if (ref >= this.numObjects)
			throw new Error(`Object ref ${ref} out of range`);
		return this.uint(this.tableOffset + ref * this.offsetSize, this.offsetSize);
	}

	private parse(ref: number): PlistValue {
		const cached = this.memo.get(ref);
		if (cached) {
			this.budget.node(cached.size);
			return cached.value;
		}
		if (this.active.has(ref)) throw new Error("Cyclic binary plist");
		this.budget.depth(this.active.size);
		const before = this.budget.nodes;
		this.budget.node();
		const value = this.parseObject(ref);
		this.memo.set(ref, { value, size: this.budget.nodes - before });
		return value;
	}

	private parseObject(ref: number): PlistValue {
		const pos = this.offsetOf(ref);
		this.need(pos, 1);
		const marker = this.bytes[pos] ?? 0;
		const type = marker >> 4;
		const read = OBJECT_READERS.get(type);
		if (!read)
			throw new Error(`Unsupported bplist object type 0x${type.toString(16)}`);
		return read(this, { ref, pos, info: marker & 0xf });
	}
}

type ObjectReader = (r: BplistReader, o: ObjectHeader) => PlistValue;

const readSingleton: ObjectReader = (_, o) =>
	o.info === 0x9 ? true : o.info === 0x8 ? false : null;

const readInt: ObjectReader = (r, { pos, info }) => {
	const size = 1 << info;
	r.need(pos + 1, size);
	if (size === 8) return Number(r.view.getBigInt64(pos + 1));
	if (size === 16) return Number(r.view.getBigInt64(pos + 9));
	return r.uint(pos + 1, size);
};

const readReal: ObjectReader = (r, { pos, info }) => {
	const size = 1 << info;
	r.need(pos + 1, size);
	if (size === 4) return r.view.getFloat32(pos + 1);
	if (size === 8) return r.view.getFloat64(pos + 1);
	throw new Error(`Unsupported real size ${size}`);
};

const readDate: ObjectReader = (r, { pos }) => {
	r.need(pos + 1, 8);
	return new Date(APPLE_EPOCH_MS + r.view.getFloat64(pos + 1) * 1000);
};

const readData: ObjectReader = (r, o) => {
	const [len, start] = r.payload(o, 1);
	return r.bytes.slice(start, start + len);
};

const readAscii: ObjectReader = (r, o) => {
	const [len, start] = r.payload(o, 1);
	return new TextDecoder("latin1").decode(r.bytes.subarray(start, start + len));
};

const readUtf16: ObjectReader = (r, o) => {
	const [len, start] = r.payload(o, 2);
	let s = "";
	for (let i = 0; i < len; i++)
		s += String.fromCharCode(r.view.getUint16(start + i * 2));
	return s;
};

const readUtf8: ObjectReader = (r, o) => {
	const [len, start] = r.payload(o, 1);
	return new TextDecoder().decode(r.bytes.subarray(start, start + len));
};

const readUid: ObjectReader = (r, { pos, info }) => r.uint(pos + 1, info + 1);

/** Arrays and sets. */
const readArray: ObjectReader = (r, o) => {
	const [len, start] = r.lengthAt(o.pos, o.info);
	r.need(start, len * r.refSize);
	return r.nested(o.ref, () => {
		const out: PlistValue[] = [];
		for (let i = 0; i < len; i++) out.push(r.refAt(start, i));
		return out;
	});
};

const readDict: ObjectReader = (r, o) => {
	const [len, start] = r.lengthAt(o.pos, o.info);
	r.need(start, len * 2 * r.refSize);
	return r.nested(o.ref, () => {
		const out: PlistDict = Object.create(null);
		for (let i = 0; i < len; i++) {
			const key = r.refAt(start, i);
			out[String(key)] = r.refAt(start, len + i);
		}
		return out;
	});
};

/** Object readers by the high nibble of the marker byte. */
const OBJECT_READERS = new Map<number, ObjectReader>([
	[0x0, readSingleton],
	[0x1, readInt],
	[0x2, readReal],
	[0x3, readDate],
	[0x4, readData],
	[0x5, readAscii],
	[0x6, readUtf16],
	[0x7, readUtf8],
	[0x8, readUid],
	[0xa, readArray],
	[0xc, readArray],
	[0xd, readDict],
]);

/**
 * Parses a binary plist; throws on malformed input. Objects are memoised by
 * ref, and every ref resolution (including repeats) counts against a node
 * budget, so shared-reference "billion laughs" plists fail fast.
 */
export const parseBinaryPlist = (bytes: Uint8Array): PlistValue => {
	if (!isBinaryPlist(bytes)) throw new Error("Not a bplist00 file");
	if (bytes.length < 8 + 32) throw new Error("Not a bplist00 file");
	return new BplistReader(bytes).parseTop();
};
