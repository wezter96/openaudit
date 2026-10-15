import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { zipSync } from "fflate";

const header = (type: number, len: number): number[] =>
	len < 15
		? [(type << 4) | len]
		: [(type << 4) | 0xf, 0x11, (len >> 8) & 0xff, len & 0xff];

const float64 = (marker: number, n: number) => {
	const b = new Uint8Array(9);
	b[0] = marker;
	new DataView(b.buffer).setFloat64(1, n);
	return [...b];
};

const int64 = (v: number) => {
	const b = new Uint8Array(9);
	b[0] = 0x13;
	new DataView(b.buffer).setBigInt64(1, BigInt(v));
	return [...b];
};

const encodeInteger = (v: number): number[] => {
	if (v < 0 || v >= 2 ** 32) return int64(v);
	if (v < 0x100) return [0x10, v];
	if (v < 0x10000) return [0x11, v >> 8, v & 0xff];
	return [0x12, (v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff];
};

const encodeNumber = (v: number): number[] =>
	Number.isInteger(v) ? encodeInteger(v) : float64(0x23, v);

const encodeText = (v: string): number[] => {
	// biome-ignore lint/suspicious/noControlCharactersInRegex: ASCII range check
	if (/^[\x00-\x7f]*$/.test(v))
		return [...header(0x5, v.length), ...[...v].map((c) => c.charCodeAt(0))];
	const out = header(0x6, v.length);
	for (let i = 0; i < v.length; i++) {
		const c = v.charCodeAt(i);
		out.push(c >> 8, c & 0xff);
	}
	return out;
};

/** Adds an object to the plist and returns its reference. */
type AddObject = (v: unknown) => number;

const encodeDict = (v: Record<string, unknown>, add: AddObject): number[] => {
	const entries = Object.entries(v);
	const keys = entries.map(([k]) => add(k));
	const values = entries.map(([, val]) => add(val));
	return [...header(0xd, entries.length), ...keys, ...values];
};

/** Dates, data, arrays and dictionaries. */
const encodeObject = (v: object, add: AddObject): number[] => {
	if (v instanceof Date)
		return float64(0x33, (v.getTime() - Date.UTC(2001, 0, 1)) / 1000);
	if (v instanceof Uint8Array) return [...header(0x4, v.length), ...v];
	if (Array.isArray(v)) {
		const refs = v.map(add);
		return [...header(0xa, refs.length), ...refs];
	}
	return encodeDict(v as Record<string, unknown>, add);
};

const encodeValue = (v: unknown, add: AddObject): number[] => {
	if (v === null || v === undefined) return [0x00];
	if (v === false) return [0x08];
	if (v === true) return [0x09];
	if (typeof v === "number") return encodeNumber(v);
	if (typeof v === "string") return encodeText(v);
	return encodeObject(v as object, add);
};

/** Tiny bplist00 encoder for tests (≤ 255 objects, 1-byte refs, 2-byte offsets). */
export const encodeBplist = (root: unknown): Uint8Array => {
	const objects: Uint8Array[] = [];

	function add(v: unknown): number {
		const ref = objects.length;
		objects.push(new Uint8Array());
		objects[ref] = Uint8Array.from(encodeValue(v, add));
		if (objects.length > 255)
			throw new Error("too many objects for test encoder");
		return ref;
	}

	add(root);
	const magic = [..."bplist00"].map((c) => c.charCodeAt(0));
	const body: number[] = [...magic];
	const offsets: number[] = [];
	for (const obj of objects) {
		offsets.push(body.length);
		body.push(...obj);
	}
	const tableOffset = body.length;
	for (const off of offsets) body.push(off >> 8, off & 0xff);
	const trailer = new Uint8Array(32);
	const dv = new DataView(trailer.buffer);
	trailer[6] = 2;
	trailer[7] = 1;
	dv.setBigUint64(8, BigInt(objects.length));
	dv.setBigUint64(16, 0n);
	dv.setBigUint64(24, BigInt(tableOffset));
	return Uint8Array.from([...body, ...trailer]);
};

const escapeXml = (s: string) =>
	s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** Serializes a JS value as an XML plist. */
export const xmlPlist = (root: unknown): string => {
	const enc = (v: unknown): string => {
		if (v === true) return "<true/>";
		if (v === false) return "<false/>";
		if (typeof v === "number")
			return Number.isInteger(v)
				? `<integer>${v}</integer>`
				: `<real>${v}</real>`;
		if (typeof v === "string") return `<string>${escapeXml(v)}</string>`;
		if (Array.isArray(v)) return `<array>\n${v.map(enc).join("\n")}\n</array>`;
		const body = Object.entries(v as Record<string, unknown>)
			.map(([k, val]) => `<key>${escapeXml(k)}</key>\n${enc(val)}`)
			.join("\n");
		return `<dict>\n${body}\n</dict>`;
	};
	return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n${enc(root)}\n</plist>\n`;
};

/** Writes a zip archive (APK/IPA) into a fresh temp dir and returns its path. */
export const writeArchive = async (
	name: string,
	entries: Record<string, Uint8Array | string>,
): Promise<string> => {
	const dir = await mkdtemp(join(tmpdir(), "openaudit-mobile-"));
	const files: Record<string, Uint8Array> = {};
	for (const [k, v] of Object.entries(entries))
		files[k] = typeof v === "string" ? new TextEncoder().encode(v) : v;
	const path = join(dir, name);
	await writeFile(path, zipSync(files));
	return path;
};

/** Writes a source tree into a fresh temp dir and returns its path. */
export const writeTree = async (
	files: Record<string, string>,
): Promise<string> => {
	const dir = await mkdtemp(join(tmpdir(), "openaudit-mobile-src-"));
	for (const [rel, content] of Object.entries(files)) {
		await mkdir(dirname(join(dir, rel)), { recursive: true });
		await writeFile(join(dir, rel), content);
	}
	return dir;
};
