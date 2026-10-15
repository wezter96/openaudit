const utf32 = (bytes: Uint8Array, littleEndian: boolean): string => {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	let out = "";
	for (let i = 4; i + 4 <= bytes.length; i += 4) {
		const cp = view.getUint32(i, littleEndian);
		out += String.fromCodePoint(cp <= 0x10ffff ? cp : 0xfffd);
	}
	return out;
};

const utf16 = (encoding: "utf-16le" | "utf-16be") => (bytes: Uint8Array) =>
	new TextDecoder(encoding).decode(bytes);

/** Byte order marks, longest first so UTF-32LE is not read as UTF-16LE. */
const BOMS: ReadonlyArray<{
	readonly bom: ReadonlyArray<number>;
	readonly decode: (bytes: Uint8Array) => string;
}> = [
	{ bom: [0xff, 0xfe, 0, 0], decode: (bytes) => utf32(bytes, true) },
	{ bom: [0, 0, 0xfe, 0xff], decode: (bytes) => utf32(bytes, false) },
	{ bom: [0xff, 0xfe], decode: utf16("utf-16le") },
	{ bom: [0xfe, 0xff], decode: utf16("utf-16be") },
];

const SHEBANG = [0x23, 0x21];

const startsWith = (bytes: Uint8Array, prefix: ReadonlyArray<number>) =>
	prefix.every((b, i) => bytes[i] === b);

interface Nuls {
	readonly even: number;
	readonly odd: number;
}

const nulsOf = (head: Uint8Array): Nuls => {
	let even = 0;
	let odd = 0;
	for (let i = 0; i < head.length; i++) {
		if (head[i] !== 0) continue;
		if (i % 2) odd++;
		else even++;
	}
	return { even, odd };
};

/** UTF-16 without a BOM, told apart by where mostly-ASCII text has its NULs. */
const utf16ByNuls = (
	{ even, odd }: Nuls,
	half: number,
): "utf-16le" | "utf-16be" | undefined => {
	if (odd > half * 0.6 && even < half * 0.1) return "utf-16le";
	if (even > half * 0.6 && odd < half * 0.1) return "utf-16be";
	return undefined;
};

/**
 * Every plausible reading of a file's bytes. UTF-32 and UTF-16 (with a BOM, or
 * detected from the NUL pattern of mostly-ASCII text) are decoded as such,
 * because compilers such as tsc and csc honour them, and the UTF-8 reading is
 * scanned as well, because others ignore the BOM. Binary content yields
 * nothing when `sniff` is set; for known kinds and shebang scripts a NUL never
 * hides the file.
 */
export const decodeTexts = (bytes: Uint8Array, sniff: boolean): string[] => {
	const utf8 = () => new TextDecoder().decode(bytes);
	const marked = BOMS.find(({ bom }) => startsWith(bytes, bom));
	if (marked) return [marked.decode(bytes), utf8()];
	const head = bytes.subarray(0, 4096);
	const nuls = nulsOf(head);
	if (nuls.even + nuls.odd === 0) return [utf8()];
	const encoding = utf16ByNuls(nuls, head.length / 2);
	if (encoding) return [new TextDecoder(encoding).decode(bytes), utf8()];
	return sniff && !startsWith(bytes, SHEBANG) ? [] : [utf8()];
};
