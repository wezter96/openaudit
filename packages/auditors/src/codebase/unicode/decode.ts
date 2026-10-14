const utf32 = (bytes: Uint8Array, littleEndian: boolean): string => {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	let out = "";
	for (let i = 4; i + 4 <= bytes.length; i += 4) {
		const cp = view.getUint32(i, littleEndian);
		out += String.fromCodePoint(cp <= 0x10ffff ? cp : 0xfffd);
	}
	return out;
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
	const [b0, b1, b2, b3] = bytes;
	if (b0 === 0xff && b1 === 0xfe && b2 === 0 && b3 === 0)
		return [utf32(bytes, true), utf8()];
	if (b0 === 0 && b1 === 0 && b2 === 0xfe && b3 === 0xff)
		return [utf32(bytes, false), utf8()];
	if (b0 === 0xff && b1 === 0xfe)
		return [new TextDecoder("utf-16le").decode(bytes), utf8()];
	if (b0 === 0xfe && b1 === 0xff)
		return [new TextDecoder("utf-16be").decode(bytes), utf8()];
	const head = bytes.subarray(0, 4096);
	let even = 0;
	let odd = 0;
	for (let i = 0; i < head.length; i++)
		if (head[i] === 0) {
			if (i % 2) odd++;
			else even++;
		}
	if (even + odd > 0) {
		const half = head.length / 2;
		if (odd > half * 0.6 && even < half * 0.1)
			return [new TextDecoder("utf-16le").decode(bytes), utf8()];
		if (even > half * 0.6 && odd < half * 0.1)
			return [new TextDecoder("utf-16be").decode(bytes), utf8()];
		const shebang = b0 === 0x23 && b1 === 0x21;
		if (sniff && !shebang) return [];
	}
	return [utf8()];
};
