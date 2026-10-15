/**
 * Bounded readers for the headers of native binaries in mobile artifacts: ELF
 * section tables (shared libraries) and DEX class tables. All offsets are
 * bounds-checked and nothing is executed.
 */

const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46]; // "\x7fELF"
const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a]; // "dex\n"

/** Byte offset into a binary. */
type Offset = number;

const hasMagic = (
	bytes: Uint8Array,
	magic: ReadonlyArray<number>,
	minLength: number,
) => bytes.length >= minLength && magic.every((b, i) => bytes[i] === b);

/** The NUL-terminated string at `start`, read no further than `limit`. */
const cString = (bytes: Uint8Array, start: Offset, limit: Offset): string => {
	let end = start;
	while (end < limit && bytes[end] !== 0) end++;
	return new TextDecoder().decode(bytes.subarray(start, end));
};

/* ----------------------------------- ELF ---------------------------------- */

/** ELF section names that show a library still carries symbols or debug data. */
const DEBUG_SECTIONS = new Set([
	".symtab",
	".debug_info",
	".debug_line",
	".debug_str",
	".debug_abbrev",
	".debug_frame",
]);

interface SectionTable {
	readonly shoff: Offset;
	readonly shentsize: number;
	readonly shnum: number;
	readonly shstrndx: number;
}

interface Section {
	readonly offset: Offset;
	readonly size: number;
}

/** Field reads for a 32- or 64-bit ELF file of either byte order. */
class ElfFile {
	readonly is64: boolean;
	private readonly little: boolean;
	private readonly view: DataView;

	constructor(readonly bytes: Uint8Array) {
		this.is64 = bytes[4] === 2;
		this.little = bytes[5] !== 2;
		this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	}

	u16(o: Offset) {
		return this.view.getUint16(o, this.little);
	}

	u32(o: Offset) {
		return this.view.getUint32(o, this.little);
	}

	/** An address-sized field: 64-bit at `at64`, or 32-bit at `at32`. */
	addr(at64: Offset, at32: Offset): number {
		if (!this.is64) return this.u32(at32);
		const v = this.view.getBigUint64(at64, this.little);
		return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.NaN : Number(v);
	}

	sectionTable(): SectionTable {
		const is64 = this.is64;
		return {
			shoff: this.addr(0x28, 0x20),
			shentsize: this.u16(is64 ? 0x3a : 0x2e),
			shnum: this.u16(is64 ? 0x3c : 0x30),
			shstrndx: this.u16(is64 ? 0x3e : 0x32),
		};
	}

	header(table: SectionTable, i: number): Offset {
		return table.shoff + i * table.shentsize;
	}

	section(table: SectionTable, i: number): Section {
		const h = this.header(table, i);
		return {
			offset: this.addr(h + 0x18, h + 0x10),
			size: this.addr(h + 0x20, h + 0x14),
		};
	}
}

const plausibleTable = (t: SectionTable, minEntry: number) =>
	t.shnum !== 0 &&
	t.shnum <= 4096 &&
	t.shentsize >= minEntry &&
	t.shstrndx < t.shnum;

const tableInBounds = (t: SectionTable, length: number) =>
	Number.isFinite(t.shoff) &&
	t.shoff !== 0 &&
	t.shoff + t.shnum * t.shentsize <= length;

const sectionInBounds = (s: Section, length: number) =>
	Number.isFinite(s.offset) &&
	Number.isFinite(s.size) &&
	s.offset + s.size <= length;

const validTable = (elf: ElfFile, t: SectionTable) =>
	plausibleTable(t, elf.is64 ? 0x40 : 0x28) &&
	tableInBounds(t, elf.bytes.length);

/** Name of section `i` from the section name table, unless out of range. */
const sectionName = (
	elf: ElfFile,
	table: SectionTable,
	names: Section,
	i: number,
): string | undefined => {
	const nameOff = elf.u32(elf.header(table, i));
	if (nameOff >= names.size) return undefined;
	const start = names.offset + nameOff;
	return cString(
		elf.bytes,
		start,
		Math.min(names.offset + names.size, start + 64),
	);
};

const debugSectionNames = (elf: ElfFile): string[] => {
	const table = elf.sectionTable();
	if (!validTable(elf, table)) return [];
	const names = elf.section(table, table.shstrndx);
	if (!sectionInBounds(names, elf.bytes.length)) return [];
	const found = new Set<string>();
	for (let i = 0; i < table.shnum; i++) {
		const name = sectionName(elf, table, names, i);
		if (name !== undefined && DEBUG_SECTIONS.has(name)) found.add(name);
	}
	return [...found];
};

/**
 * Names of symbol/debug sections in an ELF file, read from its section header
 * table. Returns [] for anything that is not a well-formed ELF.
 */
export const elfDebugSections = (bytes: Uint8Array): string[] => {
	if (!hasMagic(bytes, ELF_MAGIC, 0x40)) return [];
	if (bytes[4] !== 1 && bytes[4] !== 2) return [];
	try {
		return debugSectionNames(new ElfFile(bytes));
	} catch {
		return [];
	}
};

/* ----------------------------------- DEX ---------------------------------- */

const MAX_DEX_CLASSES = 50_000;
const MAX_SAMPLES = 5;

export interface DexStats {
	/** Classes defined in the DEX (not merely referenced). */
	readonly classes: number;
	/** Of those, classes whose simple name has at most 2 characters. */
	readonly short: number;
	/** Examples of readable class descriptors. */
	readonly samples: ReadonlyArray<string>;
}

/** The id tables a class descriptor is resolved through. */
interface DexFile {
	readonly bytes: Uint8Array;
	readonly view: DataView;
	readonly stringCount: number;
	readonly stringOff: Offset;
	readonly typeCount: number;
	readonly typeOff: Offset;
	readonly classCount: number;
	readonly classOff: Offset;
}

const readDexHeader = (bytes: Uint8Array): DexFile => {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	return {
		bytes,
		view,
		stringCount: view.getUint32(0x38, true),
		stringOff: view.getUint32(0x3c, true),
		typeCount: view.getUint32(0x40, true),
		typeOff: view.getUint32(0x44, true),
		classCount: Math.min(view.getUint32(0x60, true), MAX_DEX_CLASSES),
		classOff: view.getUint32(0x64, true),
	};
};

const tablesInBounds = (dex: DexFile) => {
	const length = dex.bytes.length;
	return (
		dex.stringOff + dex.stringCount * 4 <= length &&
		dex.typeOff + dex.typeCount * 4 <= length &&
		dex.classOff + dex.classCount * 32 <= length
	);
};

/** A string_data_item: a ULEB128 UTF-16 length, then NUL-terminated MUTF-8. */
const dexString = (bytes: Uint8Array, at: Offset): string => {
	let p = at;
	while (p < bytes.length && (bytes[p] ?? 0) & 0x80) p++;
	p++;
	return cString(bytes, p, Math.min(bytes.length, p + 300));
};

/** Descriptor of the `i`th defined class, unless an index is out of range. */
const classDescriptor = (dex: DexFile, i: number): string | undefined => {
	const { view } = dex;
	const typeIdx = view.getUint32(dex.classOff + i * 32, true);
	if (typeIdx >= dex.typeCount) return undefined;
	const strIdx = view.getUint32(dex.typeOff + typeIdx * 4, true);
	if (strIdx >= dex.stringCount) return undefined;
	const p = view.getUint32(dex.stringOff + strIdx * 4, true);
	if (p >= dex.bytes.length) return undefined;
	return dexString(dex.bytes, p);
};

const CLASS_DESCRIPTOR = /^L[\w$/]+;$/;

const isClassDescriptor = (d: string | undefined): d is string =>
	d !== undefined && CLASS_DESCRIPTOR.test(d);

/** `Lcom/example/Foo$Bar;` → `Foo`. */
const simpleClassName = (descriptor: string) =>
	(descriptor.slice(1, -1).split("/").pop() ?? "").split("$")[0] ?? "";

interface DexTally {
	classes: number;
	short: number;
	readonly samples: string[];
}

const countClass = (tally: DexTally, descriptor: string) => {
	tally.classes++;
	if (simpleClassName(descriptor).length <= 2) tally.short++;
	else if (tally.samples.length < MAX_SAMPLES && descriptor.includes("/"))
		tally.samples.push(descriptor);
};

const countDexClasses = (dex: DexFile): DexStats => {
	const tally: DexTally = { classes: 0, short: 0, samples: [] };
	for (let i = 0; i < dex.classCount; i++) {
		const descriptor = classDescriptor(dex, i);
		if (isClassDescriptor(descriptor)) countClass(tally, descriptor);
	}
	return tally;
};

/**
 * Counts the classes a DEX file defines and how many carry short, renamed-looking
 * names. Reads only the header, string ids, type ids and class defs; all
 * offsets are bounds-checked.
 */
export const scanDex = (bytes: Uint8Array): DexStats | undefined => {
	if (!hasMagic(bytes, DEX_MAGIC, 0x70)) return undefined;
	try {
		const dex = readDexHeader(bytes);
		return tablesInBounds(dex) ? countDexClasses(dex) : undefined;
	} catch {
		return undefined;
	}
};
