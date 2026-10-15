import { describe, expect, test } from "bun:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Zippable, zipSync } from "fflate";

import {
	elfDebugSections,
	mobilePerformance,
	scanDex,
	sizeFinding,
} from "../src/mobile/performance";
import { ruleIds, runAuditor } from "./helpers";
import { encodeBplist, writeTree } from "./mobile-plist-encoder";
import { findingWith, firstResult } from "./must";

const MiB = 1024 * 1024;

/* ------------------------------- synthetic DEX ------------------------------ */

const concat = (...parts: ReadonlyArray<Uint8Array>) => {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
};
const u32 = (n: number) => {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n, true);
	return b;
};

/** A DEX with the given class descriptors: header, string/type ids, class defs. */
const buildDex = (descriptors: ReadonlyArray<string>): Uint8Array => {
	const n = descriptors.length;
	const stringIdsOff = 0x70;
	const typeIdsOff = stringIdsOff + 4 * n;
	const classDefsOff = typeIdsOff + 4 * n;
	const dataOff = classDefsOff + 32 * n;
	const strings: Uint8Array[] = [];
	const offsets: number[] = [];
	let off = dataOff;
	for (const d of descriptors) {
		const body = new TextEncoder().encode(d);
		const item = concat(Uint8Array.of(body.length), body, Uint8Array.of(0));
		offsets.push(off);
		off += item.length;
		strings.push(item);
	}
	const header = new Uint8Array(0x70);
	header.set([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]);
	const hv = new DataView(header.buffer);
	hv.setUint32(0x38, n, true);
	hv.setUint32(0x3c, stringIdsOff, true);
	hv.setUint32(0x40, n, true);
	hv.setUint32(0x44, typeIdsOff, true);
	hv.setUint32(0x60, n, true);
	hv.setUint32(0x64, classDefsOff, true);
	const classDefs = descriptors.map((_, i) => {
		const def = new Uint8Array(32);
		new DataView(def.buffer).setUint32(0, i, true);
		return def;
	});
	return concat(
		header,
		...offsets.map(u32),
		...descriptors.map((_, i) => u32(i)),
		...classDefs,
		...strings,
	);
};

const readable = (count: number) =>
	Array.from(
		{ length: count },
		(_, i) => `Lcom/example/app/ui/Screen${i}Controller;`,
	);
const renamed = (count: number) =>
	Array.from(
		{ length: count },
		(_, i) => `La/b/${String.fromCharCode(97 + (i % 26))}${i % 7};`,
	);

/* -------------------------------- synthetic ELF ----------------------------- */

/** A 64-bit little-endian ELF with only a section header table. */
const buildElf = (sections: ReadonlyArray<string>): Uint8Array => {
	const names = [".text", ...sections, ".shstrtab"];
	const strtab = concat(
		Uint8Array.of(0),
		...names.map((s) => concat(new TextEncoder().encode(s), Uint8Array.of(0))),
	);
	const nameOffsets: number[] = [];
	let o = 1;
	for (const s of names) {
		nameOffsets.push(o);
		o += s.length + 1;
	}
	const shoff = 0x40 + strtab.length;
	const count = names.length + 1;
	const header = new Uint8Array(0x40);
	header.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
	const hv = new DataView(header.buffer);
	hv.setBigUint64(0x28, BigInt(shoff), true);
	hv.setUint16(0x3a, 0x40, true);
	hv.setUint16(0x3c, count, true);
	hv.setUint16(0x3e, count - 1, true);
	const headers = new Uint8Array(0x40 * count);
	const sv = new DataView(headers.buffer);
	names.forEach((_, i) => {
		const h = 0x40 * (i + 1);
		sv.setUint32(h, nameOffsets[i] ?? 0, true);
		if (i === names.length - 1) {
			sv.setBigUint64(h + 0x18, 0x40n, true);
			sv.setBigUint64(h + 0x20, BigInt(strtab.length), true);
		}
	});
	return concat(header, strtab, headers);
};

/* --------------------------------- archives --------------------------------- */

const writeZipFile = async (name: string, entries: Zippable) => {
	const dir = await mkdtemp(join(tmpdir(), "openaudit-mobile-perf-"));
	const path = join(dir, name);
	await writeFile(path, zipSync(entries));
	return path;
};
const stored = (data: Uint8Array): [Uint8Array, { level: 0 }] => [
	data,
	{ level: 0 },
];

const findings = (report: Awaited<ReturnType<typeof runAuditor>>) =>
	report.results.flatMap((r) => r.findings);

/** A performance finding about the APK, with a remediation. */
const expectApkPerformance = (f: ReturnType<typeof findings>[number]) => {
	expect(f.category).toBe("performance");
	expect(f.remediation).toBeTruthy();
	expect(f.location?.file).toContain("app.apk");
};

describe("size thresholds", () => {
	test("APK: > 100 MB high, > 50 MB medium", () => {
		expect(sizeFinding("a.apk", "apk", 101 * MiB)?.severity).toBe("high");
		expect(sizeFinding("a.apk", "apk", 51 * MiB)?.severity).toBe("medium");
		expect(sizeFinding("a.apk", "apk", 50 * MiB)).toBeUndefined();
		expect(sizeFinding("a.apk", "apk", 10 * MiB)).toBeUndefined();
	});
	test("AAB and IPA use their own limits", () => {
		expect(sizeFinding("a.aab", "aab", 150 * MiB)?.severity).toBe("medium");
		expect(sizeFinding("a.aab", "aab", 201 * MiB)?.severity).toBe("high");
		expect(sizeFinding("a.ipa", "ipa", 250 * MiB)?.severity).toBe("medium");
	});
});

describe("binary scanners", () => {
	test("scanDex counts renamed-looking classes", () => {
		expect(scanDex(buildDex(readable(10)))).toMatchObject({
			classes: 10,
			short: 0,
		});
		expect(scanDex(buildDex(renamed(10)))).toMatchObject({
			classes: 10,
			short: 10,
		});
	});

	test("scanDex rejects malformed input", () => {
		expect(scanDex(new Uint8Array(10))).toBeUndefined();
		const dex = buildDex(readable(3));
		// Class table pointing past the end of the file.
		new DataView(dex.buffer).setUint32(0x64, 0x7fffffff, true);
		expect(scanDex(dex)).toBeUndefined();
		expect(scanDex(dex.subarray(0, 0x50))).toBeUndefined();
	});

	test("elfDebugSections reads the section header table", () => {
		expect(elfDebugSections(buildElf([".symtab", ".debug_info"]))).toEqual([
			".symtab",
			".debug_info",
		]);
		expect(elfDebugSections(buildElf([]))).toEqual([]);
		expect(
			elfDebugSections(new TextEncoder().encode("not an elf".repeat(10))),
		).toEqual([]);
		const broken = buildElf([".symtab"]);
		new DataView(broken.buffer).setBigUint64(0x28, 0x7fffffffn, true);
		expect(elfDebugSections(broken)).toEqual([]);
	});
});

describe("mobile.performance", () => {
	test("flags ABIs, unstripped libs, assets and un-minified code in an APK", async () => {
		const apk = await writeZipFile("app.apk", {
			"classes.dex": buildDex(readable(400)),
			"lib/arm64-v8a/libnative.so": buildElf([".symtab", ".debug_info"]),
			"lib/arm64-v8a/libclean.so": buildElf([]),
			"lib/armeabi-v7a/libnative.so": buildElf([]),
			"lib/x86_64/libnative.so": buildElf([]),
			"assets/model.bin": new Uint8Array(6 * MiB),
			"assets/data.json": stored(new Uint8Array(600 * 1024).fill(0x20)),
			"assets/small.json": stored(new Uint8Array(100).fill(0x20)),
			"resources.arsc": stored(new Uint8Array(2 * MiB)),
		});
		const report = await runAuditor(mobilePerformance, apk);
		expect(firstResult(report).status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"mobile.performance/dex-not-minified",
			"mobile.performance/large-assets",
			"mobile.performance/multi-abi-native-libs",
			"mobile.performance/uncompressed-assets",
			"mobile.performance/unstripped-native-libs",
		]);
		const all = findings(report);
		const by = (id: string) => findingWith(all, `mobile.performance/${id}`);
		expect(by("dex-not-minified").confidence).toBe("low");
		expect(by("dex-not-minified").evidence).toContain("Lcom/example/app/ui/");
		expect(by("multi-abi-native-libs").severity).toBe("low");
		expect(by("multi-abi-native-libs").message).toContain("3 ABIs");
		expect(by("unstripped-native-libs").severity).toBe("medium");
		expect(by("unstripped-native-libs").evidence).toContain(
			"lib/arm64-v8a/libnative.so",
		);
		expect(by("unstripped-native-libs").evidence).not.toContain("libclean");
		expect(by("large-assets").evidence).toContain("assets/model.bin: 6.0 MB");
		expect(by("large-assets").evidence).not.toContain("resources.arsc");
		expect(by("uncompressed-assets").evidence).toContain("assets/data.json");
		expect(by("uncompressed-assets").evidence).not.toContain("small.json");
		for (const f of all) expectApkPerformance(f);
	});

	test("passes a lean, minified APK", async () => {
		const apk = await writeZipFile("lean.apk", {
			"classes.dex": buildDex(renamed(400)),
			"lib/arm64-v8a/libnative.so": buildElf([]),
			"assets/config.json": new TextEncoder().encode("{}"),
		});
		const report = await runAuditor(mobilePerformance, apk);
		expect(report.results[0]?.status).toBe("passed");
	});

	test("does not judge minification of tiny DEX files", async () => {
		const apk = await writeZipFile("tiny.apk", {
			"classes.dex": buildDex(readable(20)),
		});
		const report = await runAuditor(mobilePerformance, apk);
		expect(ruleIds(report)).toEqual([]);
	});

	test("reads the base module of an AAB without recommending ABI splits", async () => {
		const aab = await writeZipFile("app.aab", {
			"base/dex/classes.dex": buildDex(readable(400)),
			"base/lib/arm64-v8a/libnative.so": buildElf([".symtab"]),
			"base/lib/x86/libnative.so": buildElf([".symtab"]),
			"base/lib/x86_64/libnative.so": buildElf([".symtab"]),
		});
		const report = await runAuditor(mobilePerformance, aab);
		expect(ruleIds(report)).toEqual([
			"mobile.performance/dex-not-minified",
			"mobile.performance/unstripped-native-libs",
		]);
		expect(findings(report)[0]?.severity).toBe("low");
	});

	test("flags large iOS frameworks and executables", async () => {
		const ipa = await writeZipFile("app.ipa", {
			"Payload/Demo.app/Info.plist": encodeBplist({
				CFBundleExecutable: "DemoBin",
			}),
			"Payload/Demo.app/DemoBin": new Uint8Array(101 * MiB),
			"Payload/Demo.app/Frameworks/Big.framework/Big": new Uint8Array(31 * MiB),
			"Payload/Demo.app/Frameworks/Small.framework/Small": new Uint8Array(1024),
			"Payload/Demo.app/hero.mp4": new Uint8Array(6 * MiB),
		});
		const report = await runAuditor(mobilePerformance, ipa);
		expect(ruleIds(report)).toEqual([
			"mobile.performance/ios-large-executable",
			"mobile.performance/ios-large-framework",
			"mobile.performance/large-assets",
		]);
		const assets = findings(report).find((f) =>
			f.ruleId.endsWith("/large-assets"),
		);
		expect(assets?.evidence).toContain("hero.mp4");
		expect(assets?.evidence).not.toContain("DemoBin");
		expect(assets?.evidence).not.toContain("Big.framework");
	});

	test("source trees are skipped", async () => {
		const dir = await writeTree({
			"AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b"/>`,
		});
		const report = await runAuditor(mobilePerformance, dir);
		expect(report.results[0]?.status).toBe("skipped");
	});

	test("a DEX above the extraction limit is never inflated", async () => {
		const apk = await writeZipFile("bomb.apk", {
			"classes.dex": new Uint8Array(30 * MiB),
		});
		const report = await runAuditor(mobilePerformance, apk);
		expect(report.results[0]?.status).toBe("passed");
	});
});
