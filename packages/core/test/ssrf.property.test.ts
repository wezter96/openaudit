/**
 * Property-based tests for the SSRF guard: whole address ranges, not a few
 * hand-picked examples, must be refused, however the address is written.
 */
import { describe, expect, test } from "bun:test";
import fc from "fast-check";

import { isPrivateAddress, isPrivateIPv4, parseIPv4 } from "../src/ssrf";

const octet = fc.integer({ min: 0, max: 255 });
const quad = fc.tuple(octet, octet, octet, octet);
const dotted = ([a, b, c, d]: readonly number[]) => `${a}.${b}.${c}.${d}`;

/** Addresses inside `first.second…` with the given number of fixed leading bits. */
const inRange = (prefix: readonly number[], bits: number) =>
	quad.map(([a, b, c, d]) => {
		const ip = [a, b, c, d].map((x, i) => {
			const fixed = Math.min(8, Math.max(0, bits - i * 8));
			const mask = (0xff << (8 - fixed)) & 0xff;
			return ((prefix[i] ?? 0) & mask) | (x & ~mask & 0xff);
		});
		return dotted(ip);
	});

const PRIVATE: ReadonlyArray<[readonly number[], number]> = [
	[[10], 8],
	[[127], 8],
	[[100, 64], 10],
	[[169, 254], 16],
	[[172, 16], 12],
	[[192, 168], 16],
	[[0], 8],
	[[224], 4],
	[[240], 4],
];

describe("SSRF guard properties", () => {
	test("parseIPv4 reads every dotted quad back as the same number", () => {
		fc.assert(
			fc.property(quad, (q) => {
				const [a, b, c, d] = q;
				expect(parseIPv4(dotted(q))).toBe(((a * 256 + b) * 256 + c) * 256 + d);
			}),
		);
	});

	test("parseIPv4 refuses an octet above 255", () => {
		fc.assert(
			fc.property(quad, fc.integer({ min: 256, max: 99_999 }), (q, big) => {
				expect(parseIPv4(dotted([big, ...q.slice(1)]))).toBeUndefined();
			}),
		);
	});

	for (const [prefix, bits] of PRIVATE)
		test(`every address in ${dotted([...prefix, 0, 0, 0].slice(0, 4))}/${bits} is refused`, () => {
			fc.assert(
				fc.property(inRange(prefix, bits), (ip) => {
					expect(isPrivateAddress(ip)).toBe(true);
					expect(isPrivateAddress(`::ffff:${ip}`)).toBe(true);
				}),
			);
		});

	test("an IPv4 address and its IPv4-mapped IPv6 form get the same verdict", () => {
		fc.assert(
			fc.property(quad, (q) => {
				const ip = dotted(q);
				const verdict = isPrivateIPv4(parseIPv4(ip) as number);
				expect(isPrivateAddress(ip)).toBe(verdict);
				expect(isPrivateAddress(`::ffff:${ip}`)).toBe(verdict);
			}),
		);
	});
});
