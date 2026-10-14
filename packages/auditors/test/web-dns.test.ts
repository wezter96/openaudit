import { describe, expect, test } from "bun:test";

import {
	countSpfLookups,
	domainScope,
	type MxRecord,
	makeDnsAuditor,
	matchesTakeoverFingerprint,
	parseMtaSts,
	type Resolver,
	spfAllQualifier,
	takeoverServiceFor,
} from "../src/web/dns";
import { ruleIds, runAuditor } from "./helpers";

interface Zone {
	txt?: Record<string, string[]>;
	mx?: Record<string, MxRecord[]>;
	caa?: Record<string, number>;
	cname?: Record<string, string>;
	missing?: Set<string>;
	failing?: Set<string>;
}

const fakeResolver = (zone: Zone): Resolver => {
	const check = (name: string) => {
		if (zone.failing?.has(name)) throw new Error("SERVFAIL");
	};
	return {
		resolveTxt: async (n) => {
			check(n);
			return zone.txt?.[n] ?? [];
		},
		resolveMx: async (n) => {
			check(n);
			return zone.mx?.[n] ?? [];
		},
		resolveCaa: async (n) => {
			check(n);
			return zone.caa?.[n] ?? 0;
		},
		resolveCname: async (n) => zone.cname?.[n],
		nameExists: async (n) => !zone.missing?.has(n),
	};
};

const mail = [{ exchange: "mx.example.test", priority: 10 }];
const run = (zone: Zone, url = "https://example.test/") =>
	runAuditor(makeDnsAuditor(fakeResolver(zone)), url);
const rules = async (zone: Zone, url?: string) => ruleIds(await run(zone, url));

describe("web.dns helpers", () => {
	test("registrable domain heuristic", () => {
		expect(domainScope("www.example.com")).toMatchObject({
			kind: "domain",
			domain: "example.com",
		});
		expect(domainScope("a.b.bbc.co.uk")).toMatchObject({
			kind: "domain",
			domain: "bbc.co.uk",
		});
		expect(domainScope("my-app.herokuapp.com").kind).toBe("shared");
		expect(domainScope("127.0.0.1").kind).toBe("none");
		expect(domainScope("localhost").kind).toBe("none");
		expect(domainScope("intranet").kind).toBe("none");
	});

	test("SPF qualifier and lookup counting", async () => {
		expect(spfAllQualifier("v=spf1 include:a.test -all")).toBe("-");
		expect(spfAllQualifier("v=spf1 all")).toBe("+");
		expect(spfAllQualifier("v=spf1 mx ?all")).toBe("?");
		expect(spfAllQualifier("v=spf1 mx")).toBeUndefined();
		const r = fakeResolver({
			txt: {
				"a.test": ["v=spf1 mx a include:b.test -all"],
				"b.test": ["v=spf1 ip4:1.2.3.4 exists:%{i}.x -all"],
			},
		});
		const counted = await countSpfLookups(r, "v=spf1 include:a.test ptr -all");
		expect(counted).toEqual({ count: 6, complete: true });
	});

	test("MTA-STS policy parsing", () => {
		const p = parseMtaSts(
			"version: STSv1\r\nmode: enforce\r\nmx: a.test\r\nmx: b.test\r\nmax_age: 86400\r\n",
		);
		expect(p.get("mode")).toEqual(["enforce"]);
		expect(p.get("mx")).toEqual(["a.test", "b.test"]);
	});

	test("takeover fingerprints are matched per service", () => {
		const heroku = takeoverServiceFor("foo.herokuapp.com.");
		expect(heroku?.name).toBe("Heroku");
		expect(takeoverServiceFor("bucket.s3.eu-west-1.amazonaws.com")?.name).toBe(
			"AWS S3",
		);
		expect(
			takeoverServiceFor("bucket.s3-website-us-east-1.amazonaws.com")?.name,
		).toBe("AWS S3");
		expect(takeoverServiceFor("d111.cloudfront.net")).toBeUndefined();
		expect(takeoverServiceFor("evilgithub.io.example.com")).toBeUndefined();
		if (!heroku) throw new Error("unreachable");
		expect(
			matchesTakeoverFingerprint(heroku, {
				status: 404,
				body: "<title>No such app</title>",
			}),
		).toBe(true);
		// A normal 200 page, or a different 404, is not a takeover.
		expect(
			matchesTakeoverFingerprint(heroku, { status: 200, body: "No such app" }),
		).toBe(false);
		expect(
			matchesTakeoverFingerprint(heroku, { status: 404, body: "Not found" }),
		).toBe(false);
		const azure = takeoverServiceFor("x.azurewebsites.net");
		expect(
			azure && matchesTakeoverFingerprint(azure, { status: 404, body: "" }),
		).toBe(false);
	});
});

describe("web.dns auditor", () => {
	test("mail domain with nothing configured", async () => {
		const report = await run({ mx: { "example.test": mail }, caa: {} });
		const f = report.results[0]?.findings ?? [];
		const byRule = (id: string) => f.find((x) => x.ruleId === id);
		expect(byRule("web.dns/spf-missing")?.severity).toBe("medium");
		expect(byRule("web.dns/dmarc-missing")?.severity).toBe("medium");
		expect(byRule("web.dns/caa-missing")?.severity).toBe("low");
		expect(byRule("web.dns/mta-sts-missing")).toBeDefined();
		expect(byRule("web.dns/tls-rpt-missing")?.severity).toBe("info");
	});

	test("well-configured mail domain is clean", async () => {
		const ids = await rules({
			mx: { "example.test": mail },
			txt: {
				"example.test": ["v=spf1 include:_spf.mail.test -all"],
				"_dmarc.example.test": [
					"v=DMARC1; p=reject; rua=mailto:d@example.test",
				],
				"_smtp._tls.example.test": ["v=TLSRPTv1; rua=mailto:t@example.test"],
			},
			caa: { "example.test": 1 },
			// MTA-STS TXT absent -> only that low note.
		});
		expect(ids).toEqual(["web.dns/mta-sts-missing"]);
	});

	test("weak SPF and DMARC settings", async () => {
		const ids = await rules({
			mx: { "example.test": mail },
			txt: {
				"example.test": ["v=spf1 +all", "v=spf1 -all"],
				"_dmarc.example.test": ["v=DMARC1; p=none; pct=50"],
			},
			caa: { "example.test": 1 },
		});
		for (const id of [
			"web.dns/spf-multiple-records",
			"web.dns/spf-allow-all",
			"web.dns/dmarc-policy-none",
			"web.dns/dmarc-pct-partial",
			"web.dns/dmarc-no-rua",
		])
			expect(ids).toContain(id);
	});

	test("too many SPF lookups", async () => {
		const includes = Array.from(
			{ length: 11 },
			(_, i) => `include:i${i}.test`,
		).join(" ");
		const ids = await rules({
			mx: { "example.test": mail },
			txt: { "example.test": [`v=spf1 ${includes} -all`] },
			caa: { "example.test": 1 },
		});
		expect(ids).toContain("web.dns/spf-too-many-lookups");
	});

	test("domain without MX is not nagged as a mail domain", async () => {
		const ids = await rules({ caa: { "example.test": 1 } });
		expect(ids).not.toContain("web.dns/spf-missing");
		expect(ids).toContain("web.dns/no-mail-not-locked-down");
		expect(ids).toContain("web.dns/dmarc-missing");
		const report = await run({ caa: { "example.test": 1 } });
		expect(
			report.results[0]?.findings.find(
				(f) => f.ruleId === "web.dns/dmarc-missing",
			)?.severity,
		).toBe("info");
		// Null MX plus -all is the recommended lockdown.
		const locked = await rules({
			mx: { "example.test": [{ exchange: "", priority: 0 }] },
			txt: {
				"example.test": ["v=spf1 -all"],
				"_dmarc.example.test": [
					"v=DMARC1; p=reject; rua=mailto:a@example.test",
				],
			},
			caa: { "example.test": 1 },
		});
		expect(locked).toEqual([]);
	});

	test("lookup failures produce no findings instead of false positives", async () => {
		const ids = await rules({
			failing: new Set([
				"example.test",
				"_dmarc.example.test",
				"_mta-sts.example.test",
				"_smtp._tls.example.test",
			]),
		});
		expect(ids).toEqual([]);
	});

	test("CAA is inherited from the registrable domain", async () => {
		const ids = await rules(
			{
				mx: { "example.test": [{ exchange: "", priority: 0 }] },
				txt: {
					"example.test": ["v=spf1 -all"],
					"_dmarc.example.test": ["v=DMARC1; p=reject; rua=mailto:a@x.test"],
				},
				caa: { "example.test": 2 },
			},
			"https://www.example.test/",
		);
		expect(ids).toEqual([]);
	});

	test("dangling CNAME to a released Azure resource", async () => {
		const zone: Zone = {
			mx: { "example.test": [{ exchange: "", priority: 0 }] },
			txt: {
				"example.test": ["v=spf1 -all"],
				"_dmarc.example.test": ["v=DMARC1; p=reject; rua=mailto:a@x.test"],
			},
			caa: { "example.test": 1 },
			cname: { "old.example.test": "gone.azurewebsites.net" },
			missing: new Set(["gone.azurewebsites.net"]),
		};
		const report = await run(zone, "https://old.example.test/");
		const f = report.results[0]?.findings ?? [];
		expect(f.map((x) => x.ruleId)).toEqual(["web.dns/dangling-cname"]);
		expect(f[0]?.severity).toBe("high");
		expect(f[0]?.confidence).toBe("medium");
		expect(f[0]?.evidence).toBe("old.example.test → gone.azurewebsites.net");
		// Still resolving: not a takeover.
		zone.missing = new Set();
		expect(await rules(zone, "https://old.example.test/")).toEqual([]);
	});

	test("shared hosting hostnames only get the takeover check", async () => {
		const ids = await rules({}, "https://someone.github.io/");
		expect(ids).toEqual([]);
	});

	test("a domain that does not exist errors instead of reporting missing records", async () => {
		// openaudt.se (a typo of openaudit.se) has no records at all: every
		// lookup answers NXDOMAIN, which used to read as "no CAA, no SPF".
		const report = await run(
			{ missing: new Set(["openaudt.se"]) },
			"https://openaudt.se/",
		);
		const result = report.results[0];
		expect(result?.status).toBe("error");
		expect(result?.findings).toEqual([]);
		expect(result?.message).toContain("NXDOMAIN");
		// A missing host under a real domain still gets the domain's checks.
		const sub = await rules(
			{ missing: new Set(["typo.example.test"]), caa: {} },
			"https://typo.example.test/",
		);
		expect(sub).toContain("web.dns/caa-missing");
	});

	test("an unknown existence answer does not block the checks", async () => {
		const resolver = fakeResolver({});
		const auditor = makeDnsAuditor({
			...resolver,
			nameExists: async () => {
				throw new Error("SERVFAIL");
			},
		});
		const report = await runAuditor(auditor, "https://example.test/");
		expect(ruleIds(report)).toContain("web.dns/caa-missing");
	});

	test("skipped offline and for non-DNS targets", async () => {
		const auditor = makeDnsAuditor(fakeResolver({}));
		const offline = await runAuditor(auditor, "https://example.test/", {
			offline: true,
		});
		expect(offline.results[0]?.status).toBe("skipped");
		const local = await runAuditor(auditor, "http://127.0.0.1:9/");
		expect(local.results[0]?.status).toBe("skipped");
	});
});
