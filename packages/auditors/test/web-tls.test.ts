import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect } from "effect";

import { parseHtml } from "../src/web/dom";
import type { Page } from "../src/web/page";
import {
	certificateFindings,
	inspectTls,
	mixedContentFindings,
	type TlsInfo,
	tlsAuditor,
} from "../src/web/tls";
import { runAuditor } from "./helpers";
import { badSite } from "./web-server";

const pageOf = (url: string, html: string): Page => ({
	url,
	requestedUrl: url,
	status: 200,
	isHtml: true,
	doc: parseHtml(html),
	links: [],
	response: {
		url,
		status: 200,
		headers: new Headers({ "content-type": "text/html" }),
		cookies: [],
		body: html,
		bytes: html.length,
		redirected: false,
		ttfbMs: 1,
		totalMs: 1,
	},
});

describe("web.tls", () => {
	test("flags active and passive mixed content on https pages", () => {
		const html = `<html><head><script src="http://cdn.example.com/a.js"></script></head>
			<body><img src="http://img.example.com/x.png"><img src="https://ok.example.com/y.png">
			<form action="http://example.com/login"></form></body></html>`;
		const ids = mixedContentFindings(pageOf("https://example.com/", html)).map(
			(f) => f.ruleId,
		);
		expect(ids).toEqual([
			"web.tls/mixed-content-active",
			"web.tls/mixed-content-passive",
			"web.tls/insecure-form-action",
		]);
		expect(mixedContentFindings(pageOf("http://example.com/", html))).toEqual(
			[],
		);
	});

	test("maps certificate problems to findings", () => {
		const now = Date.parse("2026-01-01T00:00:00Z");
		const base: TlsInfo = {
			protocol: "TLSv1.3",
			authorized: true,
			authorizationError: undefined,
			hostnameError: undefined,
			subject: "example.com",
			issuer: "R3",
			validFrom: new Date("2025-10-01T00:00:00Z"),
			validTo: new Date("2026-06-01T00:00:00Z"),
			selfSigned: false,
		};
		expect(certificateFindings("https://example.com/", base, now)).toEqual([]);
		const ids = (over: Partial<TlsInfo>) =>
			certificateFindings(
				"https://example.com/",
				{ ...base, ...over },
				now,
			).map((f) => f.ruleId);
		expect(ids({ validTo: new Date("2025-12-01T00:00:00Z") })).toEqual([
			"web.tls/certificate-expired",
		]);
		expect(ids({ validTo: new Date("2026-01-10T00:00:00Z") })).toEqual([
			"web.tls/certificate-expiring",
		]);
		expect(ids({ hostnameError: "Hostname/IP does not match" })).toEqual([
			"web.tls/certificate-hostname-mismatch",
		]);
		expect(ids({ protocol: "TLSv1.1" })).toEqual(["web.tls/weak-protocol"]);
	});

	describe("against a local TLS server", () => {
		let dir: string;
		let server: ReturnType<typeof Bun.serve> | undefined;
		beforeAll(() => {
			if (!Bun.which("openssl")) return;
			dir = mkdtempSync(join(tmpdir(), "openaudit-tls-"));
			const gen = Bun.spawnSync([
				"openssl",
				"req",
				"-x509",
				"-newkey",
				"rsa:2048",
				"-nodes",
				"-keyout",
				join(dir, "key.pem"),
				"-out",
				join(dir, "cert.pem"),
				"-days",
				"10",
				"-subj",
				"/CN=example.test",
			]);
			if (gen.exitCode !== 0) return;
			server = Bun.serve({
				port: 0,
				hostname: "127.0.0.1",
				tls: {
					cert: readFileSync(join(dir, "cert.pem"), "utf8"),
					key: readFileSync(join(dir, "key.pem"), "utf8"),
				},
				fetch: () => new Response("ok"),
			});
		});
		afterAll(() => {
			server?.stop(true);
			if (dir) rmSync(dir, { recursive: true, force: true });
		});

		test("detects a self-signed, soon-expiring certificate", async () => {
			if (!server) return; // openssl unavailable
			const info = await Effect.runPromise(
				inspectTls("127.0.0.1", server.port as number),
			);
			expect(info.selfSigned).toBe(true);
			expect(info.hostnameError).toBeDefined();
			expect(info.protocol).toMatch(/^TLSv1\.[23]$/);
			const ids = certificateFindings("https://127.0.0.1/", info).map(
				(f) => f.ruleId,
			);
			expect(ids).toContain("web.tls/certificate-self-signed");
			expect(ids).toContain("web.tls/certificate-expiring");

			// connectHost pins the dialled address while SNI/name checks use the hostname.
			const pinned = await Effect.runPromise(
				inspectTls("example.test", server.port as number, {
					connectHost: "127.0.0.1",
				}),
			);
			expect(pinned.subject).toBe("example.test");
			expect(pinned.hostnameError).toBeUndefined();
		});
	});

	test("does not flag plain-HTTP localhost targets", async () => {
		const site = badSite();
		try {
			const report = await runAuditor(tlsAuditor, site.url);
			expect(report.results[0]?.status).toBe("passed");
			expect(report.results[0]?.findings).toEqual([]);
		} finally {
			site.stop();
		}
	});
});
