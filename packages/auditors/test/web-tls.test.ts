import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as nodeTls from "node:tls";
import { Exec, Http, type Report, runAudit, Workspaces } from "@openaudit/core";
import { Effect, Layer } from "effect";

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

/**
 * A TLS server on 127.0.0.1 that answers anything with a tiny page. It joins
 * `servers` before it starts listening, so it is closed even if that fails.
 */
const listenTls = (servers: nodeTls.Server[], options: nodeTls.TlsOptions) =>
	new Promise<nodeTls.Server>((resolve) => {
		const server = nodeTls.createServer(options, (socket) => {
			socket.on("error", () => {});
			socket.end(
				"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 2\r\n\r\nok",
			);
		});
		server.on("tlsClientError", () => {});
		servers.push(server);
		server.listen(0, "127.0.0.1", () => resolve(server));
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

	test("tags protocol weaknesses as broken crypto, not certificate validation", () => {
		const info: TlsInfo = {
			protocol: "TLSv1",
			authorized: false,
			authorizationError: "CERT_HAS_EXPIRED",
			hostnameError: undefined,
			subject: "example.com",
			issuer: "R3",
			validFrom: new Date("2020-01-01T00:00:00Z"),
			validTo: new Date("2020-02-01T00:00:00Z"),
			selfSigned: false,
		};
		const tags = Object.fromEntries(
			certificateFindings("https://example.com/", info).map((f) => [
				f.ruleId,
				f.tags,
			]),
		);
		expect(tags["web.tls/weak-protocol"]).toEqual(["cwe-327", "owasp-a02"]);
		expect(tags["web.tls/certificate-expired"]).toEqual([
			"cwe-295",
			"owasp-a02",
		]);
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

	/*
	 * A bad certificate or a legacy-only server makes the page fetch fail, and
	 * those are the hosts the TLS checks exist for. The servers listen on
	 * 127.0.0.1 but are audited as example.test (loopback targets skip the TLS
	 * probe): the probe dials them through `connectHost`, and page requests
	 * are routed to them by rewriting the host, so fetch fails for real.
	 */
	describe("when the page fetch fails on TLS", () => {
		let dir: string | undefined;
		const servers: nodeTls.Server[] = [];
		const ports: Record<string, number> = {};

		const cert = (name: string, ...validity: string[]) =>
			Bun.spawnSync([
				"openssl",
				"req",
				"-x509",
				"-newkey",
				"rsa:2048",
				"-nodes",
				"-keyout",
				join(dir ?? "", `${name}.key`),
				"-out",
				join(dir ?? "", `${name}.pem`),
				"-subj",
				"/CN=example.test",
				"-addext",
				"subjectAltName=DNS:example.test",
				...validity,
			]).exitCode === 0;
		const listen = async (
			name: string,
			certName: string,
			options: nodeTls.TlsOptions = {},
		) => {
			const server = await listenTls(servers, {
				cert: readFileSync(join(dir ?? "", `${certName}.pem`)),
				key: readFileSync(join(dir ?? "", `${certName}.key`)),
				...options,
			});
			ports[name] = (server.address() as AddressInfo).port;
		};

		beforeAll(async () => {
			if (!Bun.which("openssl")) return;
			dir = mkdtempSync(join(tmpdir(), "openaudit-tls-"));
			if (cert("current", "-days", "90"))
				await listen("legacy", "current", {
					minVersion: "TLSv1",
					maxVersion: "TLSv1.1",
				});
			// `-not_before`/`-not_after` need OpenSSL 3.4+.
			if (
				cert(
					"expired",
					"-not_before",
					"20200101000000Z",
					"-not_after",
					"20200201000000Z",
				)
			)
				await listen("expired", "expired");
		});
		afterAll(() => {
			for (const server of servers) server.close();
			if (dir) rmSync(dir, { recursive: true, force: true });
		});

		const requested: string[] = [];
		const audit = (port: number): Promise<Report> =>
			Effect.runPromise(
				Effect.gen(function* () {
					const real = yield* Http;
					return yield* runAudit({
						target: `https://example.test:${port}/`,
						auditors: [tlsAuditor],
						options: { settings: { "web.tls": { connectHost: "127.0.0.1" } } },
						selection: { only: [tlsAuditor.id] },
					}).pipe(
						Effect.provide(
							Layer.mergeAll(
								Workspaces.layer,
								Exec.layer,
								Layer.succeed(Http, {
									request: (url, init) => {
										requested.push(url);
										return real.request(
											url.replace("//example.test:", "//127.0.0.1:"),
											init,
										);
									},
								}),
							),
						),
					);
				}).pipe(Effect.provide(Http.layer)),
			);

		test("still reports an expired certificate", async () => {
			const port = ports.expired;
			if (port === undefined) return; // openssl too old or missing
			const result = (await audit(port)).results[0];
			expect(result?.status).toBe("failed");
			const by = Object.fromEntries(
				(result?.findings ?? []).map((f) => [f.ruleId, f]),
			);
			expect(by["web.tls/certificate-expired"]?.severity).toBe("critical");
			expect(by["web.tls/certificate-self-signed"]).toBeDefined();
			// Located at the TLS endpoint that was probed.
			expect(by["web.tls/certificate-expired"]?.location).toEqual({
				url: `https://example.test:${port}/`,
			});
			// http://host:port on a TLS port is not the site's HTTP counterpart.
			expect(requested).not.toContain(`http://example.test:${port}/`);
		});

		test("still reports a legacy-only server", async () => {
			const port = ports.legacy;
			if (port === undefined) return;
			const result = (await audit(port)).results[0];
			expect(result?.status).toBe("failed");
			const weak = result?.findings.find(
				(f) => f.ruleId === "web.tls/weak-protocol",
			);
			expect(weak?.evidence).toContain("protocol=TLSv1.1");
			expect(weak?.tags).toContain("cwe-327");
		});

		test("reports the fetch error when no TLS check could run", async () => {
			if (!dir) return;
			// Nothing listens on this port: neither the page nor the handshake works.
			const closed = nodeTls.createServer({});
			const port = await new Promise<number>((resolve) =>
				closed.listen(0, "127.0.0.1", () =>
					resolve((closed.address() as AddressInfo).port),
				),
			);
			await new Promise((resolve) => closed.close(resolve));
			const result = (await audit(port)).results[0];
			expect(result?.status).toBe("error");
			expect(result?.findings).toEqual([]);
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
