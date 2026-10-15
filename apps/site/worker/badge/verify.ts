/**
 * Outbound checks: the repo on GitHub, and the verification code in the
 * repo, on the site or in DNS. Every request has a short timeout and a body
 * cap. Only api.github.com may redirect (a renamed repo); anywhere else a
 * redirect fails the check. Repos and sites are validated again before any
 * URL is built from them.
 */
import type { RepoSlug, SiteUrl, VerificationCode } from "@openaudit/badge";
import { type Bytes, readUpTo } from "./bytes";
import { parseRepo, parseSite } from "./input";

/** Repos larger than this (in KB, as GitHub reports size) aren't scanned. */
export const MAX_REPO_KB = 500 * 1024;

const TIMEOUT_MS = 5000;
/** The GitHub API's repo JSON. */
const MAX_JSON: Bytes = 64 * 1024;
/** A verification file or a DNS answer. */
const MAX_PROOF: Bytes = 4 * 1024;
const USER_AGENT = "openaudit-badge (+https://openaudit.se/badge/)";

interface Get {
	readonly url: string;
	readonly accept: string;
	readonly limit: Bytes;
	readonly redirect?: RequestRedirect;
}

const send = (g: Get) =>
	fetch(g.url, {
		headers: { accept: g.accept, "user-agent": USER_AGENT },
		redirect: g.redirect ?? "manual",
		signal: AbortSignal.timeout(TIMEOUT_MS),
	}).catch(() => undefined);

/** The body as text, cut at `limit` bytes. */
const capped = async (res: Response, limit: Bytes) =>
	new TextDecoder().decode((await readUpTo(res.body, limit)).bytes);

/** The 200 response's text, or undefined for anything else. */
const textOf = async (g: Get) => {
	const res = await send(g);
	if (res?.status !== 200) {
		await res?.body?.cancel();
		return undefined;
	}
	return capped(res, g.limit).catch(() => undefined);
};

export type RepoLookup =
	| { readonly kind: "found"; readonly repo: RepoSlug; readonly sizeKb: number }
	| { readonly kind: "missing" }
	| { readonly kind: "unavailable" };

interface GitHubRepo {
	readonly full_name?: unknown;
	readonly private?: unknown;
	readonly size?: unknown;
}

const fromGitHub = (body: GitHubRepo): RepoLookup => {
	if (body.private !== false) return { kind: "missing" };
	const repo = parseRepo(String(body.full_name ?? ""));
	if (!repo) return { kind: "missing" };
	const sizeKb = typeof body.size === "number" ? body.size : 0;
	return { kind: "found", repo, sizeKb };
};

const parseGitHub = (text: string): RepoLookup => {
	try {
		return fromGitHub(JSON.parse(text) as GitHubRepo);
	} catch {
		return { kind: "unavailable" };
	}
};

/** Looks the repo up without auth: public repos only. */
export const lookupRepo = async (input: RepoSlug): Promise<RepoLookup> => {
	const repo = parseRepo(input);
	if (!repo) return { kind: "missing" };
	const res = await send({
		url: `https://api.github.com/repos/${repo}`,
		accept: "application/vnd.github+json",
		limit: MAX_JSON,
		redirect: "follow",
	});
	if (res?.status === 404) return { kind: "missing" };
	const text = res?.ok
		? await capped(res, MAX_JSON).catch(() => undefined)
		: undefined;
	return text === undefined ? { kind: "unavailable" } : parseGitHub(text);
};

/** `.openaudit-badge` on the default branch contains the code. */
export const repoHasCode = async (
	input: RepoSlug,
	code: VerificationCode,
): Promise<boolean> => {
	const repo = parseRepo(input);
	if (!repo) return false;
	const text = await textOf({
		url: `https://raw.githubusercontent.com/${repo}/HEAD/.openaudit-badge`,
		accept: "text/plain",
		limit: MAX_PROOF,
	});
	return text?.includes(code) ?? false;
};

const wellKnownHasCode = async (site: SiteUrl, code: VerificationCode) => {
	const text = await textOf({
		url: new URL("/.well-known/openaudit-badge.txt", site).toString(),
		accept: "text/plain",
		limit: MAX_PROOF,
	});
	return text?.includes(code) ?? false;
};

export const dnsNameOf = (site: SiteUrl) =>
	`_openaudit-badge.${new URL(site).hostname}`;

interface DnsAnswer {
	readonly Answer?: ReadonlyArray<{ readonly data?: unknown }>;
}

const answersOf = (text: string | undefined) => {
	try {
		return (JSON.parse(text ?? "{}") as DnsAnswer).Answer ?? [];
	} catch {
		return [];
	}
};

const dnsHasCode = async (site: SiteUrl, code: VerificationCode) => {
	const text = await textOf({
		url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(dnsNameOf(site))}&type=TXT`,
		accept: "application/dns-json",
		limit: MAX_PROOF,
	});
	return answersOf(text).some((a) => String(a.data ?? "").includes(code));
};

/** The well-known file or the DNS TXT record contains the code. */
export const siteHasCode = async (
	input: SiteUrl,
	code: VerificationCode,
): Promise<boolean> => {
	const site = parseSite(input);
	if (!site) return false;
	return (await wellKnownHasCode(site, code)) || dnsHasCode(site, code);
};
