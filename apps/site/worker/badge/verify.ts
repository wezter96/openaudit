/**
 * Outbound checks: the repo on GitHub, and the verification code in the
 * repo, on the site or in DNS. Responses are read with a size cap.
 */
import type { RepoSlug, SiteUrl, VerificationCode } from "@openaudit/badge";
import { readUpTo } from "./bytes";

/** Repos larger than this (in KB, as GitHub reports size) aren't scanned. */
export const MAX_REPO_KB = 500 * 1024;

const TIMEOUT_MS = 8000;
const MAX_TEXT = 64 * 1024;
const USER_AGENT = "openaudit-badge (+https://openaudit.se/badge/)";

const get = (url: string, accept: string) =>
	fetch(url, {
		headers: { accept, "user-agent": USER_AGENT },
		redirect: "follow",
		signal: AbortSignal.timeout(TIMEOUT_MS),
	}).catch(() => undefined);

/** The body as text, cut at MAX_TEXT bytes. */
const capped = async (res: Response) =>
	new TextDecoder().decode((await readUpTo(res.body, MAX_TEXT)).bytes);

const textOf = async (url: string, accept: string) => {
	const res = await get(url, accept);
	if (!res?.ok) {
		await res?.body?.cancel();
		return undefined;
	}
	return capped(res).catch(() => undefined);
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
	if (body.private !== false || typeof body.full_name !== "string")
		return { kind: "missing" };
	const sizeKb = typeof body.size === "number" ? body.size : 0;
	return { kind: "found", repo: body.full_name, sizeKb };
};

/** Looks the repo up without auth: public repos only. */
export const lookupRepo = async (repo: RepoSlug): Promise<RepoLookup> => {
	const res = await get(
		`https://api.github.com/repos/${repo}`,
		"application/vnd.github+json",
	);
	if (res?.status === 404) return { kind: "missing" };
	const text = res?.ok ? await capped(res).catch(() => undefined) : undefined;
	if (text === undefined) return { kind: "unavailable" };
	try {
		return fromGitHub(JSON.parse(text) as GitHubRepo);
	} catch {
		return { kind: "unavailable" };
	}
};

/** `.openaudit-badge` on the default branch contains the code. */
export const repoHasCode = async (
	repo: RepoSlug,
	code: VerificationCode,
): Promise<boolean> =>
	(
		await textOf(
			`https://raw.githubusercontent.com/${repo}/HEAD/.openaudit-badge`,
			"text/plain",
		)
	)?.includes(code) ?? false;

const wellKnownHasCode = async (site: SiteUrl, code: VerificationCode) =>
	(
		await textOf(
			new URL("/.well-known/openaudit-badge.txt", site).toString(),
			"text/plain",
		)
	)?.includes(code) ?? false;

export const dnsNameOf = (site: SiteUrl) =>
	`_openaudit-badge.${new URL(site).hostname}`;

interface DnsAnswer {
	readonly Answer?: ReadonlyArray<{ readonly data?: unknown }>;
}

const dnsHasCode = async (site: SiteUrl, code: VerificationCode) => {
	const name = dnsNameOf(site);
	const text = await textOf(
		`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
		"application/dns-json",
	);
	try {
		const answers = (JSON.parse(text ?? "{}") as DnsAnswer).Answer ?? [];
		return answers.some((a) => String(a.data ?? "").includes(code));
	} catch {
		return false;
	}
};

/** The well-known file or the DNS TXT record contains the code. */
export const siteHasCode = async (
	site: SiteUrl,
	code: VerificationCode,
): Promise<boolean> =>
	(await wellKnownHasCode(site, code)) || dnsHasCode(site, code);
