/** Validation of what people type into the registration form. */
import type { RepoSlug, SiteUrl } from "@openaudit/badge";

/** Raw form input, not yet validated. */
export type Input = string;

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const NAME = /^[A-Za-z0-9._-]{1,100}$/;

/** `owner/name` (a GitHub URL is accepted too), or undefined when invalid. */
export const parseRepo = (input: Input): RepoSlug | undefined => {
	const slug = input
		.trim()
		.replace(/^https:\/\/github\.com\//i, "")
		.replace(/\.git$/i, "")
		.replace(/\/$/, "");
	const [owner = "", name = "", ...rest] = slug.split("/");
	if (rest.length > 0) return undefined;
	if (!OWNER.test(owner) || !NAME.test(name)) return undefined;
	return name === "." || name === ".." ? undefined : `${owner}/${name}`;
};

const PRIVATE_SUFFIXES = [
	".local",
	".internal",
	".lan",
	".localhost",
	".home.arpa",
];

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** A public DNS name: no IP literal, no single label, no private suffix. */
const isPublicHost = (host: string) => {
	if (host.startsWith("[") || IPV4.test(host)) return false;
	if (host.endsWith(".")) return false;
	if (host === "localhost" || !host.includes(".")) return false;
	return !PRIVATE_SUFFIXES.some((suffix) => host.endsWith(suffix));
};

const toUrl = (input: Input) => {
	try {
		return new URL(input.trim());
	} catch {
		return undefined;
	}
};

const isAcceptable = (url: URL) => {
	if (url.protocol !== "https:") return false;
	if (url.username !== "" || url.password !== "") return false;
	return url.port === "" && isPublicHost(url.hostname);
};

/** The site normalised to origin plus path, or undefined when not allowed. */
export const parseSite = (input: Input): SiteUrl | undefined => {
	const url = toUrl(input);
	if (!url || !isAcceptable(url)) return undefined;
	return `${url.origin}${url.pathname}`;
};

/** `owner-name` in lowercase `[a-z0-9-]`. */
export const slugOf = (repo: RepoSlug): string =>
	repo
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.slice(0, 150)
		.replace(/^-+|-+$/g, "");
