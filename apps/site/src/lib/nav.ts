/**
 * The site's top-level navigation. Plain data with no Astro imports, so the
 * build scripts can put the same links on the pages copied in from the CLI.
 */
export const REPO = "https://github.com/wezter96/openaudit";

export const NAV = [
	{ href: "/", label: "Home" },
	{ href: "/docs/", label: "Docs" },
	{ href: "/auditors/", label: "Auditors" },
	{ href: "/report/", label: "Live report" },
	{ href: "/architecture/", label: "Architecture" },
] as const;
