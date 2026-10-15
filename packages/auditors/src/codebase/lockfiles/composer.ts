import type { FindingInput } from "@openaudit/core";

import { cweUrl, isRecord, type SourceFile, truncate } from "../util";
import {
	COMPOSER_CONFIG,
	COMPOSER_REPOS,
	capPerRule,
	gitFinding,
	insecureFinding,
	pathFinding,
	uncheckedFinding,
	unparsedConfigFinding,
} from "./findings";
import { dirOf, lineFinder, parseJson, str } from "./shared";
import { displayUrl, escapesRoot, gitHost, isInsecureUrl } from "./sources";

const GIT_REPOSITORY_TYPES = new Set([
	"vcs",
	"git",
	"github",
	"gitlab",
	"bitbucket",
	"hg",
	"svn",
	"fossil",
	"perforce",
]);

/** composer.json `repositories`, as a list or keyed by name. */
const repositoryList = (repositories: unknown): unknown[] => {
	if (Array.isArray(repositories)) return repositories;
	return isRecord(repositories) ? Object.values(repositories) : [];
};

/** The finding for one composer.json repository, if it has a problem. */
const repositoryFinding = (
	file: SourceFile,
	lineOf: (needle: string) => number | undefined,
	repo: Record<string, unknown>,
): FindingInput | undefined => {
	const type = (str(repo.type) ?? "").toLowerCase();
	const url = str(repo.url);
	if (!url) return undefined;
	const site = { file: file.path, line: lineOf(`"${url}"`) };
	const evidence = `${type}: ${displayUrl(url)}`;
	if (isInsecureUrl(url))
		return insecureFinding(
			site,
			`The ${type} repository ${displayUrl(url)}`,
			evidence,
		);
	if (type === "path" && escapesRoot(dirOf(file.path), url))
		return pathFinding(
			site,
			`The path repository ${truncate(url, 60)}`,
			`path: ${truncate(url, 120)}`,
		);
	if (GIT_REPOSITORY_TYPES.has(type))
		return gitFinding(
			site,
			`The ${type} repository ${displayUrl(url)}`,
			evidence,
			{
				pinned: true,
				how: `${displayUrl(url)} (composer.lock pins the commit)`,
				host: gitHost(url),
			},
		);
	return undefined;
};

const secureHttpFinding = (
	file: SourceFile,
	line: number | undefined,
): FindingInput => ({
	...insecureFinding(
		{ file: file.path, line },
		"Composer",
		"secure-http: false",
		"medium",
	),
	title: "Composer is allowed to download over plain HTTP",
	message:
		"config.secure-http is false, so Composer accepts http:// repository and package URLs, which anyone on the network path can tamper with.",
	remediation:
		"Remove secure-http: false and serve every repository over https://.",
	references: [COMPOSER_CONFIG, cweUrl(319)],
});

/** composer.json `repositories` and `config.secure-http`. */
export const composerJsonFindings = (file: SourceFile): FindingInput[] => {
	const json = parseJson(file.text);
	if (!isRecord(json))
		return [unparsedConfigFinding(file.path, "is not a JSON object")];
	const lineOf = lineFinder(file.text);
	const out = repositoryList(json.repositories)
		.filter(isRecord)
		.map((repo) => repositoryFinding(file, lineOf, repo))
		.filter((f) => f !== undefined);
	if (isRecord(json.config) && json.config["secure-http"] === false)
		out.push(secureHttpFinding(file, lineOf('"secure-http"')));
	return out.map((f) => ({
		...f,
		references: [...(f.references ?? []), COMPOSER_REPOS],
	}));
};

/** The `dist` and `source` URLs of a composer.lock package. */
const packageUrls = (p: Record<string, unknown>): string[] =>
	(["dist", "source"] as const).flatMap((field) => {
		const download = p[field];
		const url = isRecord(download) ? str(download.url) : undefined;
		return url ? [url] : [];
	});

/** composer.lock `dist`/`source` URLs over plain HTTP. */
export const composerLockFindings = (file: SourceFile): FindingInput[] => {
	const json = parseJson(file.text);
	if (!isRecord(json))
		return [
			uncheckedFinding(
				"unparseable-lockfile",
				file.path,
				`${file.path} could not be parsed.`,
			),
		];
	const lineOf = lineFinder(file.text);
	const list = [
		...(Array.isArray(json.packages) ? json.packages : []),
		...(Array.isArray(json["packages-dev"]) ? json["packages-dev"] : []),
	];
	const out = list.filter(isRecord).flatMap((p) => {
		const name = str(p.name) ?? "a package";
		return packageUrls(p)
			.filter(isInsecureUrl)
			.map((url) =>
				insecureFinding(
					{ file: file.path, line: lineOf(url) },
					name,
					`${name}: ${displayUrl(url)}`,
				),
			);
	});
	return capPerRule(out);
};
