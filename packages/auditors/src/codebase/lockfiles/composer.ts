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

/** composer.json `repositories` and `config.secure-http`. */
export const composerJsonFindings = (file: SourceFile): FindingInput[] => {
	const json = parseJson(file.text);
	if (!isRecord(json))
		return [unparsedConfigFinding(file.path, "is not a JSON object")];
	const lineOf = lineFinder(file.text);
	const out: FindingInput[] = [];
	const repos = Array.isArray(json.repositories)
		? json.repositories
		: isRecord(json.repositories)
			? Object.values(json.repositories)
			: [];
	for (const repo of repos) {
		if (!isRecord(repo)) continue;
		const type = (str(repo.type) ?? "").toLowerCase();
		const url = str(repo.url);
		if (!url) continue;
		const line = lineOf(`"${url}"`);
		const evidence = `${type}: ${displayUrl(url)}`;
		if (isInsecureUrl(url))
			out.push(
				insecureFinding(
					file.path,
					line,
					`The ${type} repository ${displayUrl(url)}`,
					evidence,
				),
			);
		else if (type === "path" && escapesRoot(dirOf(file.path), url))
			out.push(
				pathFinding(
					file.path,
					line,
					`The path repository ${truncate(url, 60)}`,
					`path: ${truncate(url, 120)}`,
				),
			);
		else if (GIT_REPOSITORY_TYPES.has(type))
			out.push(
				gitFinding(
					file.path,
					line,
					`The ${type} repository ${displayUrl(url)}`,
					evidence,
					true,
					`${displayUrl(url)} (composer.lock pins the commit)`,
					gitHost(url),
				),
			);
	}
	if (isRecord(json.config) && json.config["secure-http"] === false)
		out.push({
			...insecureFinding(
				file.path,
				lineOf('"secure-http"'),
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
	return out.map((f) => ({
		...f,
		references: [...(f.references ?? []), COMPOSER_REPOS],
	}));
};

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
	const out: FindingInput[] = [];
	const list = [
		...(Array.isArray(json.packages) ? json.packages : []),
		...(Array.isArray(json["packages-dev"]) ? json["packages-dev"] : []),
	];
	for (const p of list) {
		if (!isRecord(p)) continue;
		const name = str(p.name) ?? "a package";
		for (const field of ["dist", "source"] as const) {
			const url = isRecord(p[field])
				? str((p[field] as Record<string, unknown>).url)
				: undefined;
			if (url && isInsecureUrl(url))
				out.push(
					insecureFinding(
						file.path,
						lineOf(url),
						name,
						`${name}: ${displayUrl(url)}`,
					),
				);
		}
	}
	return capPerRule(out);
};
