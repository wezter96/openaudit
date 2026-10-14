import type { FindingInput } from "@openaudit/core";

import { baseName, truncate } from "../util";
import type { FileConfig, Setting } from "./config";
import {
	BUN_LIFECYCLE,
	base,
	listNames,
	NPM_IGNORE_SCRIPTS,
	NPM_SCRIPTS,
	PNPM_BUILDS,
	rule,
	SOCKET_INSTALL_SCRIPTS,
	unique,
} from "./findings";
import type { LockedPackage, Lockfile } from "./shared";

/** How the lockfile's package manager gates install scripts. */
interface ScriptPolicy {
	/** Packages known to run install scripts (marked in the lockfile or allow-listed). */
	readonly scripted: ReadonlyArray<LockedPackage>;
	/** Of those, the ones that run without explicit approval. */
	readonly ungated: ReadonlyArray<LockedPackage>;
	/** Sentence describing how scripts are gated. */
	readonly gate: string;
	readonly references: ReadonlyArray<string>;
	/** A setting that lets every package run scripts. */
	readonly allowAll?: Setting;
}

const uniqueByName = (ps: ReadonlyArray<LockedPackage>) => {
	const seen = new Set<string>();
	return ps.filter((p) => !seen.has(p.name) && seen.add(p.name));
};

const scriptPolicy = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
	configs: ReadonlyArray<FileConfig>,
): ScriptPolicy | undefined => {
	const find = <K extends keyof FileConfig>(key: K) =>
		configs.find((c) => c[key] !== undefined)?.[key];
	const marked = uniqueByName(packages.filter((p) => p.installScript));
	const ignore = find("ignoreScripts");
	const byName = new Map(uniqueByName(packages).map((p) => [p.name, p]));
	const listed = (names: ReadonlyArray<string>) =>
		unique(names).map((n) => byName.get(n) ?? { name: n });
	switch (lock.manager) {
		case "npm": {
			const other = find("onlyBuilt") ?? find("trusted");
			const note = other
				? " package.json declares an install-script allow-list for pnpm or Bun, which npm ignores."
				: "";
			return {
				scripted: marked,
				ungated: ignore ? [] : marked,
				gate: ignore
					? `${ignore.file} sets ignore-scripts, so npm runs none of them.`
					: `npm runs every one of them on install because ignore-scripts is not set in the project's .npmrc.${note}`,
				references: [NPM_SCRIPTS, NPM_IGNORE_SCRIPTS, SOCKET_INSTALL_SCRIPTS],
			};
		}
		case "pnpm": {
			const onlyBuilt = find("onlyBuilt");
			const never = new Set(find("neverBuilt") ?? []);
			const allowAll = find("allowAllBuilds");
			const references = [
				PNPM_BUILDS,
				NPM_IGNORE_SCRIPTS,
				SOCKET_INSTALL_SCRIPTS,
			];
			if (ignore)
				return {
					scripted: marked,
					ungated: [],
					gate: `${ignore.file} sets ignore-scripts, so pnpm runs none of them.`,
					references,
				};
			if (allowAll)
				return {
					scripted: marked,
					ungated: marked,
					gate: `${allowAll.file} allows every package to build (${allowAll.evidence}), so pnpm runs every install script.`,
					references,
					allowAll,
				};
			if (onlyBuilt) {
				const allowed = new Set(onlyBuilt);
				return {
					scripted: uniqueByName([
						...marked,
						...listed(onlyBuilt.filter((n) => byName.has(n))),
					]),
					ungated: [],
					gate: `pnpm only runs the scripts of packages in onlyBuiltDependencies: ${listNames(onlyBuilt)}.${marked.some((p) => !allowed.has(p.name)) ? " The others are blocked." : ""}`,
					references,
				};
			}
			return {
				scripted: marked,
				// Lockfiles that record requiresBuild come from pnpm 8 and older,
				// which run every install script unless an allow-list is set.
				ungated: marked.filter((p) => !never.has(p.name)),
				gate: `pnpm 8 and older run them on install because no onlyBuiltDependencies allow-list is configured${never.size ? ` (neverBuiltDependencies excludes ${listNames([...never])})` : ""}.`,
				references,
			};
		}
		case "bun": {
			// Bun enforces package.json's list; bun.lock keeps a copy. Either
			// can be edited on its own, so both are listed.
			const trusted = unique([
				...(lock.trusted ?? []),
				...(find("trusted") ?? []),
			]);
			const wildcard = trusted.find((n) => n.includes("*"));
			return {
				scripted: listed(trusted),
				ungated: [],
				gate: "Bun only runs the lifecycle scripts of packages in trustedDependencies (and of its built-in default allow-list); bun.lock does not record which packages actually have scripts.",
				references: [BUN_LIFECYCLE, SOCKET_INSTALL_SCRIPTS],
				...(wildcard
					? {
							allowAll: {
								file: lock.path,
								evidence: `trustedDependencies: ${wildcard}`,
							},
						}
					: {}),
			};
		}
		default:
			return undefined;
	}
};

export const installScriptFindings = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
	configs: ReadonlyArray<FileConfig>,
): FindingInput[] => {
	const policy = scriptPolicy(lock, packages, configs);
	if (!policy) return [];
	const out: FindingInput[] = [];
	const names = policy.scripted.map((p) => p.name).sort();
	const firstLine = (ps: ReadonlyArray<LockedPackage>) =>
		ps.map((p) => p.line).find((l) => l !== undefined);
	if (names.length) {
		const one = names.length === 1;
		// Bun and pnpm 9+ lockfiles do not mark packages with scripts; only
		// the allow-list says which packages may run them.
		const verb = lock.recordsInstallScripts
			? one
				? "runs"
				: "run"
			: `${one ? "is" : "are"} allowed to run`;
		out.push({
			...base,
			ruleId: rule("install-scripts"),
			title: `${names.length} ${one ? "package" : "packages"} in ${baseName(lock.path)} ${verb} install scripts`,
			severity: "info",
			message: truncate(
				`${listNames(names, 20)} ${verb} code (preinstall, install or postinstall scripts) when dependencies are installed. That is not a vulnerability on its own, but it is the most common way malicious packages execute. ${policy.gate}`,
				1000,
			),
			location: { file: lock.path, line: firstLine(policy.scripted) },
			evidence: truncate(names.join(", ")),
			remediation:
				"Review which dependencies need install scripts and keep the list short: use pnpm's onlyBuiltDependencies, Bun's trustedDependencies, or npm with ignore-scripts=true plus an allow-list such as @lavamoat/allow-scripts.",
			references: policy.references,
			tags: ["install-scripts"],
		});
	}
	const ungated = policy.ungated.map((p) => p.name).sort();
	if (ungated.length || policy.allowAll) {
		const shown = ungated.length ? ungated : ["(every dependency)"];
		const allowAllOnly = policy.allowAll && !ungated.length;
		out.push({
			...base,
			ruleId: rule("ungated-install-scripts"),
			title: ungated.length
				? `${ungated.length} install ${ungated.length === 1 ? "script runs" : "scripts run"} without an allow-list`
				: "Every dependency may run install scripts",
			severity: "low",
			message: truncate(
				`${listNames(shown, 20)} ${shown.length === 1 ? "runs" : "run"} code on install without being approved by an allow-list. ${allowAllOnly ? `${policy.allowAll?.file} allows every package (${policy.allowAll?.evidence}). ` : ""}${policy.gate} A compromised version of any of them runs on every developer machine and CI runner that installs dependencies.`,
				1000,
			),
			location: allowAllOnly
				? { file: policy.allowAll?.file, line: policy.allowAll?.line }
				: { file: lock.path, line: firstLine(policy.ungated) },
			evidence: truncate(
				allowAllOnly ? (policy.allowAll?.evidence ?? "") : ungated.join(", "),
			),
			remediation:
				"Gate install scripts: with npm set ignore-scripts=true in .npmrc and allow the few packages that need them (for example with @lavamoat/allow-scripts); with pnpm list them by name in onlyBuiltDependencies; with Bun in trustedDependencies.",
			references: policy.references,
			tags: ["install-scripts", "owasp-a08"],
		});
	}
	return out;
};
