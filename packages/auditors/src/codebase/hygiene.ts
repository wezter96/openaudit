import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
} from "@openaudit/core";
import { Effect } from "effect";

type Files = ReadonlyArray<string>;

interface FileCheck {
	/** True when the repository lacks what the finding asks for. */
	readonly missing: (files: Files) => boolean;
	readonly finding: FindingInput;
}

const has = (files: Files, re: RegExp) => files.some((f) => re.test(f));
const lacks = (re: RegExp) => (files: Files) => !has(files, re);

const LOCKFILE =
	/^(bun\.lockb?|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/;
const CI_CONFIG =
	/^\.github\/workflows\/.+\.ya?ml$|^\.gitlab-ci\.yml$|^\.circleci\/|^azure-pipelines\.yml$|^Jenkinsfile$|^bitbucket-pipelines\.yml$/;

/** Checks that run before the .gitignore ones, in report order. */
const DOC_CHECKS: ReadonlyArray<FileCheck> = [
	{
		missing: lacks(/^readme(\.\w+)?$/i),
		finding: {
			ruleId: "code.hygiene/readme-missing",
			title: "README is missing",
			severity: "low",
			category: "maintainability",
			message: "The repository has no README at its root.",
			remediation: "Add a README.md describing purpose, setup and usage.",
		},
	},
	{
		missing: lacks(/^(licen[cs]e|copying)(\.\w+)?$/i),
		finding: {
			ruleId: "code.hygiene/license-missing",
			title: "LICENSE is missing",
			severity: "low",
			category: "compliance",
			message: "No LICENSE file found; others cannot legally reuse the code.",
			remediation: "Add a LICENSE file (e.g. MIT, Apache-2.0).",
			references: ["https://choosealicense.com/"],
		},
	},
	{
		missing: lacks(/^(\.github\/)?security\.md$/i),
		finding: {
			ruleId: "code.hygiene/security-policy-missing",
			title: "No security policy",
			severity: "info",
			category: "security",
			message:
				"No SECURITY.md telling researchers how to report vulnerabilities.",
			remediation: "Add SECURITY.md with a contact and disclosure process.",
			references: [
				"https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
			],
		},
	},
];

/** Checks that run after the .gitignore ones, in report order. */
const BUILD_CHECKS: ReadonlyArray<FileCheck> = [
	{
		missing: (files) => files.includes("package.json") && !has(files, LOCKFILE),
		finding: {
			ruleId: "code.hygiene/lockfile-missing",
			title: "No dependency lockfile",
			severity: "medium",
			category: "supply-chain",
			message:
				"package.json exists but no lockfile is committed, so installs are not reproducible.",
			remediation: "Commit the lockfile produced by your package manager.",
			location: { file: "package.json" },
		},
	},
	{
		missing: lacks(CI_CONFIG),
		finding: {
			ruleId: "code.hygiene/ci-missing",
			title: "No CI configuration",
			severity: "info",
			category: "reliability",
			message: "No continuous-integration configuration was found.",
			remediation: "Run tests, linting and `openaudit --fail-on high` in CI.",
		},
	},
];

const failing = (files: Files, checks: ReadonlyArray<FileCheck>) =>
	checks.filter((c) => c.missing(files)).map((c) => ({ ...c.finding }));

const ignoresEnv = (gitignore: string) =>
	/^\s*\/?\.env/m.test(gitignore) || /^\s*\*\.env/m.test(gitignore);

const gitignoreFindings = (gitignore: string | undefined): FindingInput[] => {
	if (gitignore === undefined)
		return [
			{
				ruleId: "code.hygiene/gitignore-missing",
				title: ".gitignore is missing",
				severity: "medium",
				category: "security",
				message:
					"Without a .gitignore, secrets and build output are easily committed.",
				remediation:
					"Add a .gitignore that excludes .env files, dependencies and build output.",
				location: { file: ".gitignore" },
			},
		];
	if (ignoresEnv(gitignore)) return [];
	return [
		{
			ruleId: "code.hygiene/env-not-ignored",
			title: ".env files are not git-ignored",
			severity: "medium",
			category: "security",
			message:
				".gitignore does not exclude .env files, which commonly hold secrets.",
			remediation: "Add `.env` and `.env*.local` to .gitignore.",
			location: { file: ".gitignore" },
		},
	];
};

/** Repository essentials: docs, licence, security policy, ignore rules, CI, lockfile. */
export const hygiene = defineAuditor({
	id: "code.hygiene",
	title: "Repository hygiene",
	description:
		"Checks for README, LICENSE, SECURITY.md, .gitignore coverage of secrets, lockfiles and CI configuration.",
	categories: ["best-practices", "maintainability", "security"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			const gitignore = files.includes(".gitignore")
				? yield* ws.readText(".gitignore")
				: undefined;
			return [
				...failing(files, DOC_CHECKS),
				...gitignoreFindings(gitignore),
				...failing(files, BUILD_CHECKS),
			];
		}),
});
