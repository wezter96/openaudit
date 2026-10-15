import { posix } from "node:path";
import {
	defineAuditor,
	type FindingInput,
	redact,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	isMutableTag,
	isPlaceholderValue,
	parseImageRef,
	readOptional,
	SECRET_NAME_RE,
	targetFiles,
} from "./shared";

export const DOCKERFILE_RE =
	/(^|\/)(Dockerfile|Containerfile)(\.(?!(?:dockerignore|[cm]?[jt]sx?|py|go|rb|rs|java|kt|swift|php|cs|md|mdx|json|ya?ml|toml|txt|sh|snap|map)$)[\w.-]+)?$|\.dockerfile$/i;

const BEST_PRACTICES = "https://docs.docker.com/build/building/best-practices/";
const CIS_DOCKER = "https://www.cisecurity.org/benchmark/docker";
const DOCKERIGNORE_DOCS =
	"https://docs.docker.com/build/concepts/context/#dockerignore-files";
const SECRETS_DOCS = "https://docs.docker.com/build/building/secrets/";

/** Repository-relative path of a Dockerfile or .dockerignore. */
type FilePath = string;
/** Raw Dockerfile or .dockerignore contents. */
type FileText = string;
/** Instruction arguments, e.g. the shell command of a RUN. */
type InstructionArgs = string;
/** The single character that continues an instruction onto the next line. */
type EscapeChar = string;
/** A base image reference as written after FROM. */
type ImageName = string;

export interface Instruction {
	/** Upper-cased instruction keyword, e.g. `RUN`. */
	readonly keyword: string;
	/** Arguments with line continuations joined (and heredoc bodies appended). */
	readonly args: string;
	/** 1-based line where the instruction starts. */
	readonly line: number;
	/** First source line, trimmed, for evidence. */
	readonly source: string;
}

export interface Stage {
	readonly from: Instruction;
	readonly image: string;
	readonly alias: string | undefined;
	readonly instructions: ReadonlyArray<Instruction>;
}

/** Position in the source lines while parsing. */
interface LineCursor {
	readonly lines: ReadonlyArray<string>;
	i: number;
}

const BLANK_OR_COMMENT_RE = /^\s*(#.*)?$/;
const HEREDOC_RE = /<<-?\s*["']?(\w+)["']?/;
const HEREDOC_KEYWORDS = new Set(["RUN", "COPY"]);

const skipLinesWhile = (
	cursor: LineCursor,
	keep: (line: FileText) => boolean,
): void => {
	while (cursor.i < cursor.lines.length && keep(cursor.lines[cursor.i] ?? ""))
		cursor.i++;
};

/** Joins `first` with its continuation lines, advancing past them. */
const joinContinuations = (
	cursor: LineCursor,
	first: FileText,
	escapeChar: EscapeChar,
): FileText => {
	let joined = "";
	let current = first;
	for (;;) {
		const end = current.trimEnd();
		if (!end.endsWith(escapeChar)) return joined + current;
		joined += `${end.slice(0, -1)} `;
		// Comment and blank lines inside a continuation are dropped by Docker.
		skipLinesWhile(cursor, (line) => BLANK_OR_COMMENT_RE.test(line));
		if (cursor.i >= cursor.lines.length) return joined;
		current = cursor.lines[cursor.i] ?? "";
		cursor.i++;
	}
};

/** Reads a heredoc body up to its terminator line, advancing past it. */
const readHeredoc = (
	cursor: LineCursor,
	terminator: FileText | undefined,
): FileText => {
	const start = cursor.i;
	skipLinesWhile(cursor, (line) => line.trim() !== terminator);
	const body = cursor.lines.slice(start, cursor.i);
	cursor.i++;
	return body.join("\n");
};

/** Parses the instruction starting at the cursor; undefined for blanks and comments. */
const readInstruction = (
	cursor: LineCursor,
	escapeChar: EscapeChar,
): Instruction | undefined => {
	const first = cursor.lines[cursor.i] ?? "";
	const trimmed = first.trim();
	const start = cursor.i;
	cursor.i++;
	if (trimmed === "" || trimmed.startsWith("#")) return undefined;
	const m = /^\s*(\w+)\s*(.*)$/s.exec(
		joinContinuations(cursor, first, escapeChar),
	);
	if (!m) return undefined;
	const keyword = (m[1] ?? "").toUpperCase();
	let args = (m[2] ?? "").trim();
	const heredoc = HEREDOC_RE.exec(args);
	if (heredoc && HEREDOC_KEYWORDS.has(keyword))
		args += `\n${readHeredoc(cursor, heredoc[1])}`;
	const source = trimmed.length > 160 ? `${trimmed.slice(0, 160)}…` : trimmed;
	return { keyword, args, line: start + 1, source };
};

/** Parses a Dockerfile into instructions, honouring `# escape=` and continuations. */
export const parseDockerfile = (text: FileText): Instruction[] => {
	const lines = text.split(/\r?\n/);
	const escapeMatch = /^#\s*escape\s*=\s*(\S)/i.exec(lines[0] ?? "");
	const escapeChar = escapeMatch?.[1] ?? "\\";
	const cursor: LineCursor = { lines, i: 0 };
	const out: Instruction[] = [];
	while (cursor.i < lines.length) {
		const instruction = readInstruction(cursor, escapeChar);
		if (instruction) out.push(instruction);
	}
	return out;
};

const toStage = (
	from: Instruction,
	instructions: ReadonlyArray<Instruction>,
): Stage => {
	const tokens = from.args.split(/\s+/).filter((t) => t && !t.startsWith("--"));
	return {
		from,
		image: tokens[0] ?? "",
		alias:
			tokens[1]?.toLowerCase() === "as" ? tokens[2]?.toLowerCase() : undefined,
		instructions,
	};
};

/** Groups instructions into build stages (instructions before FROM are dropped). */
export const toStages = (instructions: ReadonlyArray<Instruction>): Stage[] => {
	const groups: Array<{ from: Instruction; list: Instruction[] }> = [];
	for (const ins of instructions) {
		if (ins.keyword === "FROM") groups.push({ from: ins, list: [] });
		else groups[groups.length - 1]?.list.push(ins);
	}
	return groups.map(({ from, list }) => toStage(from, list));
};

interface KeyValue {
	readonly key: string;
	readonly value: string | undefined;
}

/** `KEY=value KEY2="v"` or legacy `KEY value` pairs of ENV/ARG/LABEL. */
const keyValues = (args: InstructionArgs): KeyValue[] => {
	if (!/^[\w.-]+=/.test(args)) {
		const [key = "", ...rest] = args.split(/\s+/);
		return [{ key, value: rest.length ? rest.join(" ") : undefined }];
	}
	const re = /([\w.-]+)(?:=("(?:[^"\\]|\\.)*"|'[^']*'|\S*))?/g;
	return [...args.matchAll(re)].map((m) => ({
		key: m[1] ?? "",
		value: m[2]?.replace(/^["']|["']$/g, ""),
	}));
};

const ARCHIVE_RE = /\.(tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|tar\.zst)$/i;
const PIPE_TO_SHELL_RE =
	/\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k|a)?sh\b/;
const BUILD_TOOLS_RE =
	/\b(apt-get|apt|apk|yum|dnf|microdnf)\b[^;&|]*\b(install|add)\b[^;&|]*\b(build-essential|build-base|gcc|g\+\+|clang|make|cmake|autoconf|golang|maven|gradle|rustc|cargo)\b/;
const BUILD_STEP_RE =
	/\b(go build|cargo build|mvn (-\S+\s+)*(package|install)|gradle(w)? (build|assemble)|(npm|yarn|pnpm|bun) (run )?build|dotnet publish|tsc\b)/;
const IGNORE_ENTRIES = [".git", ".env", "node_modules"] as const;
type IgnoreEntry = (typeof IGNORE_ENTRIES)[number];

const isIgnorePattern = (line: FileText) => line !== "" && !/^[#!]/.test(line);

/** Non-negated .dockerignore patterns, trimmed of surrounding slashes. */
const ignorePatterns = (dockerignore: FileText): FileText[] =>
	dockerignore
		.split(/\r?\n/)
		.map((l) => l.trim())
		.filter(isIgnorePattern)
		.map((l) => l.replace(/^\/+|\/+$/g, ""));

const patternExcludes = (pattern: FileText, name: IgnoreEntry): boolean => {
	if (pattern === "*" || pattern === "**") return true;
	try {
		const glob = new Bun.Glob(pattern);
		return glob.match(name) || glob.match(`${name}/x`);
	} catch {
		return false;
	}
};

/** Dockerignore patterns (non-negated) that exclude `name` at the context root. */
const ignores = (dockerignore: FileText, name: IgnoreEntry): boolean =>
	ignorePatterns(dockerignore).some((pattern) =>
		patternExcludes(pattern, name),
	);

const findDockerignore = (ws: Workspace, file: FilePath) =>
	Effect.gen(function* () {
		const dir = posix.dirname(file);
		const candidates = [
			`${file}.dockerignore`,
			posix.join(dir, ".dockerignore"),
			".dockerignore",
		];
		for (const candidate of candidates) {
			const text = (yield* ws.exists(candidate))
				? yield* readOptional(ws, candidate)
				: undefined;
			if (text !== undefined) return { path: candidate, text };
		}
		return undefined;
	});

type FindingBase = Pick<FindingInput, "location" | "evidence">;
type InstructionRule = (ins: Instruction, base: FindingBase) => FindingInput[];

const hardcodedSecretFinding = (
	ins: Instruction,
	{ key, value }: { readonly key: string; readonly value: string },
	base: FindingBase,
): FindingInput => ({
	...base,
	evidence: `${ins.keyword} ${key}=${redact(value)}`,
	ruleId: `container.dockerfile/secret-in-${ins.keyword.toLowerCase()}`,
	title: `Secret hardcoded in ${ins.keyword}`,
	severity: "high",
	category: "security",
	message: `\`${key}\` is set to a literal value; it is stored in the image metadata and visible to anyone who can pull the image.`,
	remediation:
		"Remove the value, rotate the credential, and pass secrets at runtime or with BuildKit `RUN --mount=type=secret`.",
	references: [SECRETS_DOCS, CIS_DOCKER],
	tags: ["cis-docker-4.10", "cwe-798"],
});

const secretBuildArgFinding = (
	{ key }: KeyValue,
	base: FindingBase,
): FindingInput => ({
	...base,
	ruleId: "container.dockerfile/secret-build-arg",
	title: "Secret passed as build argument",
	severity: "medium",
	category: "security",
	message: `Build argument \`${key}\` looks like a credential; build-arg values are recorded in the image history.`,
	remediation:
		"Use BuildKit secret mounts (`RUN --mount=type=secret,id=…`) instead of ARG.",
	references: [SECRETS_DOCS],
	tags: ["cwe-532"],
});

const secretKeyFindings = (
	ins: Instruction,
	pair: KeyValue,
	base: FindingBase,
): FindingInput[] => {
	const { key, value } = pair;
	if (value !== undefined && !isPlaceholderValue(value))
		return [hardcodedSecretFinding(ins, { key, value }, base)];
	if (ins.keyword === "ARG" && value === undefined)
		return [secretBuildArgFinding(pair, base)];
	return [];
};

/** Hardcoded secrets and secret-looking build args in an ENV/ARG instruction. */
const secretEnvFindings: InstructionRule = (ins, base) =>
	keyValues(ins.args)
		.filter(({ key }) => SECRET_NAME_RE.test(key))
		.flatMap((pair) => secretKeyFindings(ins, pair, base));

/** Source operands of a COPY/ADD (everything but flags and the destination). */
const copySources = (args: InstructionArgs): string[] =>
	args
		.split(/\s+/)
		.filter((t) => !t.startsWith("--"))
		.slice(0, -1);

const isRemoteSource = (source: string) => /^https?:\/\//i.test(source);
const isArchiveOrRepo = (source: string) =>
	ARCHIVE_RE.test(source) || /^git@|\.git$/.test(source);

/** A finding's fixed fields; the instruction supplies location and evidence. */
type FindingTemplate = Omit<FindingInput, "location" | "evidence">;

const ADD_REMOTE_URL: FindingTemplate = {
	ruleId: "container.dockerfile/add-remote-url",
	title: "ADD downloads a remote file without verification",
	severity: "medium",
	category: "supply-chain",
	message:
		"`ADD <url>` fetches content at build time without integrity verification.",
	remediation:
		"Use `ADD --checksum=sha256:… <url>`, or download with curl and verify a checksum in a RUN step.",
	references: [
		"https://docs.docker.com/reference/dockerfile/#add---checksum",
		BEST_PRACTICES,
	],
	tags: ["cis-docker-4.9", "cwe-494"],
};

const ADD_INSTEAD_OF_COPY: FindingTemplate = {
	ruleId: "container.dockerfile/add-instead-of-copy",
	title: "ADD used where COPY suffices",
	severity: "low",
	category: "best-practices",
	message:
		"`ADD` has implicit behaviour (archive extraction, URL fetching); `COPY` is explicit and safer for local files.",
	remediation: "Replace `ADD` with `COPY` for local files.",
	references: [BEST_PRACTICES],
	tags: ["cis-docker-4.9"],
};

/** The template that applies to an ADD's sources, if any. */
const addTemplate = (args: InstructionArgs): FindingTemplate | undefined => {
	const sources = copySources(args);
	if (sources.some(isRemoteSource))
		return /--checksum=/.test(args) ? undefined : ADD_REMOTE_URL;
	const copySuffices = sources.length > 0 && !sources.some(isArchiveOrRepo);
	return copySuffices ? ADD_INSTEAD_OF_COPY : undefined;
};

/** Remote or needless `ADD` usage. */
const addFindings: InstructionRule = ({ args }, base) => {
	const template = addTemplate(args);
	return template ? [{ ...base, ...template }] : [];
};

const APT_INSTALL_RE = /\bapt-get\s+(?:-\S+\s+)*install\b/;
const APT_LISTS_REMOVED_RE = /rm\s+-[rf]+\s+[^;&|]*\/var\/lib\/apt\/lists/;
const APK_ADD_RE = /\bapk\s+(?:-\S+\s+)*add\b/;

const usesCacheMount = (args: InstructionArgs) =>
	/--mount=type=cache/.test(args);

const aptCacheKept = (args: InstructionArgs) =>
	!usesCacheMount(args) && !APT_LISTS_REMOVED_RE.test(args);

const apkIndexKept = (args: InstructionArgs) =>
	!/--no-cache/.test(args) && !usesCacheMount(args);

interface RunCheck {
	readonly matches: (args: InstructionArgs) => boolean;
	readonly finding: FindingTemplate;
}

/** RUN checks, in reporting order. */
const RUN_CHECKS: ReadonlyArray<RunCheck> = [
	{
		matches: (args) => PIPE_TO_SHELL_RE.test(args),
		finding: {
			ruleId: "container.dockerfile/curl-pipe-shell",
			title: "Remote script piped into a shell",
			severity: "high",
			category: "security",
			message:
				"A script is downloaded and executed in one step without integrity verification; a compromised server or MITM yields code execution in the build.",
			remediation:
				"Download to a file, verify its checksum or signature, then execute it — or use a package manager.",
			references: [
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
			],
			tags: ["cwe-494", "owasp-a08"],
		},
	},
	{
		matches: (args) =>
			APT_INSTALL_RE.test(args) && !/--no-install-recommends/.test(args),
		finding: {
			ruleId: "container.dockerfile/apt-no-install-recommends",
			title: "apt-get install without --no-install-recommends",
			severity: "low",
			category: "performance",
			message:
				"Recommended packages are installed too, enlarging the image and its attack surface.",
			remediation: "Use `apt-get install -y --no-install-recommends …`.",
			references: [BEST_PRACTICES],
		},
	},
	{
		matches: (args) => APT_INSTALL_RE.test(args) && aptCacheKept(args),
		finding: {
			ruleId: "container.dockerfile/apt-cache-not-cleaned",
			title: "apt cache not cleaned",
			severity: "low",
			category: "performance",
			message:
				"The apt package lists remain in the layer, adding tens of megabytes.",
			remediation:
				"End the same RUN with `&& rm -rf /var/lib/apt/lists/*` (or use a BuildKit cache mount).",
			references: [BEST_PRACTICES],
		},
	},
	{
		matches: (args) => APK_ADD_RE.test(args) && apkIndexKept(args),
		finding: {
			ruleId: "container.dockerfile/apk-no-cache",
			title: "apk add without --no-cache",
			severity: "low",
			category: "performance",
			message: "The apk index is left in the image layer.",
			remediation: "Use `apk add --no-cache …`.",
			references: [BEST_PRACTICES],
		},
	},
	{
		matches: (args) => /(^|[\s;&|(])sudo\s/.test(args),
		finding: {
			ruleId: "container.dockerfile/sudo",
			title: "sudo used in RUN",
			severity: "medium",
			category: "security",
			message:
				"`sudo` in images has unpredictable TTY and signal behaviour and implies a privileged user setup.",
			remediation:
				"Run privileged steps before switching `USER`, or use `gosu` in entrypoints.",
			references: [BEST_PRACTICES],
			tags: ["cwe-250"],
		},
	},
];

/** Risky shell patterns in a RUN instruction. */
const runFindings: InstructionRule = ({ args }, base) =>
	RUN_CHECKS.filter((check) => check.matches(args)).map((check) => ({
		...base,
		...check.finding,
	}));

const EXPOSE_SSH: FindingTemplate = {
	ruleId: "container.dockerfile/expose-ssh",
	title: "SSH port exposed",
	severity: "medium",
	category: "security",
	message:
		"Port 22 is exposed; running an SSH daemon in a container widens the attack surface.",
	remediation:
		"Remove sshd from the image and use `docker exec` / `kubectl exec` for access.",
	references: [CIS_DOCKER],
	tags: ["cis-docker-5.6"],
};

const exposeFindings: InstructionRule = ({ args }, base) =>
	args.split(/\s+/).some((p) => /^22(\/tcp)?$/.test(p))
		? [{ ...base, ...EXPOSE_SSH }]
		: [];

const INSTRUCTION_RULES = new Map<string, InstructionRule>([
	["ADD", addFindings],
	["RUN", runFindings],
	["ENV", secretEnvFindings],
	["ARG", secretEnvFindings],
	["EXPOSE", exposeFindings],
]);

const at = (file: FilePath, ins: Instruction) => ({ file, line: ins.line });

const isScratch = (image: ImageName) => image.toLowerCase() === "scratch";

/** True for a FROM image that is pulled from a registry (not a stage, scratch or variable). */
const isRegistryImage = (image: ImageName, aliases: ReadonlySet<string>) =>
	image !== "" &&
	!isScratch(image) &&
	!aliases.has(image.toLowerCase()) &&
	!image.includes("$");

const baseImageFindings = (
	file: FilePath,
	stage: Stage,
	aliases: ReadonlySet<string>,
): FindingInput[] => {
	const image = stage.image;
	if (!isRegistryImage(image, aliases)) return [];
	const ref = parseImageRef(image);
	if (isMutableTag(ref))
		return [
			{
				ruleId: "container.dockerfile/from-latest",
				title: "Base image uses a mutable tag",
				severity: "medium",
				category: "supply-chain",
				message: `\`FROM ${image}\` ${ref.tag ? "uses `:latest`" : "has no tag (implicitly `:latest`)"}, so builds are not reproducible and can silently pick up breaking or compromised images.`,
				remediation:
					"Pin a specific version tag, ideally with a digest: `FROM node:22.11-alpine@sha256:…`.",
				location: at(file, stage.from),
				evidence: stage.from.source,
				references: [BEST_PRACTICES, CIS_DOCKER],
				tags: ["cis-docker-4.2", "cwe-1357"],
			},
		];
	if (ref.digest) return [];
	return [
		{
			ruleId: "container.dockerfile/from-unpinned-digest",
			title: "Base image not pinned by digest",
			severity: "low",
			category: "supply-chain",
			message: `\`FROM ${image}\` is pinned by tag only; tags can be re-pushed to point at different content.`,
			remediation:
				"Append the image digest (`@sha256:…`) and update it with Dependabot or Renovate.",
			location: at(file, stage.from),
			evidence: stage.from.source,
			references: [
				"https://docs.docker.com/reference/dockerfile/#from",
				BEST_PRACTICES,
			],
			tags: ["cwe-1357"],
		},
	];
};

const instructionFindings = (
	file: FilePath,
	ins: Instruction,
): FindingInput[] => {
	const rule = INSTRUCTION_RULES.get(ins.keyword);
	return rule
		? rule(ins, { location: at(file, ins), evidence: ins.source })
		: [];
};

const stageFindings = (
	file: FilePath,
	stage: Stage,
	aliases: ReadonlySet<string>,
): FindingInput[] => [
	...baseImageFindings(file, stage, aliases),
	...stage.instructions.flatMap((ins) => instructionFindings(file, ins)),
];

const hasNonrootBase = (image: ImageName) =>
	/nonroot|distroless.*:nonroot|chainguard/i.test(image);

const runsAsRoot = (final: Stage, lastUser: Instruction | undefined) => {
	if (!lastUser) return !hasNonrootBase(final.image) && !isScratch(final.image);
	const userName = lastUser.args.split(/\s+/)[0] ?? "";
	return /^(root|0)(:(root|0))?$/.test(userName);
};

const rootUserFindings = (file: FilePath, final: Stage): FindingInput[] => {
	const lastUser = final.instructions
		.filter((i) => i.keyword === "USER")
		.at(-1);
	if (!runsAsRoot(final, lastUser)) return [];
	const where = lastUser ?? final.from;
	return [
		{
			ruleId: "container.dockerfile/runs-as-root",
			title: "Container runs as root",
			severity: "medium",
			category: "security",
			message: lastUser
				? "The final stage explicitly switches to the root user."
				: "The final stage never sets `USER`, so the container runs as root; a breakout or RCE gets root inside the container.",
			remediation:
				"Create an unprivileged user and add `USER app` (or a numeric UID) to the final stage.",
			location: at(file, where),
			evidence: where.source,
			references: [
				"https://docs.docker.com/reference/dockerfile/#user",
				CIS_DOCKER,
			],
			tags: ["cis-docker-4.1", "cwe-250"],
		},
	];
};

const healthcheckFindings = (file: FilePath, final: Stage): FindingInput[] => {
	const hasHealthcheck = final.instructions.some(
		(i) => i.keyword === "HEALTHCHECK",
	);
	if (hasHealthcheck || isScratch(final.image)) return [];
	return [
		{
			ruleId: "container.dockerfile/healthcheck-missing",
			title: "No HEALTHCHECK",
			severity: "low",
			category: "reliability",
			message:
				"The image defines no HEALTHCHECK, so Docker cannot detect a hung process (orchestrators with their own probes may not need it).",
			remediation:
				"Add `HEALTHCHECK CMD …` or configure liveness probes in your orchestrator.",
			location: at(file, final.from),
			evidence: final.from.source,
			confidence: "medium",
			references: ["https://docs.docker.com/reference/dockerfile/#healthcheck"],
			tags: ["cis-docker-4.6"],
		},
	];
};

const copiesFromContext = (ins: Instruction) =>
	(ins.keyword === "COPY" || ins.keyword === "ADD") &&
	!/--from=/.test(ins.args);

const copiesWholeContext = (ins: Instruction) =>
	copiesFromContext(ins) &&
	copySources(ins.args).some((s) => s === "." || s === "./");

interface DockerfileContext {
	readonly dockerignore?: { readonly path: string; readonly text: string };
	readonly hasPackageJson?: boolean;
}

type Dockerignore = NonNullable<DockerfileContext["dockerignore"]>;

const noDockerignoreFinding = (
	file: FilePath,
	copyAll: Instruction,
): FindingInput => ({
	ruleId: "container.dockerfile/copy-context-no-dockerignore",
	title: "Whole build context copied without .dockerignore",
	severity: "medium",
	category: "security",
	message:
		"`COPY . …` copies the entire build context, and there is no .dockerignore — `.env` files, `.git` history and local credentials end up in the image.",
	remediation:
		"Add a .dockerignore excluding at least `.git`, `.env*`, `node_modules` and build output, or copy only what is needed.",
	location: at(file, copyAll),
	evidence: copyAll.source,
	references: [DOCKERIGNORE_DOCS],
	tags: ["cwe-538"],
});

/** Sensitive entries the .dockerignore should exclude but does not. */
const missingIgnores = (
	di: Dockerignore,
	context: DockerfileContext,
): IgnoreEntry[] =>
	IGNORE_ENTRIES.filter(
		(name) =>
			(name !== "node_modules" || context.hasPackageJson) &&
			!ignores(di.text, name),
	);

const incompleteDockerignoreFindings = (
	copyAll: Instruction,
	di: Dockerignore,
	context: DockerfileContext,
): FindingInput[] => {
	const missing = missingIgnores(di, context);
	if (!missing.length) return [];
	return [
		{
			ruleId: "container.dockerfile/dockerignore-incomplete",
			title: ".dockerignore misses sensitive paths",
			severity: missing.some((m) => m !== "node_modules") ? "medium" : "low",
			category: "security",
			message: `\`COPY . …\` is used but ${di.path} does not exclude ${missing.map((m) => `\`${m}\``).join(", ")}.`,
			remediation: `Add ${missing.map((m) => (m === ".env" ? "`.env*`" : `\`${m}\``)).join(", ")} to ${di.path}.`,
			location: { file: di.path, line: 1 },
			evidence: copyAll.source,
			references: [DOCKERIGNORE_DOCS],
			tags: ["cwe-538"],
		},
	];
};

const contextCopyFindings = (
	file: FilePath,
	stages: ReadonlyArray<Stage>,
	context: DockerfileContext,
): FindingInput[] => {
	const copyAll = stages
		.flatMap((s) => s.instructions)
		.find(copiesWholeContext);
	if (!copyAll) return [];
	const di = context.dockerignore;
	if (!di) return [noDockerignoreFinding(file, copyAll)];
	return incompleteDockerignoreFindings(copyAll, di, context);
};

const isBuildStep = (ins: Instruction) =>
	ins.keyword === "RUN" &&
	(BUILD_TOOLS_RE.test(ins.args) || BUILD_STEP_RE.test(ins.args));

const singleStageBuildFindings = (
	file: FilePath,
	stages: ReadonlyArray<Stage>,
): FindingInput[] => {
	const only = stages.length === 1 ? stages[0] : undefined;
	const buildStep = only?.instructions.find(isBuildStep);
	if (!buildStep) return [];
	return [
		{
			ruleId: "container.dockerfile/single-stage-build",
			title: "Build toolchain shipped in the runtime image",
			severity: "info",
			category: "best-practices",
			message:
				"This single-stage build installs compilers or runs a build, so toolchains and sources end up in the final image.",
			remediation:
				"Use a multi-stage build: compile in a `builder` stage and `COPY --from=builder` only the artefacts into a slim runtime image.",
			location: at(file, buildStep),
			evidence: buildStep.source,
			references: ["https://docs.docker.com/build/building/multi-stage/"],
		},
	];
};

/** Audits one Dockerfile's text. Exported for tests. */
export const auditDockerfile = (
	file: FilePath,
	text: FileText,
	context: DockerfileContext = {},
): FindingInput[] => {
	const stages = toStages(parseDockerfile(text));
	const final = stages[stages.length - 1];
	if (!final) return [];
	const aliases = new Set(stages.flatMap((s) => (s.alias ? [s.alias] : [])));
	return [
		...stages.flatMap((stage) => stageFindings(file, stage, aliases)),
		...rootUserFindings(file, final),
		...healthcheckFindings(file, final),
		...contextCopyFindings(file, stages, context),
		...singleStageBuildFindings(file, stages),
	];
};

/** Static analysis of Dockerfiles / Containerfiles. */
export const dockerfile = defineAuditor({
	id: "container.dockerfile",
	title: "Dockerfile security & best practices",
	description:
		"Checks Dockerfiles for mutable base images, root users, secrets in ENV/ARG, remote ADD, curl-pipe-sh, package-cache hygiene, missing HEALTHCHECK and unsafe COPY of the build context.",
	categories: ["security", "supply-chain", "best-practices", "performance"],
	targets: ["container"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, DOCKERFILE_RE);
			if (files.length === 0) return yield* skip("No Dockerfiles found");
			const findings: FindingInput[] = [];
			for (const file of files) {
				const text = yield* readOptional(ws, file);
				if (text === undefined) continue;
				const dockerignore = yield* findDockerignore(ws, file);
				const hasPackageJson = yield* ws.exists(
					posix.join(posix.dirname(file), "package.json"),
				);
				findings.push(
					...auditDockerfile(file, text, { dockerignore, hasPackageJson }),
				);
			}
			return findings;
		}),
});
