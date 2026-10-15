import { baseName } from "../util";

/* -------------------------------------------------------------------------- */
/*                              Launched packages                             */
/* -------------------------------------------------------------------------- */

/** One word of an MCP launch command, as written in the config. */
export type Token = string;
/** A package, distribution or image reference: `pkg@1.2.3`, `image:tag`. */
type Spec = string;
/** Position of a token in a launch command. */
type TokenIndex = number;

type Ecosystem = "npm" | "pypi" | "docker";

export interface LaunchedPackage {
	readonly launcher: string;
	readonly spec: string;
	/** Index of the spec among the launch tokens. */
	readonly token: number;
	readonly pinned: boolean;
	readonly ecosystem: Ecosystem;
	readonly autoYes: boolean;
}

/** The program a launch token runs: `/usr/bin/npx.cmd` is `npx`. */
export const exeName = (t: Token) =>
	baseName(t)
		.replace(/\.(?:cmd|exe|bat)$/i, "")
		.toLowerCase();

const EXACT_SEMVER =
	/^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const LOCAL_SPEC = /^(?:\.{0,2}\/|~|file:|link:|[A-Za-z]:\\)|\$/;
const ARCHIVE = /\.(?:whl|tar\.gz|zip)$/;

/** Local paths and URLs, which no registry serves. */
const isUnfetched = (spec: Spec) =>
	LOCAL_SPEC.test(spec) || /^https?:\/\//.test(spec);

/** undefined for local or unresolvable specs, which nothing fetches. */
const npmPinned = (spec: Spec): boolean | undefined => {
	if (isUnfetched(spec)) return undefined;
	if (
		/^(?:git\+|git:|github:|gitlab:|bitbucket:)|^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(
			spec,
		)
	)
		return /#[0-9a-f]{40}$/i.test(spec);
	const at = spec.lastIndexOf("@");
	return at > 0 && EXACT_SEMVER.test(spec.slice(at + 1));
};

export const npmName = (spec: Spec) => {
	const at = spec.lastIndexOf("@");
	return at > 0 ? spec.slice(0, at) : spec;
};

const pypiPinned = (spec: Spec): boolean | undefined => {
	if (isUnfetched(spec) || ARCHIVE.test(spec)) return undefined;
	if (spec.startsWith("git+")) return /@[0-9a-f]{40}(?:#.*)?$/i.test(spec);
	return /^[\w.[\],-]+(?:===?\s*[\w.!+-]+|@\d[\w.!+-]*)$/.test(spec);
};

const imagePinned = (image: Spec): boolean | undefined => {
	if (image.includes("$")) return undefined;
	if (/@sha256:[0-9a-f]{64}$/i.test(image)) return true;
	const tagAt = image.indexOf(":", image.lastIndexOf("/") + 1);
	// Version tags contain a digit; latest, main, edge, stable… move.
	return tagAt !== -1 && /\d/.test(image.slice(tagAt + 1));
};

const PINNED: Readonly<Record<Ecosystem, (spec: Spec) => boolean | undefined>> =
	{ npm: npmPinned, pypi: pypiPinned, docker: imagePinned };

/**
 * What a flag does to the package list: `yes` auto-confirms the install,
 * `package` names a package (so the first operand is a command), `with` adds
 * one, and `value` takes a value that is no package.
 */
type FlagAction = "yes" | "package" | "with" | "value";

/** How a launcher's options name the packages it fetches. */
interface Syntax {
	readonly ecosystem: Ecosystem;
	readonly flags: ReadonlyMap<Token, FlagAction>;
	/** Flags written `--flag=value` that name a package. */
	readonly namedBy?: RegExp;
	/** Whether the first operand comes before packages named by flags. */
	readonly operandFirst: boolean;
}

const flagMap = (
	valueFlags: string,
	actions: ReadonlyArray<readonly [Token, FlagAction]>,
): ReadonlyMap<Token, FlagAction> =>
	new Map([
		...valueFlags.split(" ").map((f) => [f, "value"] as const),
		...actions,
	]);

const NPM_SYNTAX: Syntax = {
	ecosystem: "npm",
	flags: flagMap("-c --call", [
		["-y", "yes"],
		["--yes", "yes"],
		["-p", "package"],
		["--package", "package"],
	]),
	namedBy: /^--package=/,
	operandFirst: false,
};
/** uvx: `--from` names the package, else the command does. */
const UV_SYNTAX: Syntax = {
	ecosystem: "pypi",
	flags: flagMap(
		"--with --with-editable --with-requirements --python -p --index --index-url --extra-index-url --default-index --find-links -f --constraint -c --overrides --build-constraint",
		[
			["--with", "with"],
			["--from", "package"],
		],
	),
	operandFirst: true,
};
/** pipx: `--spec` names the package, else the command does. */
const PIPX_SYNTAX: Syntax = {
	ecosystem: "pypi",
	flags: flagMap("--python --index-url -i --pip-args --backend", [
		["--with", "with"],
		["--spec", "package"],
	]),
	operandFirst: true,
};
const DOCKER_SYNTAX: Syntax = {
	ecosystem: "docker",
	flags: flagMap(
		"-e --env --env-file -v --volume --mount -p --publish --name -u --user -w --workdir --network --net --entrypoint -l --label --platform --add-host --cap-add --cap-drop --security-opt -m --memory --cpus --pull --hostname -h --ulimit --tmpfs --device --log-driver --log-opt --restart --dns --ipc --pid --gpus --runtime --shm-size --stop-signal --userns --volumes-from --group-add --cidfile --label-file --expose --link",
		[],
	),
	operandFirst: false,
};

/**
 * Launch command prefixes (`|` separates alternatives) and the syntax of
 * what follows them.
 */
const LAUNCHERS: ReadonlyArray<readonly [string, Syntax]> = [
	["npx|bunx", NPM_SYNTAX],
	["npm exec|x", NPM_SYNTAX],
	["pnpm|yarn dlx", NPM_SYNTAX],
	["bun x", NPM_SYNTAX],
	["uvx", UV_SYNTAX],
	["uv tool run|x", UV_SYNTAX],
	["pipx run", PIPX_SYNTAX],
	["docker|podman run", DOCKER_SYNTAX],
	["docker|podman container run", DOCKER_SYNTAX],
];

const startsWith = (words: ReadonlyArray<Token>, prefix: string) =>
	prefix
		.split(" ")
		.every((alternatives, i) =>
			alternatives.split("|").includes(words[i] ?? ""),
		);

interface OperandScan {
	named: boolean;
	autoYes: boolean;
	operand?: TokenIndex;
	readonly packages: TokenIndex[];
}

/** Applies the flag at `i`; returns the last index it consumed. */
const applyFlag = (
	scan: OperandScan,
	action: FlagAction,
	i: TokenIndex,
): TokenIndex => {
	switch (action) {
		case "yes":
			scan.autoYes = true;
			return i;
		case "package":
			scan.named = true;
			scan.packages.push(i + 1);
			return i + 1;
		case "with":
			scan.packages.push(i + 1);
			return i + 1;
		case "value":
			return i + 1;
	}
};

/** Reads options from `from` up to the first operand. */
const scanOperands = (
	tokens: ReadonlyArray<Token>,
	from: TokenIndex,
	syntax: Syntax,
): OperandScan => {
	const scan: OperandScan = { named: false, autoYes: false, packages: [] };
	for (let i = from; i < tokens.length && scan.operand === undefined; i++) {
		const t = tokens[i] ?? "";
		const action = syntax.flags.get(t);
		if (action) i = applyFlag(scan, action, i);
		else if (syntax.namedBy?.test(t)) scan.named = true;
		else if (!t.startsWith("-")) scan.operand = i;
	}
	return scan;
};

/** Token indexes of the packages, the first operand included unless a flag named them. */
const packageTokens = (
	{ named, operand, packages }: OperandScan,
	syntax: Syntax,
): TokenIndex[] => {
	if (operand === undefined || named) return packages;
	return syntax.operandFirst ? [operand, ...packages] : [...packages, operand];
};

const launched = (
	tokens: ReadonlyArray<Token>,
	token: TokenIndex,
	ecosystem: Ecosystem,
	autoYes: boolean,
): LaunchedPackage[] => {
	const spec = tokens[token];
	if (spec === undefined) return [];
	const pinned = PINNED[ecosystem](spec);
	if (pinned === undefined) return [];
	return [
		{ launcher: tokens[0] ?? "", spec, token, pinned, ecosystem, autoYes },
	];
};

/** The package, distribution or image an MCP launch command fetches. */
export const launchedPackages = (
	tokens: ReadonlyArray<Token>,
): LaunchedPackage[] => {
	const words = [exeName(tokens[0] ?? ""), ...tokens.slice(1)];
	const launch = LAUNCHERS.find(([prefix]) => startsWith(words, prefix));
	if (!launch) return [];
	const [prefix, syntax] = launch;
	const scan = scanOperands(tokens, prefix.split(" ").length, syntax);
	return packageTokens(scan, syntax).flatMap((token) =>
		launched(tokens, token, syntax.ecosystem, scan.autoYes),
	);
};
