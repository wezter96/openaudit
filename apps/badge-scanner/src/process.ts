import type { ChildEnv, ProcessRunner, RunOptions, RunResult } from "./types";

/**
 * The only variables a child inherits: the basics, plus the non-secret tool
 * settings the openaudit image sets (guarddog's cache, Go's toolchain pin,
 * the browser path). Everything else, `SCANNER_TOKEN` included, stays here.
 */
export const PASSED_ENV: ReadonlyArray<string> = [
	"PATH",
	"HOME",
	"LANG",
	"LC_ALL",
	"TZ",
	"GUARDDOG_TOP_PACKAGES_CACHE_LOCATION",
	"GOTOOLCHAIN",
	"CHROME_PATH",
	"PUPPETEER_EXECUTABLE_PATH",
	"PUPPETEER_SKIP_DOWNLOAD",
	"npm_config_update_notifier",
];

/**
 * An explicit, minimal environment for git and openaudit, which run on
 * untrusted repositories (and so does every tool openaudit starts). `tmp`
 * becomes TMPDIR, inside the job's own temp dir.
 */
export const childEnv = (
	tmp: string,
	env: Record<string, string | undefined> = process.env,
): ChildEnv => {
	const out: Record<string, string> = {};
	for (const name of PASSED_ENV) {
		const value = env[name];
		if (value !== undefined) out[name] = value;
	}
	return { ...out, TMPDIR: tmp };
};

/** Kills the whole process group, so tools openaudit started die with it. */
const killGroup = (pid: number) => {
	try {
		process.kill(-pid, "SIGKILL");
	} catch {
		// Already gone.
	}
};

/**
 * `Bun.spawn` in its own process group with a hard timeout. stdin is closed so
 * nothing can wait for a prompt.
 */
export const bunRunner: ProcessRunner = async (
	cmd,
	options: RunOptions,
): Promise<RunResult> => {
	const proc = Bun.spawn([...cmd], {
		cwd: options.cwd,
		env: { ...options.env },
		stdin: "ignore",
		stdout: "pipe",
		stderr: "pipe",
		detached: true,
	});
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		killGroup(proc.pid);
	}, options.timeoutMs);
	try {
		const [stdout, stderr, code] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		return { code, stdout, stderr, timedOut };
	} finally {
		clearTimeout(timer);
		killGroup(proc.pid);
	}
};
