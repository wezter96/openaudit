import type { ProcessRunner, RunOptions, RunResult } from "./types";

/** Environment names a scanned target must never see. */
const SECRET_ENV =
	/TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|PRIVATE_KEY|^API_URL$/i;

const isPassedOn = (entry: [string, string | undefined]) =>
	entry[1] !== undefined && !SECRET_ENV.test(entry[0]);

/**
 * The scanner's environment without its secrets. git and openaudit run on
 * untrusted repositories, so neither gets `SCANNER_TOKEN` or any other key.
 */
export const childEnv = (
	env: Record<string, string | undefined> = process.env,
): Record<string, string> =>
	Object.fromEntries(
		Object.entries(env).filter(isPassedOn) as Array<[string, string]>,
	);

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
		env: options.env ?? childEnv(),
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
