import { type OpenauditCommand, parseCommand } from "./audit";

export const DEFAULT_API_URL = "https://openaudit.se";

export interface ScannerConfig {
	/** The badge API origin, without a trailing slash. */
	readonly apiUrl: string;
	readonly token: string;
	readonly openaudit: OpenauditCommand;
}

/**
 * `API_URL` (default https://openaudit.se), `SCANNER_TOKEN` (required) and
 * `OPENAUDIT_BIN` (default `openaudit`; may be `bun apps/cli/src/bin.ts`).
 */
export const readConfig = (
	env: Record<string, string | undefined> = process.env,
): ScannerConfig => {
	const token = env.SCANNER_TOKEN?.trim();
	if (!token) throw new Error("SCANNER_TOKEN is required");
	const apiUrl = new URL(env.API_URL?.trim() || DEFAULT_API_URL);
	if (apiUrl.protocol !== "https:" && apiUrl.hostname !== "localhost")
		throw new Error("API_URL must be https (or http://localhost)");
	return {
		apiUrl: apiUrl.origin,
		token,
		openaudit: parseCommand(env.OPENAUDIT_BIN),
	};
};
