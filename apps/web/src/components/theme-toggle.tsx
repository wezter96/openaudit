import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

const STORAGE_KEY = "openaudit-theme";

/**
 * Runs before first paint (via ScriptOnce) so there is no flash of the wrong
 * theme. Uses the stored choice, else the OS preference.
 */
export const themeScript = `(function(){try{var t=localStorage.getItem("${STORAGE_KEY}");var d=t?t==="dark":matchMedia("(prefers-color-scheme: dark)").matches;document.documentElement.classList.toggle("dark",d)}catch(e){}})()`;

export function ThemeToggle() {
	const [dark, setDark] = useState<boolean | undefined>(undefined);

	useEffect(() => {
		setDark(document.documentElement.classList.contains("dark"));
	}, []);

	const toggle = () => {
		const next = !dark;
		setDark(next);
		document.documentElement.classList.toggle("dark", next);
		try {
			localStorage.setItem(STORAGE_KEY, next ? "dark" : "light");
		} catch {
			// Storage can be unavailable (private mode); the toggle still works.
		}
	};

	return (
		<button
			type="button"
			onClick={toggle}
			aria-pressed={dark ?? false}
			className="inline-flex size-10 items-center justify-center rounded-md text-ink-soft hover:bg-muted hover:text-ink"
		>
			<span className="sr-only">Dark theme</span>
			<Moon aria-hidden="true" className="size-5 dark:hidden" />
			<Sun aria-hidden="true" className="hidden size-5 dark:block" />
		</button>
	);
}
