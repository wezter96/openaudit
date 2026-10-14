import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";

const STORAGE_KEY = "openaudit-theme";

/**
 * Runs before first paint (via ScriptOnce) so there is no flash of the wrong
 * theme. Uses the stored choice, else the OS preference.
 */
export const themeScript = `(function(){try{var t=localStorage.getItem("${STORAGE_KEY}");var d=t?t==="dark":matchMedia("(prefers-color-scheme: dark)").matches;document.documentElement.classList.toggle("dark",d)}catch(e){}})()`;

/** The theme lives in the root element's class; re-render when it changes. */
const subscribeTheme = (onChange: () => void) => {
	const observer = new MutationObserver(onChange);
	observer.observe(document.documentElement, {
		attributes: true,
		attributeFilter: ["class"],
	});
	return () => observer.disconnect();
};
const isDark = () => document.documentElement.classList.contains("dark");

export function ThemeToggle() {
	// Unknown (undefined) while server rendering.
	const dark = useSyncExternalStore(subscribeTheme, isDark, () => undefined);

	const toggle = () => {
		const next = !dark;
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
