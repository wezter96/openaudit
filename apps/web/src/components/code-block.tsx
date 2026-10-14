import { cn } from "@openaudit/ui/lib/utils";
import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";

/** A shell command or snippet with a copy button. `prompt` adds a `$` that is not copied. */
export function CodeBlock({
	code,
	prompt = false,
	label,
	className,
}: {
	code: string;
	prompt?: boolean;
	/** Accessible name for the copy button's target, e.g. "install command". */
	label: string;
	className?: string;
}) {
	const [copied, setCopied] = useState(false);

	useEffect(() => {
		if (!copied) return;
		const t = setTimeout(() => setCopied(false), 2000);
		return () => clearTimeout(t);
	}, [copied]);

	const copy = async () => {
		try {
			await navigator.clipboard.writeText(code);
			setCopied(true);
		} catch {
			// Clipboard can be blocked; the text stays selectable.
		}
	};

	return (
		<div
			className={cn(
				"group relative flex items-start border border-rule bg-surface font-mono text-sm",
				className,
			)}
		>
			<pre className="min-w-0 flex-1 overflow-x-auto px-4 py-3">
				<code>
					{prompt &&
						code.split("\n").map((line, i) => (
							<span key={i} className="block">
								<span aria-hidden="true" className="select-none text-ink-soft">
									${" "}
								</span>
								{line}
							</span>
						))}
					{!prompt && code}
				</code>
			</pre>
			<button
				type="button"
				onClick={copy}
				className="m-1.5 inline-flex size-8 shrink-0 items-center justify-center rounded text-ink-soft hover:bg-muted hover:text-ink"
			>
				{copied ? (
					<Check aria-hidden="true" className="size-4 text-ok" />
				) : (
					<Copy aria-hidden="true" className="size-4" />
				)}
				<span className="sr-only">Copy {label}</span>
			</button>
			<output className="sr-only">{copied ? "Copied to clipboard" : ""}</output>
		</div>
	);
}
