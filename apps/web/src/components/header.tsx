import { Link } from "@tanstack/react-router";

import { TagMark } from "./logo";
import { ThemeToggle } from "./theme-toggle";

const links = [
	{ to: "/report", label: "Report viewer" },
	{ to: "/auditors", label: "Auditors" },
	{ to: "/docs", label: "Docs" },
] as const;

export default function Header() {
	return (
		<header className="border-rule border-b bg-paper/95">
			<div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-8 gap-y-1 px-4 py-2 sm:px-6">
				<Link
					to="/"
					className="mr-auto inline-flex items-center gap-2 py-2 font-bold text-lg tracking-tight"
				>
					<TagMark className="h-7 w-6" />
					openaudit
				</Link>
				<nav
					aria-label="Main"
					className="order-last w-full sm:order-none sm:w-auto"
				>
					<ul className="-mx-2 flex gap-1">
						{links.map(({ to, label }) => (
							<li key={to}>
								<Link
									to={to}
									className="block rounded-md px-2 py-2 text-ink-soft text-sm hover:text-ink aria-[current=page]:font-semibold aria-[current=page]:text-ink aria-[current=page]:underline aria-[current=page]:decoration-2 aria-[current=page]:underline-offset-[6px]"
								>
									{label}
								</Link>
							</li>
						))}
					</ul>
				</nav>
				<ThemeToggle />
			</div>
		</header>
	);
}
