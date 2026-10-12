import { Link } from "@tanstack/react-router";

export default function Footer() {
	return (
		<footer className="mt-24 border-rule border-t">
			<div className="mx-auto grid max-w-6xl gap-6 px-4 py-10 text-sm sm:px-6 md:grid-cols-[2fr_1fr]">
				<div className="max-w-[60ch] space-y-2">
					<p className="font-semibold">Responsible use</p>
					<p className="text-ink-soft">
						Only audit systems you own or are authorised to test. openaudit
						sends real requests to the targets you give it; scanning third
						parties without permission may be illegal where you live.
					</p>
				</div>
				<nav aria-label="Footer">
					<ul className="space-y-1">
						<li>
							<Link
								to="/docs"
								className="text-ink-soft hover:text-ink hover:underline"
							>
								Documentation
							</Link>
						</li>
						<li>
							<Link
								to="/auditors"
								className="text-ink-soft hover:text-ink hover:underline"
							>
								Auditor catalog
							</Link>
						</li>
						<li>
							<Link
								to="/report"
								className="text-ink-soft hover:text-ink hover:underline"
							>
								Report viewer
							</Link>
						</li>
					</ul>
				</nav>
			</div>
		</footer>
	);
}
