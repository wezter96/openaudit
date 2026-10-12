// Accessible patterns that code.accessibility must not flag.
type Props = { onOpen: () => void; label: string; rest: Record<string, unknown> };

export function Good({ onOpen, label, rest }: Props) {
	return (
		<main>
			<img src="/logo.png" alt="Company logo" />
			<img src="/divider.png" alt="" />
			<img {...rest} />
			<div role="button" tabIndex={0} onClick={onOpen} onKeyDown={onOpen}>
				Open
			</div>
			<a href="/docs">Docs</a>
			<button type="button" onClick={onOpen} aria-label="Close">
				<svg viewBox="0 0 10 10" />
			</button>
			<button type="button" onClick={onOpen}>
				{label}
			</button>
			<label htmlFor="email">Email</label>
			<input id="email" type="email" />
			<label>
				Name <input type="text" />
			</label>
			<input type="hidden" name="csrf" />
			<input aria-label="Search" type="search" />
			<button className="outline-none focus-visible:ring-2" type="button">
				Ring
			</button>
			{items.map((i) => (i < 3 ? <span key={i}>{i}</span> : null))}
		</main>
	);
}

declare const items: number[];
