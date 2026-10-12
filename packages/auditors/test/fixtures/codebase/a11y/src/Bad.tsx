// Intentionally inaccessible fixture for code.accessibility tests.
export function Bad({ onOpen }: { onOpen: () => void }) {
	return (
		<div>
			<img src="/hero.png" />
			<div onClick={onOpen}>Open</div>
			<a onClick={onOpen}>Do it</a>
			<a href="#" onClick={onOpen}>
				Also do it
			</a>
			<span tabIndex={3}>Focusable</span>
			<input autoFocus type="text" placeholder="Search" />
			<button onClick={onOpen}>
				<svg viewBox="0 0 10 10" />
			</button>
			<button className="px-2 outline-none" onClick={onOpen}>
				Plain
			</button>
		</div>
	);
}
