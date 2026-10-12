/** A small inspection tag: the openaudit mark. Decorative; the wordmark carries the name. */
export function TagMark({ className }: { className?: string }) {
	return (
		<svg
			viewBox="0 0 24 28"
			aria-hidden="true"
			focusable="false"
			className={className}
		>
			<path
				d="M5 1h14l4 4.5V26a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V5.5Z"
				fill="var(--tag)"
				stroke="var(--tag-edge)"
				strokeWidth="1.5"
			/>
			<circle
				cx="12"
				cy="7"
				r="2.25"
				fill="var(--paper)"
				stroke="var(--tag-edge)"
				strokeWidth="1.5"
			/>
			<path
				d="m7 17.5 3.2 3.2L17 14"
				fill="none"
				stroke="var(--tag-ink)"
				strokeWidth="2.4"
				strokeLinecap="round"
				strokeLinejoin="round"
			/>
		</svg>
	);
}
