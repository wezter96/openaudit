import { useEffect, useState } from "react";

export function Counter({ enabled, step }: { enabled: boolean; step: number }) {
	if (enabled) {
		const [count, setCount] = useState(0);
		useEffect(() => {
			setCount(count + step);
		}, []);
		return <p>{count}</p>;
	}
	return null;
}

export function List({ items }: { items: string[] }) {
	return (
		<ul>
			{items.map((item) => (
				<li>{item}</li>
			))}
		</ul>
	);
}
