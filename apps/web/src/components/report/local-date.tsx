import { useEffect, useState } from "react";

/**
 * Renders a timestamp in UTC on the server and in the visitor's locale and
 * timezone after hydration, so server and client markup match.
 */
export function LocalDate({
	iso,
	withTime = false,
}: {
	iso: string;
	withTime?: boolean;
}) {
	const [hydrated, setHydrated] = useState(false);
	useEffect(() => setHydrated(true), []);

	const date = new Date(iso);
	if (Number.isNaN(date.getTime())) return <>{iso}</>;
	const options: Intl.DateTimeFormatOptions = withTime
		? { dateStyle: "medium", timeStyle: "short" }
		: { dateStyle: "medium" };

	return (
		<time dateTime={date.toISOString()}>
			{hydrated
				? date.toLocaleString(undefined, options)
				: `${date.toLocaleString("en-GB", { ...options, timeZone: "UTC" })}${withTime ? " UTC" : ""}`}
		</time>
	);
}
