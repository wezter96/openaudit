import type { Report } from "@openaudit/core/model";
import { Button } from "@openaudit/ui/components/button";
import { Input } from "@openaudit/ui/components/input";
import { useMutation } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { useId, useState } from "react";

import { orpc } from "@/utils/orpc";

/** Adds https:// when the scheme is left out ("example.com"). */
const normalize = (value: string) => {
	const v = value.trim();
	return /^[a-z][a-z0-9+.-]*:/i.test(v) ? v : `https://${v}`;
};

export function AuditUrlForm({
	onReport,
}: {
	onReport: (report: Report) => void;
}) {
	const id = useId();
	const [url, setUrl] = useState("");
	const audit = useMutation(
		orpc.audit.url.mutationOptions({
			onSuccess: (report) => onReport(report),
		}),
	);

	return (
		<form
			aria-labelledby={`${id}-title`}
			aria-busy={audit.isPending}
			onSubmit={(e) => {
				e.preventDefault();
				if (!url.trim() || audit.isPending) return;
				audit.mutate({ url: normalize(url) });
			}}
			className="border border-rule bg-surface p-4 sm:p-5"
		>
			<h2 id={`${id}-title`} className="font-semibold text-lg">
				Audit a URL
			</h2>
			<p id={`${id}-help`} className="mt-1 text-ink-soft text-sm">
				Runs the built-in web checks from our server, without a browser: up to 5
				pages, about a minute at most. Only audit sites you own or are
				authorised to test.
			</p>
			<div className="mt-4 flex flex-col gap-2 sm:flex-row">
				<label htmlFor={`${id}-url`} className="sr-only">
					Website URL
				</label>
				<Input
					id={`${id}-url`}
					name="url"
					type="text"
					inputMode="url"
					autoComplete="url"
					spellCheck={false}
					required
					maxLength={2048}
					placeholder="https://your-site.example"
					aria-describedby={`${id}-help${audit.isError ? ` ${id}-error` : ""}`}
					aria-invalid={audit.isError || undefined}
					value={url}
					onChange={(e) => setUrl(e.target.value)}
					className="h-11 bg-paper px-3 font-mono text-base sm:flex-1 md:text-sm"
				/>
				<Button
					type="submit"
					disabled={audit.isPending}
					className="h-11 px-5 font-semibold text-sm"
				>
					{audit.isPending ? (
						<>
							<Loader2 aria-hidden="true" className="animate-spin" />
							Auditing…
						</>
					) : (
						"Run audit"
					)}
				</Button>
			</div>
			<div aria-live="polite" className="text-sm">
				{audit.isPending && (
					<p className="mt-3 text-ink-soft">
						Fetching {normalize(url)} and running the web auditors…
					</p>
				)}
				{audit.isError && (
					<p id={`${id}-error`} className="mt-3 font-medium text-sev-critical">
						{audit.error.message}
					</p>
				)}
			</div>
		</form>
	);
}
