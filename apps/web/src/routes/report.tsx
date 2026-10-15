import type { Report } from "@openaudit/core/model";
import { Button } from "@openaudit/ui/components/button";
import { Textarea } from "@openaudit/ui/components/textarea";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { FileJson } from "lucide-react";
import type React from "react";
import { useEffect, useId, useRef, useState } from "react";

import { ReportView } from "@/components/report/report-view";
import { sampleReport } from "@/lib/sample-report";

const MAX_BYTES = 25 * 1024 * 1024;

export const Route = createFileRoute("/report")({
	validateSearch: (search: Record<string, unknown>): { example?: boolean } =>
		search.example === true || search.example === "true"
			? { example: true }
			: {},
	head: () => ({
		meta: [
			{ title: "Report viewer | openaudit" },
			{
				name: "description",
				content:
					"Open an openaudit JSON report in your browser: scores, filterable findings and auditor status. Nothing is uploaded.",
			},
		],
	}),
	component: ReportPage,
});

/** Reads and validates a report the visitor picks or pastes. */
function useReportFile() {
	const [loaded, setLoaded] = useState<Report | undefined>();
	const [error, setError] = useState<string | undefined>();
	const [busy, setBusy] = useState(false);

	const open = async (raw: string) => {
		setBusy(true);
		setError(undefined);
		try {
			const { validateReport } = await import("@/lib/validate-report");
			const result = validateReport(raw);
			if (result.ok) setLoaded(result.report);
			else setError(result.error);
		} finally {
			setBusy(false);
		}
	};

	const onFile = async (file: File | undefined) => {
		if (!file) return;
		if (file.size > MAX_BYTES) {
			setError(
				`That file is ${(file.size / 1024 / 1024).toFixed(1)} MB; the viewer opens reports up to 25 MB.`,
			);
			return;
		}
		await open(await file.text());
	};

	const clear = () => {
		setLoaded(undefined);
		setError(undefined);
	};

	return { loaded, error, busy, open, onFile, clear };
}

/** Moves focus to `ref` whenever `value` becomes set. */
function useFocusWhen(
	value: unknown,
	ref: React.RefObject<HTMLElement | null>,
) {
	useEffect(() => {
		if (value) ref.current?.focus();
	}, [value, ref]);
}

function ReportIntro() {
	return (
		<div className="max-w-[60ch]">
			<h1 className="font-extrabold text-4xl tracking-tight sm:text-5xl">
				Report viewer
			</h1>
			<p className="mt-3 text-ink-soft">
				Open a report from{" "}
				<code className="font-mono text-ink">openaudit --json</code> or{" "}
				<code className="font-mono text-ink">
					--format json --out report.json
				</code>
				. It is read and checked in your browser; nothing is uploaded.
			</p>
		</div>
	);
}

function PickFile({
	onFile,
	onExample,
}: {
	onFile: (file: File | undefined) => Promise<void>;
	onExample: () => void;
}) {
	return (
		<div className="space-y-4">
			<div>
				<p className="mb-2 font-semibold">Report file</p>
				<label className="flex cursor-pointer flex-col items-center gap-2 border-2 border-rule border-dashed bg-surface px-6 py-10 text-center hover:border-signal has-[:focus-visible]:outline-3 has-[:focus-visible]:outline-[var(--focus)] has-[:focus-visible]:outline-offset-2">
					<FileJson aria-hidden="true" className="size-8 text-ink-soft" />
					<span className="font-medium">Choose a .json report</span>
					<span className="text-ink-soft text-sm">Up to 25 MB</span>
					<input
						type="file"
						accept="application/json,.json"
						className="sr-only"
						onChange={(e) => {
							void onFile(e.target.files?.[0]);
							e.target.value = "";
						}}
					/>
				</label>
			</div>
			<p className="text-ink-soft text-sm">
				No report yet?{" "}
				<button
					type="button"
					className="text-signal underline underline-offset-2"
					onClick={onExample}
				>
					Load the example report
				</button>
			</p>
		</div>
	);
}

function PasteJson({
	id,
	text,
	setText,
	busy,
	error,
}: {
	id: string;
	text: string;
	setText: (text: string) => void;
	busy: boolean;
	error: string | undefined;
}) {
	return (
		<div className="space-y-3">
			<label htmlFor={`${id}-json`} className="block font-semibold">
				Or paste the JSON
			</label>
			<Textarea
				id={`${id}-json`}
				value={text}
				onChange={(e) => setText(e.target.value)}
				spellCheck={false}
				placeholder='{"schemaVersion": "1", …}'
				aria-describedby={error ? `${id}-error` : undefined}
				className="field-sizing-fixed h-56 resize-y bg-surface font-mono text-sm md:text-sm"
			/>
			<Button
				type="submit"
				disabled={busy || !text.trim()}
				className="h-10 px-5 font-semibold text-sm"
			>
				Open report
			</Button>
		</div>
	);
}

function ChooseReport({
	id,
	text,
	setText,
	busy,
	error,
	onOpen,
	onFile,
	onExample,
}: {
	id: string;
	text: string;
	setText: (text: string) => void;
	busy: boolean;
	error: string | undefined;
	onOpen: (raw: string) => Promise<void>;
	onFile: (file: File | undefined) => Promise<void>;
	onExample: () => void;
}) {
	return (
		<form
			aria-labelledby={`${id}-title`}
			className="mt-10 grid gap-8 lg:grid-cols-[1fr_1.4fr]"
			onSubmit={(e) => {
				e.preventDefault();
				if (text.trim()) void onOpen(text);
			}}
		>
			<h2 id={`${id}-title`} className="sr-only">
				Choose a report
			</h2>
			<PickFile onFile={onFile} onExample={onExample} />
			<PasteJson
				id={id}
				text={text}
				setText={setText}
				busy={busy}
				error={error}
			/>
		</form>
	);
}

function OpenError({
	id,
	error,
	errorRef,
}: {
	id: string;
	error: string;
	errorRef: React.Ref<HTMLDivElement>;
}) {
	return (
		<div
			ref={errorRef}
			tabIndex={-1}
			role="alert"
			id={`${id}-error`}
			className="mt-8 border-sev-critical border-l-4 bg-surface p-4"
		>
			<p className="font-semibold">The report could not be opened</p>
			<pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap font-mono text-ink-soft text-sm">
				{error}
			</pre>
		</div>
	);
}

function ReportPage() {
	const { example } = Route.useSearch();
	const navigate = useNavigate({ from: "/report" });
	const id = useId();
	const file = useReportFile();
	const [text, setText] = useState("");
	const errorRef = useRef<HTMLDivElement>(null);
	const titleRef = useRef<HTMLHeadingElement>(null);

	const { loaded, error } = file;
	const report = loaded ?? (example ? sampleReport : undefined);

	useFocusWhen(loaded, titleRef);
	useFocusWhen(error, errorRef);

	const reset = () => {
		file.clear();
		if (example) navigate({ search: {} });
	};

	return (
		<div className="mx-auto max-w-6xl px-4 pt-12 sm:px-6">
			<div className="flex flex-wrap items-end justify-between gap-4">
				<ReportIntro />
				{report && (
					<Button
						variant="outline"
						className="h-10 px-4 text-sm"
						onClick={reset}
					>
						Open another report
					</Button>
				)}
			</div>

			{report ? (
				<div className="mt-12">
					<ReportView
						report={report}
						titleRef={titleRef}
						tagCaption={loaded ? undefined : "Example report"}
					/>
				</div>
			) : (
				<ChooseReport
					id={id}
					text={text}
					setText={setText}
					busy={file.busy}
					error={error}
					onOpen={file.open}
					onFile={file.onFile}
					onExample={() => navigate({ search: { example: true } })}
				/>
			)}

			{error && !report && (
				<OpenError id={id} error={error} errorRef={errorRef} />
			)}
		</div>
	);
}
