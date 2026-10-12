import type { Report } from "../model";
import { toHtml } from "./html";
import { toJson } from "./json";
import { toMarkdown } from "./markdown";
import { toSarif } from "./sarif";
import { toTerminal } from "./terminal";

export { type HtmlOptions, toHtml } from "./html";
export { canonicalize, type JsonOptions, toJson } from "./json";
export { type MarkdownOptions, toMarkdown } from "./markdown";
export { type SarifOptions, toSarif, toSarifLog } from "./sarif";
export { jsonSchemaOf, reportJsonSchema } from "./schema";
export {
	escapeHtml,
	formatDuration,
	formatLocation,
	sortedFindings,
	targetLabel,
} from "./shared";
export { colorEnabled, type TerminalOptions, toTerminal } from "./terminal";

export const REPORT_FORMATS = [
	"terminal",
	"json",
	"sarif",
	"markdown",
	"html",
] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/** File extension used when writing `openaudit-report.<ext>`. */
export const FORMAT_EXTENSIONS: Record<ReportFormat, string> = {
	terminal: "txt",
	json: "json",
	sarif: "sarif",
	markdown: "md",
	html: "html",
};

export const isReportFormat = (value: string): value is ReportFormat =>
	(REPORT_FORMATS as ReadonlyArray<string>).includes(value);

/** Renders a report in any format with default options. */
export const renderReport = (
	report: Report,
	format: ReportFormat,
	options: { readonly color?: boolean; readonly verbose?: boolean } = {},
): string => {
	switch (format) {
		case "json":
			return toJson(report);
		case "sarif":
			return toSarif(report);
		case "markdown":
			return toMarkdown(report);
		case "html":
			return toHtml(report);
		case "terminal":
			return toTerminal(report, options);
	}
};
