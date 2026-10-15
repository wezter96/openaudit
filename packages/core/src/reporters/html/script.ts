/*
 * Progressive enhancement for the HTML report. Without it every panel shows
 * stacked and complete; with it the panels become WAI-ARIA tabs (selected tab
 * in the URL hash), the findings get filters, and the page gets its motion:
 * one load sequence on the overview, and motion that answers the reader
 * (tab ink, panel slide, disclosure height, filter counts). Every listener is
 * delegated, so the page stays fast with thousands of findings. Reduced
 * motion shows final states immediately. The browser code lives in report.js,
 * imported as text; the report inlines it and allows it by hash.
 */
import report from "./report.js" with { type: "text" };

export const SCRIPT: string = report;
