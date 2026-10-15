/** Domain names for the values the shared codebase helpers pass around. */

/** Workspace-relative path of a file. */
export type FilePath = string;
/** Text of a file, or a line or fragment of it. */
export type SourceText = string;
/** Character offset into a source text. */
export type Offset = number;
/** Language id from `LANGUAGE_BY_EXT` (`js`, `python`, ...). */
export type Language = string;
/** A count of characters. */
export type CharCount = number;
/** A CWE number, such as 79. */
export type CweId = number;
/** An entry of a standard: an OWASP category (`a03`) or WCAG criterion (`1.1.1`). */
export type StandardId = string;
