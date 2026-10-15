/** Domain aliases for the lockfile auditor, so signatures say what a string holds. */

/** A path relative to the scanned workspace root, with `/` separators. */
export type FilePath = string;
/** An absolute or relative URL, or a source spec that may become one. */
export type Url = string;
/** A registry or package host name. */
export type Host = string;
/** A package name as written in a manifest or lockfile. */
export type PackageName = string;
/** A raw resolved/source spec from a lockfile entry. */
export type SourceSpec = string;
/** A line of text from a lockfile or requirements file. */
export type TextLine = string;
/** File contents. */
export type FileText = string;
/** An SRI integrity string, possibly several space-separated hashes. */
export type Integrity = string;
