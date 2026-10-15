/** Workspace-relative path of a file. */
export type FilePath = string;
/** Full text of a file. */
export type SourceText = string;
/** One line of a file, or what is left of it after stripping. */
export type SourceLine = string;
/** 1-based line number. */
export type LineNumber = number;
/** 0-based character offset within a line or text. */
export type Offset = number;
/** Indentation width in columns. */
export type Indent = number;
/** Name of a package.json script. */
export type ScriptName = string;
