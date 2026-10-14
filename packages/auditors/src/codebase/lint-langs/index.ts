/**
 * Strict linters and type checkers for Rust (clippy), Python (ruff, mypy), Go
 * (staticcheck, golangci-lint), shell (ShellCheck), PHP (PHPStan) and Java
 * (PMD). Tools that can execute target code (clippy: build scripts and
 * proc-macros; mypy: plugins; golangci-lint: plugins) are opt-in; PHPStan and
 * PMD ignore project config that could.
 */

export * from "./go";
export * from "./java";
export * from "./php";
export * from "./python";
export * from "./rust";
export * from "./shell";
