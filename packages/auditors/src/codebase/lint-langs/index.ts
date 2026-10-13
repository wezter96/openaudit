/**
 * Strict linters and type checkers for Rust (clippy), Python (ruff, mypy), Go
 * (staticcheck, golangci-lint) and shell (ShellCheck). Tools that can execute
 * target code (clippy: build scripts and proc-macros; mypy: plugins;
 * golangci-lint: plugins) are opt-in.
 */

export * from "./go";
export * from "./python";
export * from "./rust";
export * from "./shell";
