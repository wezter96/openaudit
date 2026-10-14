import {
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, jsonLines, num, str } from "../../tool";
import { isRecord, kebab, scrubLine, truncate } from "../util";
import { dedupe, inRoot, manifestDirs, run, withTempDir } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                   clippy                                   */
/* -------------------------------------------------------------------------- */

type ClippyGroup =
	| "correctness"
	| "suspicious"
	| "perf"
	| "complexity"
	| "style"
	| "other";

const words = (s: string) => new Set(s.split(/\s+/).filter(Boolean));

// The JSON `code` field carries only the lint name (`clippy::needless_bool`),
// not its group, so the groups are listed here. Unlisted clippy lints at
// `error` level are deny-by-default, which is the correctness group.
const CLIPPY_CORRECTNESS = words(`
	absurd_extreme_comparisons approx_constant async_yields_async bad_bit_mask
	cast_slice_different_sizes deprecated_semver derive_ord_xor_partial_ord
	derived_hash_with_manual_eq eager_transmute enum_clike_unportable_variant
	eq_op erasing_op fn_address_comparisons if_let_mutex ifs_same_cond
	impl_hash_borrow_with_str_and_bytes impossible_comparisons ineffective_bit_mask
	infinite_iter inherent_to_string_shadow_display inline_fn_without_body
	invalid_null_ptr_usage invalid_regex invisible_characters iter_next_loop
	iter_skip_zero let_underscore_lock lint_groups_priority match_str_case_mismatch
	mem_replace_with_uninit min_max mismatched_target_os mistyped_literal_suffixes
	modulo_one mut_from_ref nonsensical_open_options not_unsafe_ptr_arg_deref
	option_env_unwrap out_of_bounds_indexing overly_complex_bool_expr
	panicking_overflow_checks panicking_unwrap read_line_without_trim
	recursive_format_impl redundant_comparisons reversed_empty_ranges
	self_assignment serde_api_misuse size_of_in_element_count suspicious_splitn
	transmute_null_to_fn transmuting_null uninit_assumed_init uninit_vec
	unit_cmp unit_hash unit_return_expecting_ord unused_io_amount
	while_immutable_condition wrong_transmute zst_offset
`);

const CLIPPY_SUSPICIOUS = words(`
	almost_complete_range arc_with_non_send_sync await_holding_invalid_type
	await_holding_lock await_holding_refcell_ref blanket_clippy_restriction_lints
	cast_abs_to_unsigned cast_enum_constructor cast_enum_truncation
	cast_nan_to_int cast_slice_from_raw_parts crate_in_macro_def
	drop_non_drop duplicate_underscore_argument duration_subsec empty_docs
	empty_loop float_equality_without_abs forget_non_drop four_forward_slashes
	from_raw_with_void_ptr ifs_same_cond incompatible_msrv ineffective_open_options
	inherent_to_string_shadow_display js_unwrap_in_wasm let_underscore_future
	lines_filter_map_ok maybe_misused_cfg misnamed_getters misrefactored_assign_op
	mixed_attributes_style multiple_bound_locations mut_range_bound mutable_key_type
	no_effect_replace non_canonical_clone_impl non_canonical_partial_ord_impl
	octal_escapes path_ends_with_ext possible_missing_comma print_in_format_impl
	rc_clone_in_vec_init repeat_vec_with_capacity single_component_path_imports
	size_of_ref suspicious_arithmetic_impl suspicious_assignment_formatting
	suspicious_command_arg_space suspicious_doc_comments suspicious_else_formatting
	suspicious_map suspicious_op_assign_impl suspicious_open_options
	suspicious_to_owned suspicious_unary_op_formatting swap_ptr_to_ref
	test_attr_in_doctest type_id_on_box unconditional_recursion
	unnecessary_clippy_cfg unused_format_specs
`);

const CLIPPY_PERF = words(`
	box_collection boxed_local cmp_owned collapsible_str_replace drain_collect
	expect_fun_call extend_with_drain format_collect format_in_format_args
	iter_overeager_cloned iter_nth large_const_arrays large_enum_variant
	manual_contains manual_memcpy manual_retain manual_str_repeat manual_try_fold
	map_entry missing_const_for_thread_local needless_collect redundant_allocation
	result_large_err single_char_pattern slow_vector_initialization
	to_string_in_format_args unnecessary_to_owned useless_vec vec_init_then_push
	waker_clone_wake
`);

const CLIPPY_COMPLEXITY = words(`
	bind_instead_of_map borrowed_box bool_comparison clone_on_copy
	collapsible_if collapsible_else_if crosspointer_transmute deprecated_cfg_attr
	double_comparisons explicit_auto_deref explicit_counter_loop filter_next
	identity_op if_same_then_else int_plus_one iter_count let_and_return
	manual_filter manual_flatten manual_map manual_range_contains manual_strip
	map_flatten match_like_matches_macro needless_bool needless_borrow
	needless_lifetimes needless_option_as_deref needless_range_loop
	needless_return nonminimal_bool option_map_unit_fn partialeq_ne_impl
	redundant_closure redundant_slicing search_is_some too_many_arguments
	type_complexity unit_arg unnecessary_cast unnecessary_unwrap useless_conversion
	useless_format
`);

/** Lints about memory safety or unsound `unsafe`. */
const CLIPPY_SECURITY = words(`
	not_unsafe_ptr_arg_deref uninit_assumed_init uninit_vec wrong_transmute
	transmute_null_to_fn transmuting_null mem_replace_with_uninit zst_offset
	cast_ptr_alignment cast_slice_different_sizes transmute_ptr_to_ref
	missing_safety_doc undocumented_unsafe_blocks unsound_collection_transmute
	from_raw_with_void_ptr invalid_null_ptr_usage
`);

const clippyGroup = (name: string, level: string): ClippyGroup => {
	if (CLIPPY_CORRECTNESS.has(name)) return "correctness";
	if (CLIPPY_SUSPICIOUS.has(name)) return "suspicious";
	if (CLIPPY_PERF.has(name)) return "perf";
	if (CLIPPY_COMPLEXITY.has(name)) return "complexity";
	// Deny-by-default lints that are not listed above are correctness lints.
	return level === "error" ? "correctness" : "style";
};

/** rustc lints that point at a likely bug rather than tidiness. */
const RUSTC_RELIABILITY = words(`
	arithmetic_overflow unconditional_recursion overflowing_literals
	unused_must_use unused_comparisons unreachable_code unreachable_patterns
	invalid_value unconditional_panic useless_deprecated ambiguous_associated_items
	unused_results_ignored dropping_references forgetting_references
`);

const CLIPPY_SEVERITY: Record<ClippyGroup, Severity> = {
	correctness: "high",
	suspicious: "medium",
	perf: "low",
	complexity: "low",
	style: "info",
	other: "info",
};

/**
 * Parses `cargo clippy --message-format=json` output (one JSON object per
 * line). Only `compiler-message` records with a primary span inside the
 * workspace become findings; duplicates from building one crate for several
 * targets (lib, bin, tests) are collapsed.
 */
export const parseClippyReport = (
	stdout: string,
	root: string,
	prefix = "",
): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const record of jsonLines(stdout)) {
		if (record.reason !== "compiler-message") continue;
		const msg = record.message;
		if (!isRecord(msg)) continue;
		const level = str(msg.level);
		if (level !== "warning" && level !== "error") continue;
		const span = arr(msg.spans).find(
			(s): s is Record<string, unknown> => isRecord(s) && s.is_primary === true,
		);
		if (!span) continue;
		const file = inRoot(root, str(span.file_name));
		if (!file) continue;
		const code = isRecord(msg.code) ? str(msg.code.code) : undefined;
		const message = str(msg.message) ?? "lint";
		const isClippy = code?.startsWith("clippy::") === true;
		const name = isClippy ? (code as string).slice("clippy::".length) : code;
		// A compile error (E0xxx) or a rustc lint without clippy's group.
		const isCompileError = level === "error" && !isClippy && !name;
		const compileCode = !isClippy && name && /^E\d{4}$/.test(name);
		const group = isClippy && name ? clippyGroup(name, level) : "other";
		const security = isClippy && name && CLIPPY_SECURITY.has(name);
		let category: Category;
		let severity: Severity;
		if (isClippy) {
			severity = CLIPPY_SEVERITY[group];
			if (security) {
				category = "security";
				if (severity === "info" || severity === "low") severity = "medium";
			} else if (group === "perf") category = "performance";
			else if (group === "correctness" || group === "suspicious")
				category = "reliability";
			else category = "maintainability";
			// Deny-level configuration (`-D warnings`, `[lints.clippy]`) is the
			// project's own bar: never report it below low.
			if (level === "error" && severity === "info") severity = "low";
		} else if (isCompileError || compileCode) {
			category = "reliability";
			severity = "medium";
		} else if (level === "error") {
			category = "reliability";
			severity = "high";
		} else if (name && RUSTC_RELIABILITY.has(name)) {
			category = "reliability";
			severity = "low";
		} else {
			category = "maintainability";
			severity = "info";
		}
		const lineNo = num(span.line_start);
		const column = num(span.column_start);
		const sourceText = arr(span.text)
			.map((t) => (isRecord(t) ? str(t.text) : undefined))
			.find(Boolean);
		const label = name ?? (isCompileError ? "compile-error" : "diagnostic");
		findings.push({
			ruleId: `code.clippy/${kebab(label)}`,
			title: truncate(message, 100),
			severity,
			category,
			message: isClippy
				? `${message} (clippy::${name}, ${group})`
				: `${message} (rustc${name ? ` ${name}` : ""})`,
			location: {
				file: prefix ? `${prefix}/${file}` : file,
				line: lineNo,
				column,
			},
			evidence: sourceText ? truncate(scrubLine(sourceText)) : undefined,
			remediation: isClippy
				? "Apply the suggested change, or silence a justified false positive with a scoped `#[allow(clippy::...)]` that explains why."
				: "Fix the diagnostic reported by the compiler.",
			references:
				isClippy && name
					? [
							`https://rust-lang.github.io/rust-clippy/master/index.html#${name}`,
						]
					: [],
			confidence: isCompileError || compileCode ? "low" : "high",
			tags: ["rust", ...(isClippy ? [`clippy-${group}`] : [])],
		});
	}
	return dedupe(findings);
};

export const clippy = defineAuditor({
	id: "code.clippy",
	title: "Rust clippy lints",
	description:
		"Runs `cargo clippy` over Rust crates and workspaces. NOT safe on untrusted code: clippy compiles the crate, so it runs build.rs scripts, proc-macros and any .cargo/config.toml hooks of the target, which is why it is opt-in. Runs with --locked --offline (needs a committed Cargo.lock and already vendored or cached dependencies; nothing is downloaded) and a throwaway target dir. clippy::correctness findings are high, suspicious medium, perf and complexity low, style info; compile errors are reported with low confidence.",
	categories: ["reliability", "maintainability", "performance", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "cargo",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			const crates = manifestDirs(files, "Cargo.toml", false);
			if (crates.length === 0)
				return yield* skip("No Cargo.toml in the workspace");
			const locked = crates.filter((d) =>
				files.includes(d ? `${d}/Cargo.lock` : "Cargo.lock"),
			);
			if (locked.length === 0)
				return yield* skip(
					"No Cargo.lock next to Cargo.toml: clippy runs --locked --offline and would otherwise have to resolve (download) dependencies",
				);
			const cargo = yield* requireTool(
				ctx,
				"cargo",
				"Install the Rust toolchain: https://rustup.rs.",
			);
			yield* requireTool(
				ctx,
				"cargo-clippy",
				"Install: rustup component add clippy.",
			);
			const findings: FindingInput[] = [];
			for (const dir of locked) {
				const res = yield* withTempDir((target) =>
					run(
						ctx,
						[
							cargo,
							"clippy",
							"--message-format=json",
							"--all-targets",
							"--workspace",
							"--locked",
							"--offline",
							"--target-dir",
							target,
						],
						{
							cwd: ws.absolute(dir || "."),
							// 101 = a lint at deny level or a compile error.
							okCodes: [0, 101],
							env: {
								CARGO_TERM_COLOR: "never",
								CARGO_NET_OFFLINE: "true",
							},
						},
					),
				);
				// Resolution failures print to stderr and never reach build-finished.
				if (!res.stdout.includes('"reason":"build-finished"'))
					return yield* Effect.fail(
						new AuditorError({
							message: `cargo clippy failed: ${truncate(res.stderr || res.stdout, 300)}`,
						}),
					);
				findings.push(
					...parseClippyReport(res.stdout, ws.absolute(dir || "."), dir),
				);
			}
			return findings;
		}),
});
