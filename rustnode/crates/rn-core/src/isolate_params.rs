//! The `CreateParams` a Node isolate is built with.
//!
//! V8's fallback heap sizing is chosen for a browser: 1.4 GB of old generation
//! on 64-bit and a small semi-space, regardless of how much memory the machine
//! actually has. Node overrides that in
//! `src/api/environment.cc::SetIsolateCreateParamsForNode` by asking libuv how
//! much memory the process may use and handing the answer to
//! `ResourceConstraints::ConfigureDefaults`. An embedder that skips the call
//! gets V8's browser numbers instead, which is observable from JavaScript
//! through `v8.getHeapStatistics().heap_size_limit` and through how much
//! scavenging startup does.
//!
//! # Why the memory is passed in rather than read here
//!
//! `uv_get_total_memory` and `uv_get_constrained_memory` are libuv, and this
//! crate sits below the libuv layer (`rn-uv` depends on it, not the other way
//! round). They are also not "physical memory" in any simple sense: libuv reads
//! the cgroup limit on Linux, so the answer is what the process is allowed to
//! use, and reproducing that rule second-hand would be the wrong kind of
//! reimplementation. Callers pass the two numbers; [`installable_memory`] is
//! the arithmetic Node does with them and is testable without libuv at all.
//!
//! # The `== 0` gate
//!
//! Node only configures when `max_old_generation_size_in_bytes()` is still
//! zero, i.e. when nothing has sized the heap yet. That is *not* a check for
//! `--max-old-space-size`: that is a V8 flag, it lands in
//! `v8_flags.max_old_space_size`, and `Heap::ConfigureHeap` applies it on top
//! of whatever the constraints say. Measured on the pinned oracle,
//! `node --max-old-space-size=100 -e 'v8.getHeapStatistics().heap_size_limit'`
//! answers 196 MB, which is the 100 MB the user asked for plus the 96 MB young
//! generation `ConfigureDefaults` picked from the machine. Skipping the call
//! because the user named a size would answer about 104 MB and diverge from the
//! reference for a flag the user *did* set.
//!
//! The gate does matter for the one caller that pre-sizes the heap: a
//! `Worker`'s `resourceLimits`. `src/node_worker.cc` calls this function first
//! and `UpdateResourceConstraints` second, so the limits the user named are
//! applied on top, and only the ones left at zero are configured here.

use rn_v8_sys::v8;

/// The memory Node sizes the heap from, out of libuv's two answers.
///
/// `uv_get_constrained_memory` is the cgroup limit and is 0 when there is
/// none; `uv_get_total_memory` is the machine's total. Node takes the smaller
/// of the two so a container limit wins over the host's real memory.
#[must_use]
pub fn installable_memory(constrained_memory: u64, total_memory: u64) -> u64 {
    if constrained_memory > 0 {
        total_memory.min(constrained_memory)
    } else {
        total_memory
    }
}

/// `SetIsolateCreateParamsForNode`: size the heap from the machine.
///
/// `constrained_memory` and `total_memory` are libuv's
/// `uv_get_constrained_memory()` and `uv_get_total_memory()`.
pub fn set_isolate_create_params_for_node(
    params: v8::CreateParams,
    constrained_memory: u64,
    total_memory: u64,
) -> v8::CreateParams {
    let memory = installable_memory(constrained_memory, total_memory);
    if memory > 0 && params.max_old_generation_size_in_bytes() == 0 {
        // `ConfigureDefaults(physical_memory, virtual_memory_limit)`: the
        // second argument is the virtual-memory limit, which Node passes as
        // zero because it has none to declare. It only affects the code range.
        return params.heap_limits_from_system_memory(memory, 0);
    }
    params
}

/// Whether the linked V8 keeps its heap in a pointer-compressed cage.
///
/// `v8-152.2.0/build.rs:419-433` sets `v8_enable_pointer_compression=false`
/// unless the `v8_enable_pointer_compression` feature is on, and this workspace
/// enables neither it nor the sandbox. Node's calculation branches on the same
/// define, so the branch is kept with the answer this build would take rather
/// than dropped: a build that turned the feature on would otherwise silently
/// keep using the uncompressed rule.
const POINTER_COMPRESSION: bool = false;

/// The largest heap pointer compression can address, in bytes.
const MAX_POINTER_COMPRESSION_HEAP: u64 = 4 * 1024 * 1024 * 1024;

/// The percentage → megabytes conversion of
/// `PerIsolateOptions::HandleMaxOldSpaceSizePercentage`
/// (`src/node_options.cc:237`).
///
/// The memory this uses is *not* [`installable_memory`]: when a constraint
/// exists Node takes it whole, without the `min` against total memory, and the
/// total is capped at 4 GiB when pointer compression is on because that is all
/// the cage can address. Both differences are measured on the pinned oracle —
/// `--max-old-space-size-percentage=50` on a 47 GB box reports a 23677 MB
/// `heap_size_limit`, which is 50% of the 47162 MB cgroup limit rounded down,
/// plus the 96 MB young generation.
///
/// Returns `Err` with Node's message when the input is not a percentage.
pub fn max_old_space_size_percentage_mb(
    input: &str,
    constrained_memory: u64,
    total_memory: u64,
) -> Result<u64, String> {
    // `std::strtod` accepts leading whitespace, a sign, and hexadecimal, and
    // requires the whole string to be consumed (`*end_ptr != '\0'`). Every one
    // of those is observable: the oracle accepts ` 50`, `+50` and `0x10`, and
    // rejects `1%`.
    let percentage = strtod(input);
    let valid = match percentage {
        Some(percentage) => percentage > 0.0 && percentage <= 100.0,
        None => false,
    };
    if !valid {
        return Err(format!(
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: {input}"
        ));
    }
    let percentage = percentage.unwrap_or(0.0);

    let total_memory = if POINTER_COMPRESSION {
        total_memory.min(MAX_POINTER_COMPRESSION_HEAP)
    } else {
        total_memory
    };
    // `constrained_memory > 0 && constrained_memory != UINT64_MAX`: libuv
    // answers 0 when there is no cgroup limit, and the v1 cgroup file reports
    // `UINT64_MAX` for an unmetered process.
    let available_memory = if constrained_memory > 0 && constrained_memory != u64::MAX {
        constrained_memory
    } else {
        total_memory
    };
    if available_memory == 0 {
        return Err("the available memory can not be calculated".to_string());
    }

    let memory_mb = available_memory / (1024 * 1024);
    // `static_cast<size_t>(memory_mb * percentage / 100.0)`: the multiply
    // happens in `double` and the truncation toward zero is the cast.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the range is checked above to be (0, 100], so the product is \
                  a finite non-negative number far below u64::MAX"
    )]
    let mb = (memory_mb as f64 * percentage / 100.0) as u64;
    Ok(mb)
}

/// `std::strtod`'s conversion, or `None` when it would not consume everything.
///
/// A hand-written scanner rather than Rust's parser alone, because the accepted
/// grammar is `strtod`'s and it is *not* Rust's: the C function takes optional
/// leading whitespace, an optional sign, and either a decimal or a hexadecimal
/// significand, and fails only when something is left over. Both halves of that
/// are observable — the oracle accepts `" 50"`, `"+50"` and `"0x10"` and rejects
/// `"1%"` — and `str::parse` disagrees in both directions (`" 50"` is an error
/// there, `"nan"` is a value).
///
/// `"nan"` is the one input where this deliberately differs from Node. `strtod`
/// returns NaN, and NaN makes Node's own bounds check
/// (`percentage <= 0.0 || percentage > 100.0`) false because every comparison
/// against NaN is false, so Node goes on to compute a garbage size and lets V8
/// reject `--max_old_space_size=9223372036854775808`. Rejecting it here with the
/// percentage message reports the same class of mistake at the flag that caused
/// it. Both exits are failures, so no test can tell them apart by status.
fn strtod(text: &str) -> Option<f64> {
    let trimmed = text.trim_start();
    let (negative, body) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let magnitude = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        let digits = hex
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(hex.len());
        if digits == 0 || digits != hex.len() {
            return None;
        }
        u64::from_str_radix(&hex[..digits], 16).ok()? as f64
    } else {
        // A decimal significand: digits, an optional fraction, and an optional
        // exponent. The whole string has to be consumed, which is
        // `*end_ptr == '\0'`.
        let bytes = body.as_bytes();
        let mut index = 0;
        let mut seen_digit = false;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
            seen_digit = true;
        }
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
                seen_digit = true;
            }
        }
        if !seen_digit {
            return None;
        }
        if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
            index += 1;
            if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
                index += 1;
            }
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if index == start {
                return None;
            }
        }
        if index != bytes.len() {
            return None;
        }
        body.parse::<f64>().ok()?
    };
    Some(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;
    /// The same sizes as `usize`, which is what `CreateParams` reports.
    const MB_USIZE: usize = 1024 * 1024;

    #[test]
    fn a_cgroup_limit_wins_over_the_machines_memory() {
        assert_eq!(installable_memory(2 * GB, 47 * GB), 2 * GB);
        // `uv_get_constrained_memory` reports 0 when there is no limit.
        assert_eq!(installable_memory(0, 47 * GB), 47 * GB);
    }

    #[test]
    fn a_constraint_that_already_sizes_the_heap_is_left_alone() {
        // The worker path: `UpdateResourceConstraints` already set the old
        // generation, so it must stay what the user asked for.
        let params =
            v8::CreateParams::default().set_max_old_generation_size_in_bytes(16 * MB_USIZE);
        let params = set_isolate_create_params_for_node(params, 0, 47 * GB);
        assert_eq!(params.max_old_generation_size_in_bytes(), 16 * MB_USIZE);
    }

    #[test]
    fn an_unconstrained_isolate_gets_the_machines_numbers() {
        let params = v8::CreateParams::default();
        assert_eq!(params.max_old_generation_size_in_bytes(), 0);
        let params = set_isolate_create_params_for_node(params, 0, 47 * GB);
        // `OldGenerationSizeFromPhysicalMemory` halves the physical memory and
        // clamps to V8's 256 MB floor and 4 GB ceiling.
        assert_eq!(params.max_old_generation_size_in_bytes(), 4 * GB as usize);
        // `YoungGenerationSizeFromPhysicalMemory` picks a semi-space of
        // min(physical / 4 / 32, 32 MB) = 32 MB, three of those to the
        // generation.
        assert_eq!(params.max_young_generation_size_in_bytes(), 96 * MB_USIZE);
    }

    #[test]
    fn a_machine_with_no_readable_memory_keeps_v8s_defaults() {
        // A zero answer means libuv could not say, and Node leaves the params
        // alone rather than configuring a heap from nothing.
        let params = set_isolate_create_params_for_node(v8::CreateParams::default(), 0, 0);
        assert_eq!(params.max_old_generation_size_in_bytes(), 0);
        assert_eq!(params.max_young_generation_size_in_bytes(), 0);
    }

    #[test]
    fn a_small_machine_gets_the_floor_rather_than_a_tiny_heap() {
        let params = set_isolate_create_params_for_node(v8::CreateParams::default(), 0, 512 * MB);
        assert_eq!(params.max_old_generation_size_in_bytes(), 256 * MB_USIZE);
    }

    #[test]
    fn a_percentage_is_computed_from_the_available_memory() {
        // The numbers measured on this machine. The usable figure is the cgroup
        // limit, 47162 MB; the oracle's `heap_size_limit` for 50% is 23677 MB,
        // which is this 23581 MB plus the 96 MB young generation V8 adds.
        let cgroup = 49_453_301_760;
        let total = 50_527_043_584;
        assert_eq!(
            max_old_space_size_percentage_mb("50", cgroup, total),
            Ok(23_581)
        );
        // 47162 * 0.255 = 12026.31, truncated; the oracle reports 12122 = +96.
        assert_eq!(
            max_old_space_size_percentage_mb("25.5", cgroup, total),
            Ok(12_026)
        );
        assert_eq!(
            max_old_space_size_percentage_mb("100", cgroup, total),
            Ok(47_162)
        );
        // A constraint is taken whole rather than min'd against total memory,
        // which is the one place this differs from `installable_memory`.
        assert_eq!(
            max_old_space_size_percentage_mb("50", 4 * GB, 47 * GB),
            Ok(2048)
        );
    }

    #[test]
    fn the_input_grammar_is_strtod_and_not_rusts() {
        // Accepted by `strtod`, rejected by `str::parse::<f64>(" 50")`.
        assert_eq!(
            max_old_space_size_percentage_mb(" 50", 0, 1000 * MB),
            Ok(500)
        );
        assert_eq!(
            max_old_space_size_percentage_mb("+50", 0, 1000 * MB),
            Ok(500)
        );
        assert_eq!(
            max_old_space_size_percentage_mb("50.", 0, 1000 * MB),
            Ok(500)
        );
        assert_eq!(
            max_old_space_size_percentage_mb("1e2", 0, 1000 * MB),
            Ok(1000)
        );
        // `strtod` reads hexadecimal, which is 16%.
        assert_eq!(
            max_old_space_size_percentage_mb("0x10", 0, 1000 * MB),
            Ok(160)
        );
        // And the whole string has to be a number.
        assert!(max_old_space_size_percentage_mb("1%", 0, 1000 * MB).is_err());
        assert!(max_old_space_size_percentage_mb("abc", 0, 1000 * MB).is_err());
        assert!(max_old_space_size_percentage_mb("", 0, 1000 * MB).is_err());
    }

    #[test]
    fn the_error_text_is_nodes() {
        assert_eq!(
            max_old_space_size_percentage_mb("0", 0, 1000 * MB).unwrap_err(),
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: 0"
        );
        assert_eq!(
            max_old_space_size_percentage_mb("101", 0, 1000 * MB).unwrap_err(),
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: 101"
        );
        assert_eq!(
            max_old_space_size_percentage_mb("-1", 0, 1000 * MB).unwrap_err(),
            "--max-old-space-size-percentage must be greater than 0 and up to 100. Got: -1"
        );
    }

    #[test]
    fn a_machine_with_no_memory_cannot_answer_a_percentage() {
        assert_eq!(
            max_old_space_size_percentage_mb("50", 0, 0).unwrap_err(),
            "the available memory can not be calculated"
        );
    }
}
