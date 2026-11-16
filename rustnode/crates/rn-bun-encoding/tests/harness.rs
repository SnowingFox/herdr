//! Prints the differential corpus for `tests/oracle/record.sh`.
//!
//! A separate test file rather than a flag on `differential.rs` because libtest
//! frames a test binary's stdout with its own progress lines; this binary's only
//! test prints the corpus, and the recorder slices from the first `const cases`.

// The harness lives in the differential test, which is where the corpus reader
// and the comparison already are. `include!` rather than a shared module so the
// two files cannot drift about what a case is.
#[path = "differential.rs"]
mod differential;

/// Prints the harness so the recorder and the comparison run the same bytes.
///
/// `RN_PRINT_HARNESS` gates it because a `#[test]` always runs, and this must not
/// print during an ordinary `cargo test`.
#[test]
fn print_harness() {
    if std::env::var_os("RN_PRINT_HARNESS").is_none() {
        return;
    }
    // libtest writes its own progress to stdout, so the corpus goes to a file
    // rather than to stdout: stripping newlines to separate the two would eat the
    // `//` comments in the harness and change what the runtimes execute.
    let path = std::env::var("RN_HARNESS_OUT").expect("RN_HARNESS_OUT names the output file");
    std::fs::write(&path, differential::harness()).expect("the harness path is writable");
    eprintln!("wrote {path}");
}
