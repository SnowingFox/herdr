//! A differential harness against the real `node` binary.
//!
//! The matching engine has to agree with Node about braces, extglobs, globstars,
//! dot handling and case folding. Reading the C++ carefully is necessary but not
//! sufficient: an off-by-one in a probe or a missing guard still compiles and
//! still passes hand-written tests that were derived from the same reading.
//!
//! So the oracle is the recorder binary itself. It can drive
//! `internalBinding('glob').matchesGlob` directly, which is the same function
//! `path.matchesGlob` and `fs.glob` call. `tests/corpus/matches-glob.txt` holds
//! one `path|pattern` case per line and
//! `tests/corpus/matches-glob.expected.txt` holds the answer recorded from Node,
//! so this runs without the binary present and fails if the two ever diverge.
//!
//! Regenerate the expectations with `tools/record-matches-glob.sh`.

use crate::matcher::{match_pattern, CompiledPattern};
use crate::parser::CompileFlags;

/// One recorded case: the path, the pattern, and what Node answered.
pub struct Case {
    pub path: String,
    pub pattern: String,
    pub expected: Expected,
}

/// A recorded answer, which may be an exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    Matched(bool),
    Threw(String),
}

impl Case {
    /// Parses one line of the expected-answers file, written by the recorder as
    /// a JSON array: `["path","pattern",true]`.
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let inner = line.strip_prefix('[')?.strip_suffix(']')?;
        let fields = split_json_fields(inner);
        if fields.len() != 3 {
            return None;
        }
        let path = unquote(&fields[0])?;
        let pattern = unquote(&fields[1])?;
        let expected = if let Some(message) = fields[2].strip_prefix("\"THROW:") {
            Expected::Threw(unquote(&format!("\"{message}")).unwrap_or_default())
        } else if fields[2] == "true" {
            Expected::Matched(true)
        } else if fields[2] == "false" {
            Expected::Matched(false)
        } else {
            return None;
        };
        Some(Self {
            path,
            pattern,
            expected,
        })
    }
}

/// Splits a JSON array body on top-level commas, honouring string escapes.
fn split_json_fields(body: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for character in body.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_string => {
                current.push(character);
                escaped = true;
            }
            '"' => {
                in_string = !in_string;
                current.push(character);
            }
            ',' if !in_string => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

/// Decodes a JSON string literal.
fn unquote(text: &str) -> Option<String> {
    let text = text.trim();
    let body = text.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'u' => {
                let mut code = 0u32;
                for _ in 0..4 {
                    code = code * 16 + chars.next()?.to_digit(16)?;
                }
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            other => out.push(other),
        }
    }
    Some(out)
}

/// How the recorded answers were produced: `matchesGlob(path, pattern, 0)` on
/// the host, so no windows or dot flag.
pub fn host_flags() -> CompileFlags {
    CompileFlags {
        windows: false,
        nocase: false,
        nocase_magic_only: true,
        dot: false,
        match_base: false,
    }
}

/// Runs one case through the engine, reproducing Node's throw as an `Err`.
pub fn evaluate(case: &Case) -> Result<bool, String> {
    let flags = host_flags();
    let path: Vec<u16> = case.path.encode_utf16().collect();
    let pattern: Vec<u16> = case.pattern.encode_utf16().collect();
    match CompiledPattern::from_pattern(&pattern, flags) {
        Ok(compiled) => Ok(match_pattern(&compiled, &path)),
        Err(error) => Err(error.message().0.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every recorded case, read from the checked-in corpus.
    fn cases() -> Vec<Case> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("corpus")
            .join("matches-glob.expected.txt");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        text.lines().filter_map(Case::parse).collect()
    }

    #[test]
    fn every_recorded_case_agrees_with_node() {
        let cases = cases();
        assert!(
            cases.len() > 50,
            "expected a substantial corpus, found {}",
            cases.len()
        );
        let mut failures = Vec::new();
        for case in &cases {
            let actual = evaluate(case);
            let matches = match (&case.expected, &actual) {
                (Expected::Matched(expected), Ok(actual)) => expected == actual,
                (Expected::Threw(expected), Err(actual)) => expected == actual,
                _ => false,
            };
            if !matches {
                failures.push(format!(
                    "path {:?} pattern {:?}: node {:?}, rust {:?}",
                    case.path, case.pattern, case.expected, actual
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} cases disagree with node:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }
}
