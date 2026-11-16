//! `Bun.semver.satisfies(version, range)` and `Bun.semver.order(a, b)`.
//!
//! Bun does not use npm's `semver`. Two of its choices invert what npm does, and
//! both are deliberate rather than bugs:
//!
//! * **An unparseable range matches everything.** `satisfies("1.0.0", "notarange")`
//!   is `true` here and `false` in npm, and so is `"latest"`, `"workspace:*"`,
//!   `"file:../x"`, `">="`, `"&&"`. The rule is "a range that cannot be parsed
//!   is not a constraint", which is what makes `Bun.semver` usable on a
//!   `package.json` whose dependency specs include workspace and git protocols.
//! * **An invalid *version* matches nothing**, so `satisfies("notavar", "*")` is
//!   `false` even though `"*"` matches everything else. `"1"` and `"1.2.3.4"` are
//!   invalid versions, but `"01.0.0"` is valid — leading zeros are tolerated —
//!   and a leading `v` is too.
//!
//! `order` is the mirror image: it *throws* on an empty or undefined version, and
//! the message ends with a literal newline, but an unparseable non-empty version
//! simply sorts (invalid sorts after valid, `order("1.0.0", "x")` is `-1`).
//!
//! Those asymmetries are why this module exists instead of a call into the
//! `semver` crate, which follows npm on every one of them.

/// A parsed version: three numeric components plus the prerelease parts.
///
/// Build metadata is parsed and dropped, because `order("1.0.0+b1", "1.0.0+b2")`
/// is `0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Prerelease identifiers in order; empty means a release version.
    pub prerelease: Vec<Identifier>,
}

/// One dot-separated prerelease component.
///
/// SemVer compares numeric identifiers numerically and alphanumeric ones
/// lexically, and a numeric identifier always sorts before an alphanumeric one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Identifier {
    Numeric(u64),
    Alpha(String),
}

impl Identifier {
    fn ordering_key(&self) -> (u8, u64, &str) {
        match self {
            Self::Numeric(value) => (0, *value, ""),
            Self::Alpha(text) => (1, 0, text.as_str()),
        }
    }
}

/// Parses a version, returning `None` for anything Bun rejects.
///
/// A leading `v` or `V` is skipped and leading zeros are accepted, which is
/// exactly the tolerance Bun shows and npm does not.
pub fn parse_version(text: &str) -> Option<Version> {
    let text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    // Build metadata never affects ordering, so it is cut before parsing.
    let text = text.split('+').next().unwrap_or(text);
    let (core, prerelease) = match text.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (text, None),
    };

    let mut components = core.split('.');
    let major = parse_number(components.next()?)?;
    let minor = parse_number(components.next()?)?;
    let patch = parse_number(components.next()?)?;
    if components.next().is_some() {
        // Four components is not a version: `satisfies("1.2.3.4", "*")` is false.
        return None;
    }

    let mut identifiers = Vec::new();
    if let Some(prerelease) = prerelease {
        if prerelease.is_empty() {
            return None;
        }
        for part in prerelease.split('.') {
            if part.is_empty() {
                return None;
            }
            if part.chars().all(|c| c.is_ascii_digit()) {
                identifiers.push(Identifier::Numeric(part.parse().ok()?));
            } else if part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                identifiers.push(Identifier::Alpha(part.to_string()));
            } else {
                return None;
            }
        }
    }

    Some(Version {
        major,
        minor,
        patch,
        prerelease: identifiers,
    })
}

fn parse_number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// SemVer precedence: `Ordering::Less` when `a` sorts before `b`.
pub fn compare(a: &Version, b: &Version) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match a.major.cmp(&b.major) {
        Ordering::Equal => {}
        other => return other,
    }
    match a.minor.cmp(&b.minor) {
        Ordering::Equal => {}
        other => return other,
    }
    match a.patch.cmp(&b.patch) {
        Ordering::Equal => {}
        other => return other,
    }
    // A release sorts after every prerelease of the same core version.
    match (a.prerelease.is_empty(), b.prerelease.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    for (left, right) in a.prerelease.iter().zip(b.prerelease.iter()) {
        match left.ordering_key().cmp(&right.ordering_key()) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    a.prerelease.len().cmp(&b.prerelease.len())
}

/// One `||`-separated alternative, itself a conjunction of comparators.
struct ComparatorSet {
    comparators: Vec<Comparator>,
}

/// A single comparator: `>=1.2.3`, `^1.0.0`, `1.x`, `*`, or an exact version.
struct Comparator {
    operator: Operator,
    version: Option<Version>,
    /// For partial versions (`1`, `1.2`, `1.x`), the components that were
    /// actually specified, so `1` can mean `>=1.0.0 <2.0.0` and `1.2` means
    /// `>=1.2.0 <1.3.0`.
    specified: Specified,
}

/// Which components a range literally named.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Specified {
    Major,
    Minor,
    Patch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operator {
    Exact,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    Caret,
    Tilde,
    /// `1.x`, `1.2.x`, `*`: a prefix match on the specified components.
    Wildcard,
}

/// The upper bound of a caret range, or `None` when it is unbounded.
///
/// `^1.2.3` is `>=1.2.3 <2.0.0`; `^0.2.3` is `>=0.2.3 <0.3.0`; `^0.0.3` is
/// `>=0.0.3 <0.0.4`. The zero-major rules are why this cannot be one expression.
fn caret_upper(version: &Version, specified: Specified) -> Option<Version> {
    if version.major != 0 {
        return Some(Version {
            major: version.major + 1,
            minor: 0,
            patch: 0,
            prerelease: Vec::new(),
        });
    }
    if specified == Specified::Major {
        return Some(Version {
            major: 1,
            minor: 0,
            patch: 0,
            prerelease: Vec::new(),
        });
    }
    if version.minor != 0 || specified == Specified::Minor {
        return Some(Version {
            major: 0,
            minor: version.minor + 1,
            patch: 0,
            prerelease: Vec::new(),
        });
    }
    Some(Version {
        major: 0,
        minor: version.minor,
        patch: version.patch + 1,
        prerelease: Vec::new(),
    })
}

/// Parses a range into alternatives. `None` means "unparseable", which the
/// caller turns into "matches everything" — Bun's rule, not an error.
fn parse_range(text: &str) -> Option<Vec<ComparatorSet>> {
    let text = text.trim();
    if text.is_empty() {
        // `""` genuinely matches everything, and npm agrees.
        return Some(vec![ComparatorSet {
            comparators: Vec::new(),
        }]);
    }

    let mut alternatives = Vec::new();
    for alternative in text.split("||") {
        // A hyphen range is `LOW - HIGH` and means `>=LOW <=HIGH`. It is checked
        // first because the three tokens would otherwise fail on the lone `-`.
        let trimmed = alternative.trim();
        if let Some((low, high)) = trimmed.split_once(" - ") {
            let low = parse_comparator(&format!(">={}", low.trim()))?;
            let high = parse_comparator(&format!("<={}", high.trim()))?;
            alternatives.push(ComparatorSet {
                comparators: vec![low, high],
            });
            continue;
        }
        // An operator may be a token of its own: `">= 1.0.0"` splits into `">="`
        // and `"1.0.0"`, and Bun treats the pair as one comparator. Joining a
        // bare-operator token to the one after it is what makes that parse.
        let raw: Vec<&str> = trimmed.split_whitespace().collect();
        let mut comparators = Vec::new();
        let mut index = 0;
        while index < raw.len() {
            let token = raw[index];
            let bare_operator = !token.is_empty()
                && token
                    .chars()
                    .all(|character| matches!(character, '>' | '<' | '=' | '^' | '~'));
            if bare_operator && index + 1 < raw.len() {
                comparators.push(parse_comparator(&format!("{token}{}", raw[index + 1]))?);
                index += 2;
                continue;
            }
            comparators.push(parse_comparator(token)?);
            index += 1;
        }
        alternatives.push(ComparatorSet { comparators });
    }
    Some(alternatives)
}

fn parse_comparator(token: &str) -> Option<Comparator> {
    if token == "*" || token == "x" || token == "X" {
        return Some(Comparator {
            operator: Operator::Wildcard,
            version: None,
            specified: Specified::Major,
        });
    }

    // The operator prefix is the longest of the known ones that matches.
    let (operator, rest) = if let Some(rest) = token.strip_prefix(">=") {
        (Operator::GreaterEqual, rest)
    } else if let Some(rest) = token.strip_prefix("<=") {
        (Operator::LessEqual, rest)
    } else if let Some(rest) = token.strip_prefix('>') {
        (Operator::Greater, rest)
    } else if let Some(rest) = token.strip_prefix('<') {
        (Operator::Less, rest)
    } else if let Some(rest) = token.strip_prefix('=') {
        (Operator::Exact, rest)
    } else if let Some(rest) = token.strip_prefix('^') {
        (Operator::Caret, rest)
    } else if let Some(rest) = token.strip_prefix('~') {
        (Operator::Tilde, rest)
    } else {
        (Operator::Exact, token)
    };

    // Bun accepts an operator separated from its version by a space inside one
    // alternative — `">= 1.0.0"` is a real range, not an unparseable one — so the
    // remainder is trimmed here.
    let rest = rest.trim();
    if rest.is_empty() {
        // A bare operator on its own (`">="`) is not a range.
        return None;
    }

    // Partial and wildcard forms. `1.x`, `1.2.x`, `1`, `1.2` all pin only a
    // prefix, and which components they pin decides the bounds.
    let (core, specified, wildcard) = split_partial(rest)?;
    if wildcard {
        return Some(Comparator {
            operator: Operator::Wildcard,
            version: Some(parse_version(&core)?),
            specified,
        });
    }

    // `core` is `rest` padded to three components, so a partial like `"2"` or
    // `"1.2"` parses here even though `parse_version("2")` would not.
    Some(Comparator {
        operator,
        version: Some(parse_version(&core)?),
        specified,
    })
}

/// Splits a possibly-partial version into a core that `parse_version` accepts,
/// the number of components it named, and whether it used `x`.
fn split_partial(text: &str) -> Option<(String, Specified, bool)> {
    let text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    let text = text.split('+').next().unwrap_or(text);
    let (core, prerelease) = match text.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (text, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let mut wildcard = false;
    let mut specified = Specified::Patch;
    for (index, part) in parts.iter().enumerate() {
        if *part == "x" || *part == "X" || *part == "*" {
            wildcard = true;
            specified = match index {
                0 => Specified::Major,
                1 => Specified::Minor,
                _ => Specified::Patch,
            };
            // Everything after a wildcard is implied.
            break;
        }
        if !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    if !wildcard {
        specified = match parts.len() {
            1 => Specified::Major,
            2 => Specified::Minor,
            _ => Specified::Patch,
        };
    }

    // The core handed to `parse_version` must have three numeric components;
    // missing ones become zero and the wildcard component is dropped.
    let mut filled: Vec<String> = Vec::with_capacity(3);
    for index in 0..3 {
        match parts.get(index) {
            Some(part) if *part != "x" && *part != "X" && *part != "*" => {
                filled.push((*part).to_string())
            }
            _ => filled.push("0".to_string()),
        }
    }
    let mut core = filled.join(".");
    if let Some(prerelease) = prerelease {
        core.push('-');
        core.push_str(prerelease);
    }
    Some((core, specified, wildcard))
}

/// Whether `version` satisfies `range`, following Bun's rules.
pub fn satisfies(version: &str, range: &str) -> bool {
    let Some(parsed) = parse_version(version) else {
        // An invalid version matches nothing, whatever the range says.
        return false;
    };
    // **A prerelease version satisfies nothing but a range that names a
    // prerelease on the same core version.** This is checked before the
    // unparseable-range shortcut, because the recorded answer for
    // `satisfies("1.0.0-alpha", "notarange")` is `false` while
    // `satisfies("1.0.0", "notarange")` is `true`. Getting the order backwards
    // makes every prerelease match every malformed range.
    if !parsed.prerelease.is_empty() {
        if range.trim().is_empty() {
            // The empty range means "any release"; a prerelease is not one.
            return false;
        }
        let alternatives = match parse_range(range) {
            Some(alternatives) => alternatives,
            // An unparseable range names no prerelease, so a prerelease version
            // cannot satisfy it.
            None => return false,
        };
        return alternatives.iter().any(|set| {
            set.comparators.iter().all(|comparator| {
                let Some(target) = comparator.version.as_ref() else {
                    return false;
                };
                !target.prerelease.is_empty()
                    && target.major == parsed.major
                    && target.minor == parsed.minor
                    && target.patch == parsed.patch
                    && matches(&parsed, comparator)
            })
        });
    }
    let Some(alternatives) = parse_range(range) else {
        // An unparseable range is not a constraint for a release version.
        return true;
    };
    alternatives
        .iter()
        .any(|set| set.comparators.iter().all(|c| matches(&parsed, c)))
}

fn matches(version: &Version, comparator: &Comparator) -> bool {
    use std::cmp::Ordering;

    let Some(target) = comparator.version.as_ref() else {
        // A bare `*`: every release version, and **no** prerelease — measured,
        // `satisfies("1.0.0-alpha", "*")` is `false`.
        return version.prerelease.is_empty()
            || comparator
                .version
                .as_ref()
                .is_some_and(|target| !target.prerelease.is_empty());
    };

    // The prerelease rule, measured: a prerelease version is satisfied **only**
    // by a comparator that itself names a prerelease on the same core version.
    // Every other shape is false, which is why `satisfies("1.0.0-alpha", "1.x")`,
    // `"notarange"`, `""` and `"latest"` are all `false` while
    // `satisfies("1.0.0-beta.2", "^1.0.0-beta.1")` is `true`. Note this is *not*
    // SemVer's rule: there, `"*"` and an unparseable range would be vacuously
    // satisfied.
    if !version.prerelease.is_empty() {
        let same_core = version.major == target.major
            && version.minor == target.minor
            && version.patch == target.patch;
        if target.prerelease.is_empty() || !same_core {
            return false;
        }
    } else if comparator.operator == Operator::Wildcard && !target.prerelease.is_empty() {
        // A release version against a prerelease-naming wildcard is not a match
        // either: `1.2.3` does not satisfy `1.0.0-beta`.
        return false;
    }

    // A partial version pins only the components it named, and that is decided by
    // the components rather than by ordering: `"2"` is "any 2.x", so `1.2.3`
    // fails it and `2.0.0` passes. This runs before any ordering test.
    match comparator.operator {
        Operator::Exact if comparator.specified == Specified::Major => {
            return version.major == target.major;
        }
        Operator::Exact if comparator.specified == Specified::Minor => {
            return version.major == target.major && version.minor == target.minor;
        }
        Operator::Tilde | Operator::Caret if comparator.specified == Specified::Major => {
            return version.major == target.major;
        }
        Operator::Tilde if comparator.specified == Specified::Minor => {
            return version.major == target.major && version.minor == target.minor;
        }
        Operator::Tilde | Operator::Caret | Operator::Exact => {}
        _ => {}
    }

    let ordering = compare(version, target);
    match comparator.operator {
        Operator::Exact => ordering == Ordering::Equal,
        Operator::Greater => ordering == Ordering::Greater,
        Operator::GreaterEqual => ordering != Ordering::Less,
        Operator::Less => ordering == Ordering::Less,
        Operator::LessEqual => ordering != Ordering::Greater,
        Operator::Tilde => {
            if ordering == Ordering::Less {
                return false;
            }
            // `~1.2.0` allows patch bumps; `~1` allows minor bumps.
            match comparator.specified {
                Specified::Major => version.major == target.major,
                _ => version.major == target.major && version.minor == target.minor,
            }
        }
        Operator::Caret => {
            if ordering == Ordering::Less {
                return false;
            }
            match caret_upper(target, comparator.specified) {
                Some(upper) => compare(version, &upper) == Ordering::Less,
                None => true,
            }
        }
        Operator::Wildcard => {
            // A wildcard pins only the components it named.
            match comparator.specified {
                Specified::Major => true,
                Specified::Minor => version.major == target.major,
                Specified::Patch => version.major == target.major && version.minor == target.minor,
            }
        }
    }
}

/// The outcome of `Bun.semver.order(a, b)`.
#[derive(Debug, Clone)]
pub enum OrderError {
    /// The message Bun throws, which ends with a literal newline.
    Invalid(String),
}

impl OrderError {
    pub fn message(&self) -> String {
        match self {
            Self::Invalid(text) => text.clone(),
        }
    }
}

/// A version as `order` sees it: wildcard components are tolerated, and a
/// missing component is zero.
///
/// `order` is more permissive than `satisfies` about what counts as a version —
/// `"1"`, `"1.2"`, `"1.x"`, `"x"` and `"*"` all parse — but it throws on a string
/// that has any other structure, such as `"notavar"`, `"1..2"`, `"1.2.3.4"`, or a
/// range operator like `">=1.0.0"`.
fn parse_loose(text: &str) -> Option<(Version, bool, usize)> {
    // The wildcard flag means "a component was `x`, `X` or `*`", which `order`
    // sorts **above** every concrete version: `order("1.0.0", "x")` is `-1`.
    // Separately, a version that named *fewer* components sorts after one that
    // named more with the same prefix, so `"1"` is greater than `"1.0"`, which is
    // greater than `"1.0.0"`. Both are measured.
    let text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    let text = text.split('+').next().unwrap_or(text);
    let (core, prerelease) = match text.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (text, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }

    let mut numbers = [0u64; 3];
    let mut wildcard = false;
    for (index, part) in parts.iter().enumerate() {
        if *part == "x" || *part == "X" || *part == "*" {
            wildcard = true;
            // Everything after a wildcard is implied.
            break;
        }
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        numbers[index] = part.parse().ok()?;
    }

    let mut identifiers = Vec::new();
    if let Some(prerelease) = prerelease {
        if prerelease.is_empty() {
            // `1.2.3-` parses: an empty prerelease is simply absent.
            let named = parts
                .iter()
                .take_while(|part| **part != "x" && **part != "X" && **part != "*")
                .count();
            return Some((
                Version {
                    major: numbers[0],
                    minor: numbers[1],
                    patch: numbers[2],
                    prerelease: Vec::new(),
                },
                wildcard,
                named,
            ));
        }
        for part in prerelease.split('.') {
            if part.is_empty() {
                return None;
            }
            if part.chars().all(|c| c.is_ascii_digit()) {
                identifiers.push(Identifier::Numeric(part.parse().ok()?));
            } else if part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                identifiers.push(Identifier::Alpha(part.to_string()));
            } else {
                return None;
            }
        }
    }

    let named = parts
        .iter()
        .take_while(|part| **part != "x" && **part != "X" && **part != "*")
        .count();
    Some((
        Version {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
            prerelease: identifiers,
        },
        wildcard,
        named,
    ))
}

/// Compares two version strings the way `Bun.semver.order` does.
///
/// Each side is parsed in turn — left first, then right — and the first one that
/// fails is reported, which is why `order("x", "y")` names `y` and
/// `order("notavar", "1.0.0")` names `notavar`. `None` means "absent", and an
/// absent version is reported as the literal text `undefined`.
///
/// A side that fails to parse is *not* automatically an error: `"x"` and `"1.x"`
/// parse, as wildcards. Only genuinely malformed text throws.
pub fn order(a: Option<&str>, b: Option<&str>) -> Result<i32, OrderError> {
    let left_text = a.unwrap_or("undefined");
    let right_text = b.unwrap_or("undefined");

    // An empty string is invalid even though it is not `None`, and the recorded
    // message for it is `Invalid SemVer: \n`.
    let left = if a.is_none() || a == Some("") {
        return Err(OrderError::Invalid(
            "Invalid SemVer: ".to_string() + if a.is_none() { "undefined" } else { "" } + "\n",
        ));
    } else {
        match parse_loose(left_text) {
            Some(parsed) => parsed,
            None => {
                return Err(OrderError::Invalid(format!(
                    "Invalid SemVer: {left_text}\n"
                )))
            }
        }
    };
    let right = if b.is_none() || b == Some("") {
        return Err(OrderError::Invalid(
            "Invalid SemVer: ".to_string() + if b.is_none() { "undefined" } else { "" } + "\n",
        ));
    } else {
        match parse_loose(right_text) {
            Some(parsed) => parsed,
            None => {
                return Err(OrderError::Invalid(format!(
                    "Invalid SemVer: {right_text}\n"
                )))
            }
        }
    };

    // A wildcard on one side and a concrete version on the other sorts the
    // wildcard last, which is why `order("1.0.0", "x")` is `-1`.
    match (left.1, right.1) {
        (true, true) => return Ok(0),
        (true, false) => return Ok(1),
        (false, true) => return Ok(-1),
        (false, false) => {}
    }

    // A version that named fewer components sorts after one that named more,
    // once the shared prefix is equal: `"1"` > `"1.0"` > `"1.0.0"`. The length is
    // carried through `parse_loose`'s wildcard flag, so it is recovered here from
    // the prerelease-free comparison of the parsed values with a trailing
    // component count.
    let ordering = compare(&left.0, &right.0);
    if ordering != std::cmp::Ordering::Equal {
        return Ok(match ordering {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => 0,
        });
    }
    // Equal values: the shorter spelling wins, i.e. sorts greater.
    Ok(match left.2.cmp(&right.2).reverse() {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}
