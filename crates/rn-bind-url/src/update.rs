//! The ten `update` actions.
//!
//! `update(href, action, value)` re-parses the href, applies one setter, and
//! returns the new serialization — or `false` when the setter rejected the
//! value. `lib/internal/url.js` only writes the result back when it is truthy,
//! so the boolean and the string are one return channel.
//!
//! Each action mirrors a specific function in `deps/ada/ada.cpp`; the comment on
//! each states which one, because the guards inside them are what makes
//! `update` agree with Node. Two of those guards are easy to miss and are worth
//! naming here:
//!
//! * A credential or port cannot be set on a URL whose host is empty or whose
//!   scheme is `file` (`cannot_have_credentials_or_port`), so `username`,
//!   `password` and `port` fail on `mailto:` and on `file:` URLs.
//! * `set_protocol` is *not* the WHATWG "scheme state" algorithm. ada validates
//!   the scheme text, then dispatches on whether the input names a special
//!   scheme. The two paths disagree about refusals: the fast path fails, the
//!   slow path silently leaves the URL alone. `update.rs` reproduces both, and a
//!   refusal being silent is why `url.protocol = 'foo'` does not throw.

use url::Url;

/// The action numbers, matching `enum url_update_action` in
/// `src/node_url.h` and `updateActions` in `lib/internal/url.js`.
///
/// The numbers are the wire contract between the JavaScript and the binding, so
/// they are listed in one place rather than repeated as literals.
pub const K_PROTOCOL: u32 = 0;
pub const K_HOST: u32 = 1;
pub const K_HOSTNAME: u32 = 2;
pub const K_PORT: u32 = 3;
pub const K_USERNAME: u32 = 4;
pub const K_PASSWORD: u32 = 5;
pub const K_PATHNAME: u32 = 6;
pub const K_SEARCH: u32 = 7;
pub const K_HASH: u32 = 8;
pub const K_HREF: u32 = 9;

/// Why a setter refused.
///
/// Only the distinction between "refused" and "the URL cannot be parsed at all"
/// is observable: both report `false` from `update`. It is kept because the
/// `kHref` action genuinely re-parses, and a caller that later wants to throw
/// needs to know which happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    /// The setter rejected the value.
    Refused,
    /// The href itself no longer parses.
    Unparsable,
}

/// Applies `action` to `href` with `value`, returning the new serialization.
///
/// Returns `Err` where Node returns `false`; the caller writes the new href into
/// `urlComponents` only after this succeeds.
pub fn update(href: &str, action: u32, value: &str) -> Result<String, UpdateError> {
    let mut url = Url::parse(href).map_err(|_| UpdateError::Unparsable)?;
    match action {
        K_PROTOCOL => set_protocol(&mut url, value)?,
        K_HOST => set_host(&mut url, value, false)?,
        K_HOSTNAME => set_host(&mut url, value, true)?,
        K_PORT => set_port(&mut url, value)?,
        K_USERNAME => set_username(&mut url, value)?,
        K_PASSWORD => set_password(&mut url, value)?,
        K_PATHNAME => set_pathname(&mut url, value)?,
        K_SEARCH => set_search(&mut url, value),
        K_HASH => set_hash(&mut url, value),
        K_HREF => {
            // `set_href` re-parses and replaces the whole URL; a failure leaves
            // the old one, which is why the parse target is separate.
            let replacement = Url::parse(value).map_err(|_| UpdateError::Refused)?;
            url = replacement;
        }
        // Node's `UNREACHABLE` for any other number. `lib/**` never sends one,
        // so refusing is the honest answer rather than inventing behaviour.
        _ => return Err(UpdateError::Refused),
    }
    Ok(url.as_str().to_string())
}

/// `url_aggregator::set_protocol` — including its two-path structure.
///
/// ada decides which of two implementations runs by testing whether the *input
/// text*, compared case-sensitively, names a special scheme. The two paths
/// disagree about what a refusal means, and that disagreement is observable from
/// JavaScript:
///
/// * **Fast path** (input is literally `http`, `https`, `ws`, `wss`, `ftp` or
///   `file`): every state-override refusal `return false`, so
///   `url.protocol = 'http'` on a `foo:` URL throws.
/// * **Slow path** (anything else, including `FILE` in capitals, because
///   `get_scheme_type` does not fold case): every refusal `return true` without
///   touching the URL, so `url.protocol = 'foo'` on an `https:` URL is a silent
///   no-op.
///
/// The scheme text is the leading run of `[A-Za-z0-9+-.]`. ada appends a `:` and
/// then takes the prefix before the first character outside that set, so
/// `"a:80"` means scheme `a` — the rest is discarded, not rejected.
fn set_protocol(url: &mut Url, value: &str) -> Result<(), UpdateError> {
    let cleaned: String = value
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect();
    if cleaned.is_empty() {
        // ada returns true without touching the URL.
        return Ok(());
    }
    if !cleaned
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
    {
        return Err(UpdateError::Refused);
    }
    // The scheme is the leading alphanumeric-plus run, and it must be terminated
    // by the colon ada appends — i.e. the next character has to be `:` or the end
    // of the input.
    let scheme_len = cleaned
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
        .count();
    let scheme_text = &cleaned[..scheme_len];
    let terminator = cleaned[scheme_len..].chars().next();
    if terminator.is_some_and(|character| character != ':') {
        return Err(UpdateError::Refused);
    }

    // Case-sensitive, deliberately: this is what selects the path.
    let parsed_type = crate::model::scheme_type(scheme_text);
    let fast_path = parsed_type != 1;
    let lower = scheme_text.to_ascii_lowercase();
    let old_type = crate::model::scheme_type(url.scheme());
    let old_special = old_type != 1;
    let has_credentials = !url.username().is_empty() || url.password().is_some();

    if fast_path {
        if !old_special {
            return Err(UpdateError::Refused);
        }
        if parsed_type == 6 && (has_credentials || url.port().is_some()) {
            return Err(UpdateError::Refused);
        }
        if old_type == 6 && url.host_str().is_none_or(str::is_empty) {
            return Err(UpdateError::Refused);
        }
        apply_scheme(url, &lower, parsed_type)
    } else {
        // The slow path folds case first and then finds the same refusals, but
        // reports them as success so the URL is left exactly as it was.
        let new_type = crate::model::scheme_type(&lower);
        if old_special != (new_type != 1) {
            return Ok(());
        }
        if (has_credentials || url.port().is_some()) && lower == "file" {
            return Ok(());
        }
        if old_type == 6 && url.host_str().is_none_or(str::is_empty) {
            return Ok(());
        }
        apply_scheme(url, &lower, new_type)
    }
}

/// Writes `scheme` into `url` and drops a now-default port.
fn apply_scheme(url: &mut Url, scheme: &str, new_type: u32) -> Result<(), UpdateError> {
    // If the port equals the new scheme's default it becomes no port at all, so
    // `https://ex.com:443/` becomes `http://ex.com/` rather than keeping `:443`.
    if let Some(port) = url.port() {
        if u32::from(port) == default_port(new_type) {
            url.set_port(None).map_err(|()| UpdateError::Refused)?;
        }
    }

    // The `url` crate applies the stricter WHATWG setter rules, which refuse a
    // couple of transitions ada permits — notably a hop through `file` between
    // two special schemes. Rewriting the scheme in the serialization and
    // re-parsing reaches the same answer, and the re-parse is what re-derives the
    // default-port and path rules.
    if url.set_scheme(scheme).is_err() {
        return rewrite_scheme(url, scheme);
    }
    Ok(())
}

/// Replaces the scheme by rebuilding the URL from its parts.
///
/// Used only for the special-to-special transitions `url::Url::set_scheme`
/// refuses. The parts are re-joined in their serialized form, so the result is
/// parsed exactly once and cannot drift from what a parser would accept.
fn rewrite_scheme(url: &mut Url, scheme: &str) -> Result<(), UpdateError> {
    let rest = url.as_str();
    // Everything from the colon onward, colon included: the replaced scheme
    // text is the part before it.
    let colon = rest.find(':').ok_or(UpdateError::Refused)?;
    let rebuilt = format!("{scheme}{}", &rest[colon..]);
    match Url::parse(&rebuilt) {
        Ok(replacement) => {
            *url = replacement;
            Ok(())
        }
        Err(_) => Err(UpdateError::Refused),
    }
}

/// The default port for an ada `scheme::type`, or 0 when there is none.
fn default_port(scheme_type: u32) -> u32 {
    match scheme_type {
        0 | 3 => 80,
        2 | 5 => 443,
        4 => 21,
        _ => 0,
    }
}

/// `url_aggregator::set_host` (`hostname == false`) and `set_hostname`.
///
/// The two differ only in what they do with a `:port` suffix: `set_host` splits
/// it off and applies it, `set_hostname` refuses the value outright. A trailing
/// `#fragment` is cut first, and tab/newline characters are removed, matching
/// `set_host_or_hostname`.
fn set_host(url: &mut Url, value: &str, hostname_only: bool) -> Result<(), UpdateError> {
    if url.cannot_be_a_base() {
        // `has_opaque_path` in ada.
        return Err(UpdateError::Refused);
    }
    let cut = value.split('#').next().unwrap_or("");
    let cleaned: String = cut
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect();

    let is_file = url.scheme() == "file";
    let special = crate::model::scheme_type(url.scheme()) != 1;

    if is_file {
        // `file` URLs take the file-host branch: the host ends at the first
        // path delimiter, an empty host is allowed, and `localhost` collapses
        // to the empty host.
        let host_text = cleaned
            .split(['/', '\\', '?'])
            .next()
            .unwrap_or("")
            .to_string();
        if host_text.is_empty() {
            url.set_host(None).map_err(|_| UpdateError::Refused)?;
            return Ok(());
        }
        let host = url::Host::parse(&host_text).map_err(|_| UpdateError::Refused)?;
        let serialized = host.to_string();
        if serialized == "localhost" {
            url.set_host(None).map_err(|_| UpdateError::Refused)?;
        } else {
            url.set_host(Some(&serialized))
                .map_err(|_| UpdateError::Refused)?;
        }
        return Ok(());
    }

    // Split the value at the first colon that is outside brackets.
    let (host_end, found_colon) = host_split(&cleaned);
    let mut host_text = cleaned[..host_end].to_string();
    let port_text = cleaned[host_end..].strip_prefix(':');

    // A URL that never had an authority gains one when a host is set. ada's
    // `set_port` updates an existing port component in place, so there is
    // nothing to update on such a URL and the port is dropped:
    // `foo:/bar` with `"a:80"` becomes `foo://a/bar`, not `foo://a:80/bar`.
    // The port is therefore validated but not applied.
    let gaining_authority = !url.has_authority();
    if found_colon {
        if hostname_only {
            return Err(UpdateError::Refused);
        }
        if let Some(port_text) = port_text.filter(|text| !text.is_empty()) {
            if gaining_authority {
                validate_port(port_text)?;
            } else {
                set_port(url, port_text)?;
            }
        }
    }

    if !special {
        // A non-special URL takes the opaque-host branch: the value is cut at a
        // path delimiter rather than parsed as a domain, so `"/p q"` and
        // `"?q=2"` mean an empty host, and `"99999"` stays `99999` instead of
        // becoming an IPv4 address.
        host_text = host_text.split(['/', '?']).next().unwrap_or("").to_string();
        // ada's opaque-host parse forbids `@` as well as space, tab and the
        // bracket, `^`, `|`, `<`, `>`, `` ` `` and control characters. The other
        // forbidden characters are covered by `Host::parse_opaque`; `@` is not,
        // because a host *can* legitimately contain a percent-encoded one.
        if host_text.contains('@') {
            return Err(UpdateError::Refused);
        }
    }

    if host_text.is_empty() {
        let has_credentials = !url.username().is_empty() || url.password().is_some();
        // "If url is special and host is the empty string, validation error,
        // return failure. Otherwise, if state override is given, host is the
        // empty string, and either url includes credentials or url's port is
        // non-null, return."
        if special || has_credentials || url.port().is_some() {
            return Err(UpdateError::Refused);
        }
        // A URL that never had an authority (`foo:/bar`) keeps that shape: ada
        // sets the host to the empty string, and an empty host on a URL with no
        // `//` serializes identically to having none, so nothing changes.
        if !url.has_authority() {
            return Ok(());
        }
        // Otherwise `set_host(Some(""))` keeps the `//` marker, which is what
        // ada does: `foo://bar/baz` becomes `foo:///baz`. `set_host(None)` would
        // drop it and give `foo:/baz`, a different URL.
        url.set_host(Some("")).map_err(|_| UpdateError::Refused)?;
        return Ok(());
    }

    // A URL that never had an authority gains one when a host is set, and the
    // port is ignored because there was no port component to update: ada's
    // `set_port` updates an existing port in place, so `foo:/bar` with `"a:80"`
    // becomes `foo://a/bar`, not `foo://a:80/bar`.
    if !url.has_authority() {
        if !special {
            let scheme = url.scheme().to_string();
            let path = url.path().to_string();
            let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
            let fragment = url.fragment().map(|f| format!("#{f}")).unwrap_or_default();
            let rebuilt = format!("{scheme}://{host_text}{path}{query}{fragment}");
            return match Url::parse(&rebuilt) {
                Ok(replacement) => {
                    *url = replacement;
                    Ok(())
                }
                Err(_) => Err(UpdateError::Refused),
            };
        }
        return Err(UpdateError::Refused);
    }

    // A special URL parses the value as a domain (percent-decoding, IDNA, IPv4
    // shorthand); a non-special one percent-encodes an opaque host instead.
    let host = if special {
        url::Host::parse(&host_text).map_err(|_| UpdateError::Refused)?
    } else {
        url::Host::parse_opaque(&host_text).map_err(|_| UpdateError::Refused)?
    };
    url.set_host(Some(&host.to_string()))
        .map_err(|_| UpdateError::Refused)
}

/// Locates the first `:` outside brackets, matching `get_host_delimiter_location`.
fn host_split(input: &str) -> (usize, bool) {
    let mut brackets = 0u32;
    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b':' if brackets == 0 => return (index, true),
            _ => {}
        }
    }
    (input.len(), false)
}

/// `url_aggregator::set_port`.
///
/// The algorithm is ada's, reproduced from `set_port` + `parse_port` together,
/// because the split between them is what produces the surprising cases:
///
/// 1. Strip tab and newline. An empty result clears the port.
/// 2. A leading `-` marks the URL invalid, so the whole update fails.
/// 3. `from_chars` parses the digit prefix. `result_out_of_range` fails, and so
///    does any other error: a value with **no** digits (`"x"`, `"+"`, `" 80"`)
///    yields `invalid_argument`, which leaves `is_valid` false and makes
///    `set_port` roll back → `false`. This is why `"x"` fails while `"x1"`
///    succeeds: `"x1"` has digits later in the string, which `from_chars` still
///    rejects, but `set_port`'s own `find_first_of("0123456789")` guard passes,
///    so `parse_port` runs with the *whole* trimmed string…
/// 4. …and `from_chars` stops at the first non-digit, so `"x1"` contributes no
///    port and `is_valid` stays true, clearing the port instead. `"1x"` sets 1.
/// 5. A port equal to the scheme's default clears the port (`:443` on `https`).
fn set_port(url: &mut Url, value: &str) -> Result<(), UpdateError> {
    if cannot_have_credentials_or_port(url) {
        return Err(UpdateError::Refused);
    }
    let trimmed: String = value
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect();
    if trimmed.is_empty() {
        url.set_port(None).map_err(|()| UpdateError::Refused)?;
        return Ok(());
    }
    // "Input should not start with control characters." A leading space counts.
    let first = trimmed.chars().next().unwrap_or('\0');
    if first.is_ascii_control() || first == ' ' {
        return Err(UpdateError::Refused);
    }
    // `set_port`'s own guard: the input must contain a digit *somewhere*, or it
    // returns false before `parse_port` runs. This is why `"x"` fails while
    // `"x1"` does not.
    if !trimmed.chars().any(|character| character.is_ascii_digit()) {
        return Err(UpdateError::Refused);
    }
    // `parse_port` on the whole trimmed string. A leading `-` invalidates it.
    if trimmed.starts_with('-') {
        return Err(UpdateError::Refused);
    }
    // `from_chars` reads the digit prefix only, and `is_valid` is never cleared
    // by a conversion error — only `result_out_of_range` and the `-` check clear
    // it. So an empty prefix (a digit exists, but not first: `"x1"`, `"+80"`)
    // leaves `is_valid` true and lands in the `else` branch of `parse_port`,
    // which *clears* the port and still reports success.
    let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        url.set_port(None).map_err(|()| UpdateError::Refused)?;
        return Ok(());
    }
    let Ok(port) = digits.parse::<u16>() else {
        return Err(UpdateError::Refused);
    };
    url.set_port(Some(port)).map_err(|()| UpdateError::Refused)
}

/// `url_aggregator::set_username`.
fn set_username(url: &mut Url, value: &str) -> Result<(), UpdateError> {
    if cannot_have_credentials_or_port(url) {
        return Err(UpdateError::Refused);
    }
    url.set_username(value).map_err(|()| UpdateError::Refused)
}

/// `url_aggregator::set_password`.
///
/// An empty value clears the password, which `set_password` expresses as
/// `None`; ada keeps the empty password and the empty password is what
/// serialization drops anyway, so the two agree.
fn set_password(url: &mut Url, value: &str) -> Result<(), UpdateError> {
    if cannot_have_credentials_or_port(url) {
        return Err(UpdateError::Refused);
    }
    let password = if value.is_empty() { None } else { Some(value) };
    url.set_password(password)
        .map_err(|()| UpdateError::Refused)
}

/// `url_aggregator::set_pathname`.
///
/// An opaque path cannot be replaced. Everything else is a rebuild of the
/// serialization with the new path, because `url::Url::set_path` differs from
/// ada in three ways that are all observable:
///
/// * It treats `?` and `#` as delimiters, so `set_pathname("?q=2")` would empty
///   the path and set a query, where ada percent-encodes them into the path.
/// * It collapses a leading `//` to `/` when the URL has an authority, where ada
///   keeps it (`file:////x` has path `//x`).
/// * It drops the `:` of `foo:` entirely when the path becomes empty, where ada
///   writes `foo:/`.
///
/// The rebuild is parsed once, so the result is exactly what a parser produces
/// and every other component keeps its meaning.
fn set_pathname(url: &mut Url, value: &str) -> Result<(), UpdateError> {
    if url.cannot_be_a_base() {
        return Err(UpdateError::Refused);
    }
    let wanted = normalise_path(value);
    // A path beginning `//` on a URL with no authority needs ada's literal `/.`
    // prefix, or re-parsing `foo:/.//x` would invent an authority.
    let path = if wanted.starts_with("//") && !url.has_authority() {
        format!("/.{wanted}")
    } else {
        wanted
    };
    // An empty path drops the trailing `/` of an authority URL, so
    // `foo://bar/baz` becomes `foo://bar`, not `foo://bar/`.
    let path = if value.is_empty() && url.has_authority() {
        String::new()
    } else {
        path
    };

    let scheme = url.scheme().to_string();
    let authority = if url.has_authority() {
        let userinfo = match (url.username(), url.password()) {
            ("", None) => String::new(),
            (user, password) => {
                let mut text = user.to_string();
                if let Some(password) = password {
                    text.push(':');
                    text.push_str(password);
                }
                text.push('@');
                text
            }
        };
        let host = url.host_str().unwrap_or("");
        let port = url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        format!("//{userinfo}{host}{port}")
    } else {
        String::new()
    };
    let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
    let fragment = url.fragment().map(|f| format!("#{f}")).unwrap_or_default();
    let rebuilt = format!("{scheme}:{authority}{path}{query}{fragment}");

    match Url::parse(&rebuilt) {
        Ok(replacement) => {
            // A `file:` URL whose path begins `//` (`file:////x`) is the one shape
            // the url crate cannot represent: it folds the extra slash while
            // parsing, and `Url` has no way to hold the longer form, so neither
            // `set_path` nor a re-parse can recover it. The folded URL is
            // returned instead, which is the documented difference in the crate
            // docs; every other path shape round-trips exactly.
            *url = replacement;
            Ok(())
        }
        Err(_) => Err(UpdateError::Refused),
    }
}

/// The path a `set_pathname` value produces, after dot-segment removal.
///
/// Percent-encodes `?` and `#` (which `set_path` would otherwise take as
/// delimiters) while leaving an existing `%xx` escape alone, then resolves `.`
/// and `..` and guarantees a leading `/`. An empty value becomes `/`, as it does
/// for a hierarchical URL.
fn normalise_path(value: &str) -> String {
    let escaped = value.replace('?', "%3F").replace('#', "%23");
    if escaped.is_empty() {
        return "/".to_string();
    }
    let mut segments: Vec<&str> = Vec::new();
    let mut trailing_slash = false;
    for segment in escaped.split('/') {
        match segment {
            "." => trailing_slash = true,
            ".." => {
                segments.pop();
                trailing_slash = true;
            }
            other => {
                segments.push(other);
                trailing_slash = other.is_empty() || other == "." || other == "..";
            }
        }
    }
    let mut path = segments.join("/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if trailing_slash && !path.ends_with('/') {
        path.push('/');
    }
    path
}

/// `url_aggregator::set_search`.
///
/// ada's setter has no failure mode: an empty value clears the query and
/// anything else becomes the query with a leading `?` optionally stripped by
/// the caller. `lib/internal/url.js` passes the value through
/// `StringPrototypeToWellFormed` and lets the setter encode it.
fn set_search(url: &mut Url, value: &str) {
    let value = value.strip_prefix('?').unwrap_or(value);
    if value.is_empty() {
        url.set_query(None);
    } else {
        url.set_query(Some(value));
    }
}

/// `url_aggregator::set_hash`.
fn set_hash(url: &mut Url, value: &str) {
    let value = value.strip_prefix('#').unwrap_or(value);
    if value.is_empty() {
        url.set_fragment(None);
    } else {
        url.set_fragment(Some(value));
    }
}

/// Checks a port value the way `set_port` does, without applying it.
///
/// Needed where ada parses the port but has no port component to write to — a
/// URL that is only now gaining an authority — so the invalid value must still
/// fail the update.
fn validate_port(value: &str) -> Result<(), UpdateError> {
    let trimmed: String = value
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect();
    if trimmed.is_empty() {
        return Ok(());
    }
    if !trimmed.chars().any(|character| character.is_ascii_digit()) || trimmed.starts_with('-') {
        return Err(UpdateError::Refused);
    }
    let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Ok(());
    }
    if digits.parse::<u16>().is_err() {
        return Err(UpdateError::Refused);
    }
    // The `cannot_have_credentials_or_port` guard is deliberately *not* applied:
    // it would reject exactly the case this exists for, a URL whose host is
    // currently absent and is being replaced in the same update.
    Ok(())
}

/// `cannot_have_credentials_or_port`: no host, an empty host, or `file`.
fn cannot_have_credentials_or_port(url: &Url) -> bool {
    url.host_str().is_none_or(str::is_empty) || url.scheme() == "file"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(href: &str, action: u32, value: &str) -> Option<String> {
        update(href, action, value).ok()
    }

    #[test]
    fn the_action_numbers_match_the_javascript_enum() {
        // `updateActions` in lib/internal/url.js.
        assert_eq!(
            [
                K_PROTOCOL, K_HOST, K_HOSTNAME, K_PORT, K_USERNAME, K_PASSWORD, K_PATHNAME,
                K_SEARCH, K_HASH, K_HREF
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn a_special_scheme_cannot_become_non_special() {
        // A non-special target is a silent no-op: ada's slow path returns true
        // without touching the URL, so the href comes back unchanged.
        let base = "https://u:p@example.com:8080/a/b?q=1#f";
        assert_eq!(apply(base, K_PROTOCOL, "foo").as_deref(), Some(base));
        assert_eq!(
            apply(base, K_PROTOCOL, "example.org").as_deref(),
            Some(base)
        );
        assert_eq!(
            apply(base, K_PROTOCOL, "http").as_deref(),
            Some("http://u:p@example.com:8080/a/b?q=1#f")
        );
    }

    #[test]
    fn a_non_special_target_in_capitals_is_also_a_no_op() {
        // `get_scheme_type` does not fold case, so `FILE` takes the slow path and
        // is a no-op even where lowercase `file` would be refused.
        let base = "https://user:pw@example.com:8080/a/b?q=1#f";
        assert_eq!(apply(base, K_PROTOCOL, "FILE").as_deref(), Some(base));
    }

    #[test]
    fn file_is_refused_when_credentials_or_a_port_are_present() {
        assert_eq!(apply("https://u:p@example.com/x", K_PROTOCOL, "file"), None);
        assert_eq!(
            apply("https://example.com:8080/x", K_PROTOCOL, "file"),
            None
        );
        assert_eq!(
            apply("https://example.com/x", K_PROTOCOL, "file").as_deref(),
            Some("file://example.com/x")
        );
    }

    #[test]
    fn a_non_special_scheme_cannot_become_special() {
        assert_eq!(apply("foo://bar/x", K_PROTOCOL, "https"), None);
        assert_eq!(apply("foo:/x", K_PROTOCOL, "https"), None);
    }

    #[test]
    fn a_scheme_needs_a_leading_letter() {
        for bad in ["", "1x", "-x", "a b", "%41"] {
            let outcome = apply("https://x.com/p", K_PROTOCOL, bad);
            // An empty value is a no-op in ada, everything else is refused.
            if bad.is_empty() {
                assert_eq!(outcome.as_deref(), Some("https://x.com/p"));
            } else {
                assert_eq!(outcome, None, "scheme {bad:?}");
            }
        }
    }

    #[test]
    fn a_valid_scheme_change_keeps_everything_else() {
        assert_eq!(
            apply("https://u:p@h.example:8080/a?q#f", K_PROTOCOL, "wss").as_deref(),
            Some("wss://u:p@h.example:8080/a?q#f")
        );
    }

    #[test]
    fn setting_the_default_port_clears_it() {
        assert_eq!(
            apply("https://ex.com:8080/p", K_PORT, "443").as_deref(),
            Some("https://ex.com/p")
        );
        // A non-special scheme has no default port, so it is kept.
        assert_eq!(
            apply("foo://ex.com:1/p", K_PORT, "80").as_deref(),
            Some("foo://ex.com:80/p")
        );
    }

    #[test]
    fn a_port_keeps_only_its_leading_digits() {
        assert_eq!(
            apply("https://ex.com:8080/p", K_PORT, "80a").as_deref(),
            Some("https://ex.com:80/p")
        );
    }

    #[test]
    fn a_port_value_that_is_not_a_number_is_refused() {
        for bad in ["x", " 8080 ", "99999", "65536"] {
            assert_eq!(
                apply("https://ex.com:8080/p", K_PORT, bad),
                None,
                "port {bad:?}"
            );
        }
    }

    #[test]
    fn a_port_cannot_be_set_on_a_file_or_hostless_url() {
        assert_eq!(apply("file:///tmp/x", K_PORT, "80"), None);
        assert_eq!(apply("mailto:a@b.c", K_PORT, "80"), None);
    }

    #[test]
    fn host_and_hostname_differ_on_a_port_suffix() {
        assert_eq!(
            apply("https://ex.com/p", K_HOST, "a:8080").as_deref(),
            Some("https://a:8080/p")
        );
        assert_eq!(apply("https://ex.com/p", K_HOSTNAME, "a:8080"), None);
    }

    #[test]
    fn an_empty_host_is_allowed_only_for_a_non_special_scheme() {
        assert_eq!(
            apply("foo://bar/baz", K_HOST, "").as_deref(),
            Some("foo:///baz")
        );
        assert_eq!(apply("https://ex.com/p", K_HOST, ""), None);
        assert_eq!(apply("https://ex.com/p", K_HOSTNAME, ""), None);
    }

    #[test]
    fn a_file_host_accepts_the_empty_value_and_collapses_localhost() {
        assert_eq!(
            apply("file:///tmp/x", K_HOST, "").as_deref(),
            Some("file:///tmp/x")
        );
        assert_eq!(
            apply("file:///tmp/x", K_HOST, "host").as_deref(),
            Some("file://host/tmp/x")
        );
    }

    #[test]
    fn credentials_cannot_be_set_without_a_host() {
        assert_eq!(apply("mailto:a@b.c", K_USERNAME, "u"), None);
        assert_eq!(apply("mailto:a@b.c", K_PASSWORD, "p"), None);
        assert_eq!(apply("file:///tmp/x", K_USERNAME, "u"), None);
    }

    #[test]
    fn a_username_is_percent_encoded() {
        assert_eq!(
            apply("https://u:p@ex.com/", K_USERNAME, "a b").as_deref(),
            Some("https://a%20b:p@ex.com/")
        );
    }

    #[test]
    fn a_password_can_be_added_and_cleared() {
        assert_eq!(
            apply("https://u@ex.com/", K_PASSWORD, "p").as_deref(),
            Some("https://u:p@ex.com/")
        );
        assert_eq!(
            apply("https://u:p@ex.com/", K_PASSWORD, "").as_deref(),
            Some("https://u@ex.com/")
        );
    }

    #[test]
    fn an_opaque_path_cannot_be_replaced() {
        assert_eq!(apply("mailto:a@b.c", K_PATHNAME, "/x"), None);
    }

    #[test]
    fn a_pathname_is_resolved_and_encoded() {
        assert_eq!(
            apply("https://x.com/p", K_PATHNAME, "/a/../b").as_deref(),
            Some("https://x.com/b")
        );
        assert_eq!(
            apply("https://x.com/p", K_PATHNAME, "a b").as_deref(),
            Some("https://x.com/a%20b")
        );
    }

    #[test]
    fn search_and_hash_strip_their_leading_sigil_and_encode() {
        assert_eq!(
            apply("https://x.com/p", K_SEARCH, "?q=2").as_deref(),
            Some("https://x.com/p?q=2")
        );
        assert_eq!(
            apply("https://x.com/p", K_HASH, "#h").as_deref(),
            Some("https://x.com/p#h")
        );
        assert_eq!(
            apply("https://x.com/p", K_SEARCH, "a b").as_deref(),
            Some("https://x.com/p?a%20b")
        );
    }

    #[test]
    fn an_empty_search_or_hash_clears_it() {
        assert_eq!(
            apply("https://a.com/x?q#h", K_SEARCH, "").as_deref(),
            Some("https://a.com/x#h")
        );
        assert_eq!(
            apply("https://a.com/x?q#h", K_HASH, "").as_deref(),
            Some("https://a.com/x?q")
        );
    }

    #[test]
    fn href_replaces_the_whole_url_and_refuses_an_invalid_one() {
        assert_eq!(
            apply("https://a.com/x", K_HREF, "file:///y").as_deref(),
            Some("file:///y")
        );
        assert_eq!(apply("https://a.com/x", K_HREF, "not a url"), None);
    }

    #[test]
    fn an_unknown_action_is_refused_instead_of_guessed() {
        assert_eq!(
            update("https://a.com/x", 42, "x"),
            Err(UpdateError::Refused)
        );
    }

    #[test]
    fn an_unparsable_href_reports_its_own_error() {
        assert_eq!(
            update("not a url", K_HASH, "h"),
            Err(UpdateError::Unparsable)
        );
    }
}
