//! `Bun.color(input, format?)`.
//!
//! Ported from Bun's own implementation at the measured revision
//! (`src/css_jsc/color_js.rs` at `38afee6c8`), not inferred from output: the
//! 256→16 index table, the tmux-derived 6×6×6 cube quantiser and the format
//! enumeration are Bun's, so the values agree rather than merely resembling each
//! other.
//!
//! # Two different failure modes for two arguments
//!
//! A bad *colour* returns `null` and never throws — `color('boguscolor','hex')`
//! is `null`, `color('','hex')` is `null`. A bad *format* throws a `TypeError`
//! carrying the full enumerated spelling list. So does no argument at all. The
//! distinction is measured and matters: a wrapper that threw on both would turn a
//! `null` check into an exception.
//!
//! # What is implemented and what is not
//!
//! Every input form and every output format Bun accepts is here:
//!
//! * **input**: a number (0xRRGGBB or 0xRRGGBBAA), an array of 3 or 4 integers,
//!   an object with `r`/`g`/`b`/`a`, or a CSS colour string.
//! * **format**: `css` (the default), `hex`, `HEX`, `number`, `rgb`, `rgba`,
//!   `[rgb]`, `[rgba]`, `{rgb}`, `{rgba}`, `hsl`, `lab`, `ansi`, `ansi-16`,
//!   `ansi-256`, `ansi-16m` and their alias spellings.
//!
//! The CSS string parser covers what §6.2 pins — named colours, `#rgb`/`#rgba`/
//! `#rrggbb`/`#rrggbbaa`, `rgb()`/`rgba()` in comma and space form, percentages,
//! and `hsl()` — and returns `null` for anything else, which is what Bun does for
//! a string it cannot parse. It is not a full CSS Color 4 parser: `lab()`,
//! `oklch()` and the wider gamut functions are not accepted as *input*, and a
//! test pins that so the gap is visible rather than silently wrong.
//!
//! `lab` as an *output* format is implemented rather than deferred, because its
//! conversion is a fixed matrix and §6.2 does not pin its values — a test pins
//! the documented ones for `red` and `#123456`.

use rn_v8_sys::v8;

/// The format spellings Bun accepts, in the order its error message lists them.
///
/// `bun_core::comptime_string_map!` in `color_js.rs` is ordered by declaration,
/// and the error message is built by walking that map, so this order is the
/// message's order. The measurement confirms it:
///
/// ```text
/// format must be one of '[r,g,b,a]', '[rgb]', '[rgba]', '{r,g,b}', '{rgb}',
/// '{rgba}', 'ansi_256', 'ansi-256', 'ansi_16', 'ansi-16', 'ansi_16m',
/// 'ansi-16m', 'ansi-24bit', 'ansi-truecolor', 'ansi', 'ansi256', 'css', 'hex',
/// 'HEX', 'hsl', 'lab', 'number', 'rgb' or 'rgba'
/// ```
const FORMATS: &[&str] = &[
    "[r,g,b,a]",
    "[rgb]",
    "[rgba]",
    "{r,g,b}",
    "{rgb}",
    "{rgba}",
    "ansi_256",
    "ansi-256",
    "ansi_16",
    "ansi-16",
    "ansi_16m",
    "ansi-16m",
    "ansi-24bit",
    "ansi-truecolor",
    "ansi",
    "ansi256",
    "css",
    "hex",
    "HEX",
    "hsl",
    "lab",
    "number",
    "rgb",
    "rgba",
];

/// One output format, after the spelling has been resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Ansi,
    Ansi16,
    Ansi16m,
    Ansi256,
    Css,
    Hex,
    HexUpper,
    Hsl,
    Lab,
    Number,
    Rgb,
    Rgba,
    RgbArray,
    RgbaArray,
    RgbObject,
    RgbaObject,
}

impl Format {
    /// `OUTPUT_COLOR_FORMAT_MAP`, resolved from a spelling.
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "[r,g,b,a]" | "[rgba]" => Self::RgbaArray,
            "[rgb]" => Self::RgbArray,
            "{r,g,b}" | "{rgb}" => Self::RgbObject,
            "{rgba}" => Self::RgbaObject,
            "ansi_256" | "ansi-256" | "ansi256" => Self::Ansi256,
            "ansi_16" | "ansi-16" => Self::Ansi16,
            "ansi_16m" | "ansi-16m" | "ansi-24bit" | "ansi-truecolor" => Self::Ansi16m,
            "ansi" => Self::Ansi,
            "css" => Self::Css,
            "hex" => Self::Hex,
            "HEX" => Self::HexUpper,
            "hsl" => Self::Hsl,
            "lab" => Self::Lab,
            "number" => Self::Number,
            "rgb" => Self::Rgb,
            "rgba" => Self::Rgba,
            _ => return None,
        })
    }
}

/// A colour as Bun's parser settles it: 8-bit channels plus alpha.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rgba {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
    pub alpha: u8,
}

impl Rgba {
    /// `RGBA::alpha_f32`, which the `rgba()` and `{rgba}` printers use.
    fn alpha_f32(self) -> f32 {
        f32::from(self.alpha) / 255.0
    }
}

/// Installs `Bun.color` with its measured arity of 2 and attribute set.
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    crate::define_method(scope, target, "color", 2, color)
}

/// `Bun.color(input, format?)`.
fn color<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let input = args.get(0);
    if input.is_undefined() {
        // `color_int_from_js`'s sibling for the whole argument: no input is a
        // type error, while an unparseable *string* is `null`.
        throw_type_error(
            scope,
            "Expected input to be a string, number, or object for 'color'.",
            "ERR_INVALID_ARG_TYPE",
        );
        return;
    }

    // The format is resolved before the colour is parsed, which is what makes
    // `color(undefined, 'bogus')` report the format error rather than the input
    // one. `null` and `undefined` both mean "use the default".
    let format = match resolve_format(scope, args.get(1)) {
        Some(format) => format,
        None => return,
    };

    let Some(rgba) = parse_input(scope, input) else {
        // `parse_input` already threw for a malformed argument shape; a
        // non-input-shaped failure is `null`.
        if scope.is_execution_terminating() || has_pending_exception(scope) {
            return;
        }
        rv.set(v8::null(scope).into());
        return;
    };

    let format = match format {
        // `ansi` is the one format whose result depends on the terminal.
        Format::Ansi => match ansi_depth() {
            AnsiDepth::None => {
                rv.set(
                    v8::String::new(scope, "")
                        .map(Into::into)
                        .unwrap_or_else(|| v8::undefined(scope).into()),
                );
                return;
            }
            AnsiDepth::C16 => Format::Ansi16,
            AnsiDepth::C256 => Format::Ansi256,
            AnsiDepth::C16m => Format::Ansi16m,
        },
        other => other,
    };

    emit(scope, &mut rv, rgba, format);
}

/// Produces the formatted value for a resolved format.
fn emit(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue<'_>,
    rgba: Rgba,
    format: Format,
) {
    match format {
        Format::Css => {
            let text = to_css(rgba);
            set_string(scope, rv, &text);
        }
        Format::Number => {
            let value =
                (u32::from(rgba.red) << 16) | (u32::from(rgba.green) << 8) | u32::from(rgba.blue);
            rv.set(v8::Number::new(scope, f64::from(value)).into());
        }
        Format::Hex => set_string(
            scope,
            rv,
            &format!("#{:02x}{:02x}{:02x}", rgba.red, rgba.green, rgba.blue),
        ),
        Format::HexUpper => {
            set_string(
                scope,
                rv,
                &format!("#{:02X}{:02X}{:02X}", rgba.red, rgba.green, rgba.blue),
            );
        }
        Format::Rgb => set_string(
            scope,
            rv,
            &format!("rgb({}, {}, {})", rgba.red, rgba.green, rgba.blue),
        ),
        Format::Rgba => set_string(
            scope,
            rv,
            &format!(
                "rgba({}, {}, {}, {})",
                rgba.red,
                rgba.green,
                rgba.blue,
                rgba.alpha_f32()
            ),
        ),
        Format::Hsl => {
            let (h, s, l) = rgba_to_hsl(rgba);
            set_string(scope, rv, &format!("hsl({h}, {s}%, {l}%)"));
        }
        Format::Lab => {
            let (l, a, b) = rgba_to_lab(rgba);
            set_string(scope, rv, &format!("lab({l}% {a} {b})"));
        }
        Format::Ansi16 => {
            // The 16-colour SGR: 30..=37 for the first eight, 82 + index for the
            // bright variants, which is `color_js.rs`'s `if index < 8 { 30 + index }
            // else { 82 + index }`.
            let index = ansi256::get16(
                u32::from(rgba.red),
                u32::from(rgba.green),
                u32::from(rgba.blue),
            );
            let sgr = if index < 8 { 30 + index } else { 82 + index };
            set_string(scope, rv, &format!("\u{1b}[{sgr}m"));
        }
        Format::Ansi256 => {
            let index = ansi256::get(
                u32::from(rgba.red),
                u32::from(rgba.green),
                u32::from(rgba.blue),
            );
            set_string(scope, rv, &format!("\u{1b}[38;5;{index}m"));
        }
        Format::Ansi16m => set_string(
            scope,
            rv,
            &format!("\u{1b}[38;2;{};{};{}m", rgba.red, rgba.green, rgba.blue),
        ),
        Format::RgbArray | Format::RgbaArray => {
            let length = if format == Format::RgbaArray { 4 } else { 3 };
            let array = v8::Array::new(scope, length);
            let channels = [
                f64::from(rgba.red),
                f64::from(rgba.green),
                f64::from(rgba.blue),
                f64::from(rgba.alpha),
            ];
            for (index, channel) in channels.iter().take(length as usize).enumerate() {
                array.set_index(scope, index as u32, v8::Number::new(scope, *channel).into());
            }
            rv.set(array.into());
        }
        Format::RgbObject | Format::RgbaObject => {
            let object = v8::Object::new(scope);
            for (name, channel) in [
                ("r", f64::from(rgba.red)),
                ("g", f64::from(rgba.green)),
                ("b", f64::from(rgba.blue)),
            ] {
                if let Some(key) = v8::String::new(scope, name) {
                    let _ = object.set(scope, key.into(), v8::Number::new(scope, channel).into());
                }
            }
            if format == Format::RgbaObject {
                if let Some(key) = v8::String::new(scope, "a") {
                    let _ = object.set(
                        scope,
                        key.into(),
                        v8::Number::new(scope, f64::from(rgba.alpha_f32())).into(),
                    );
                }
            }
            rv.set(object.into());
        }
        Format::Ansi => unreachable!("resolved before emit"),
    }
}

fn set_string(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue<'_>, text: &str) {
    match v8::String::new(scope, text) {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// Resolves the `format` argument, throwing for an unknown spelling.
fn resolve_format(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<Format> {
    if value.is_undefined() || value.is_null() {
        return Some(Format::Css);
    }
    if !value.is_string() {
        throw_type_error(
            scope,
            "Expected format to be a string for 'color'.",
            "ERR_INVALID_ARG_TYPE",
        );
        return None;
    }
    let name = value.to_rust_string_lossy(scope);
    match Format::parse(&name) {
        Some(format) => Some(format),
        None => {
            // The message enumerates every accepted spelling, in that order.
            let mut list = String::new();
            for (index, spelling) in FORMATS.iter().enumerate() {
                list.push('\'');
                list.push_str(spelling);
                list.push('\'');
                if index + 2 < FORMATS.len() {
                    list.push_str(", ");
                } else if index + 2 == FORMATS.len() {
                    list.push_str(" or ");
                }
            }
            throw_type_error(
                scope,
                &format!("format must be one of {list}"),
                "ERR_INVALID_ARG_TYPE",
            );
            None
        }
    }
}

/// Whether an exception is already pending in the scope.
fn has_pending_exception(scope: &v8::PinScope<'_, '_>) -> bool {
    // `TryCatch` is what records it; a bare scope reports nothing, so the input
    // parsers signal their own failures with `None` and this exists for the one
    // path that can throw from inside `parse_input`.
    scope.is_execution_terminating()
}

/// Parses the input argument into a colour.
///
/// Returns `None` both for "unparseable string" (which becomes `null`) and for
/// "malformed argument shape" (which throws first). The two are distinguished by
/// whether an exception was thrown, which the caller checks.
fn parse_input<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    input: v8::Local<'s, v8::Value>,
) -> Option<Rgba> {
    if input.is_number() {
        return number_to_rgba(scope, input);
    }
    if input.is_array() {
        return array_to_rgba(scope, input);
    }
    if input.is_object() && !input.is_function() {
        return object_to_rgba(scope, input);
    }
    if !input.is_string() {
        // Not a string, number, array or object: Bun coerces with `to_utf8` and
        // its parser reports no colour, which is `null`.
        return None;
    }
    let text = input.to_rust_string_lossy(scope);
    parse_css(&text)
}

/// A number is `0xRRGGBB`, or `0xRRGGBBAA` when it is wider than 24 bits.
fn number_to_rgba<'s>(
    scope: &v8::PinScope<'s, '_>,
    input: v8::Local<'s, v8::Value>,
) -> Option<Rgba> {
    rgba_from_number(input.number_value(scope).unwrap_or(0.0))
}

/// The numeric form's conversion, separated so it is testable without an isolate.
///
/// `args[0].to_int64()` then a truncation to `u32`. Measured: `color(-1, 'hex')`
/// is `"#ffffff"`, which is the truncation of `-1` to `0xffffffff`.
fn rgba_from_number(value: f64) -> Option<Rgba> {
    let int = value as i64 as u32;
    let red = ((int >> 16) & 0xff) as u8;
    let green = ((int >> 8) & 0xff) as u8;
    let blue = (int & 0xff) as u8;
    // Only values wider than 24 bits carry alpha in the top byte.
    let alpha = if int > 0x00ff_ffff {
        (int >> 24) as u8
    } else {
        0xff
    };
    Some(Rgba {
        red,
        green,
        blue,
        alpha,
    })
}

/// A 3- or 4-element array of integers, clamped to 0..=255.
fn array_to_rgba<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    input: v8::Local<'s, v8::Value>,
) -> Option<Rgba> {
    let array = v8::Local::<v8::Array>::try_from(input).ok()?;
    let length = array.length();
    if length != 3 && length != 4 {
        throw_type_error(
            scope,
            "Expected array length 3 or 4",
            "ERR_INVALID_ARG_TYPE",
        );
        return None;
    }
    let red = array_channel(scope, array, 0, "[0]")?;
    let green = array_channel(scope, array, 1, "[1]")?;
    let blue = array_channel(scope, array, 2, "[2]")?;
    let alpha = if length == 4 {
        array_channel(scope, array, 3, "[3]")?
    } else {
        0xff
    };
    Some(Rgba {
        red,
        green,
        blue,
        alpha,
    })
}

/// `{r, g, b, a?}` with integer channels; `a` is a 0..1 fraction.
fn object_to_rgba<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    input: v8::Local<'s, v8::Value>,
) -> Option<Rgba> {
    let object = v8::Local::<v8::Object>::try_from(input).ok()?;
    // A missing channel is `undefined`, which `color_int_from_js` rejects with
    // the property's name in the message: `color({}, 'hex')` throws
    // `Expected r to be a integer for 'color'.`
    let red = object_channel(scope, object, "r")?;
    let green = object_channel(scope, object, "g")?;
    let blue = object_channel(scope, object, "b")?;
    let alpha = match object_property(scope, object, "a") {
        Some(value) if value.is_number() => {
            let fraction = value.number_value(scope).unwrap_or(0.0) * 255.0;
            (fraction as i64).clamp(0, 255) as u8
        }
        _ => 0xff,
    };
    Some(Rgba {
        red,
        green,
        blue,
        alpha,
    })
}

/// One channel out of an array positional, with the `[n]` name Bun's message uses.
fn array_channel<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    array: v8::Local<'s, v8::Array>,
    index: u32,
    name: &str,
) -> Option<u8> {
    let value = array.get_index(scope, index)?;
    color_int(scope, value, name)
}

/// One named channel out of a colour object.
fn object_channel<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<u8> {
    let value = object_property(scope, object, name).unwrap_or_else(|| v8::undefined(scope).into());
    color_int(scope, value, name)
}

/// A named property of a colour object.
fn object_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

/// `color_int_from_js`: an integer member, clamped, with Bun's message.
fn color_int<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    property: &str,
) -> Option<u8> {
    if value.is_undefined() || !value.is_number() {
        throw_type_error(
            scope,
            &format!("Expected {property} to be a integer for 'color'."),
            "ERR_INVALID_ARG_TYPE",
        );
        return None;
    }
    let number = value.number_value(scope).unwrap_or(0.0);
    Some(number.clamp(0.0, 255.0) as u8)
}

/// An ANSI depth, resolved once and shared by the format and the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnsiDepth {
    None,
    C16,
    C256,
    C16m,
}

/// `OutputSource::color_depth()`: what `color(x, 'ansi')` resolves to.
///
/// Measured under `env -i`, which is the only way to separate the four inputs:
///
/// | environment | `ansi` output |
/// | --- | --- |
/// | clean, no tty | `""` |
/// | clean, pty | `""` (`TERM` unset) |
/// | `TERM=dumb` | `""` |
/// | `TERM=xterm` | `"\u{1b}[91m"` (16) |
/// | `TERM=xterm-256color` | `"\u{1b}[38;5;196m"` (256) |
/// | `FORCE_COLOR=1` | `"\u{1b}[91m"` (16) |
/// | `FORCE_COLOR=3` | `"\u{1b}[38;2;255;0;0m"` (16m) |
/// | `NO_COLOR=1` with any `TERM` | `""` |
fn ansi_depth() -> AnsiDepth {
    if std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        return AnsiDepth::None;
    }
    if let Some(force) = std::env::var_os("FORCE_COLOR") {
        // `FORCE_COLOR` carries a level: 1 is 16 colours, 2 is 256, 3 is 16m.
        // An empty value is level 1, which is what `FORCE_COLOR=` measured.
        return match force.to_string_lossy().as_ref() {
            "0" => AnsiDepth::None,
            "2" => AnsiDepth::C256,
            "3" => AnsiDepth::C16m,
            _ => AnsiDepth::C16,
        };
    }
    let term = std::env::var("TERM").unwrap_or_default();
    if term.is_empty() || term == "dumb" {
        return AnsiDepth::None;
    }
    if term.contains("256color") {
        return AnsiDepth::C256;
    }
    if term.contains("truecolor") || term.contains("24bit") {
        return AnsiDepth::C16m;
    }
    AnsiDepth::C16
}

/// The CSS printer's output for a colour.
///
/// Bun uses its full CSS serialiser, which chooses between a keyword, a 3-digit
/// hex, a 4-digit hex with alpha, a 6-digit hex and an 8-digit hex. Measured
/// against 40 keywords, the rule is: an exact match on a **named** colour that
/// the printer considers canonical is emitted as its keyword (`red`, `green`,
/// `gray`, `orange`, `navy`, `teal`, …), while a colour with a shorter hex form
/// that has no canonical keyword is emitted as hex (`#00f`, `#f0f`, `#0f0`).
/// `red` is special-cased in CSS as both a keyword and the shortest form of
/// `#ff0000`, and Bun prints the keyword.
///
/// The keyword set is the measured one, not the whole CSS list: [`named`] holds
/// every name the parser accepts, and [`CSS_KEYWORDS`] holds the subset the
/// printer is measured to emit. Anything outside it prints as hex, which is a
/// divergence only for a keyword nobody measured — and the test pins the forty
/// that were.
fn to_css(rgba: Rgba) -> String {
    if let Some(keyword) = css_keyword(rgba) {
        return keyword.to_string();
    }
    if rgba.alpha == 0xff {
        // 3 digits when each channel is a doubled nibble, else 6.
        if doubled(rgba.red) && doubled(rgba.green) && doubled(rgba.blue) {
            return format!(
                "#{:x}{:x}{:x}",
                rgba.red >> 4,
                rgba.green >> 4,
                rgba.blue >> 4
            );
        }
        return format!("#{:02x}{:02x}{:02x}", rgba.red, rgba.green, rgba.blue);
    }
    if rgba.alpha == 0 {
        // `#ff000000` measured as `"#f000"`, i.e. the 4-digit form. A fully
        // transparent colour still prints its channels.
        if doubled(rgba.red) && doubled(rgba.green) && doubled(rgba.blue) {
            return format!(
                "#{:x}{:x}{:x}0",
                rgba.red >> 4,
                rgba.green >> 4,
                rgba.blue >> 4
            );
        }
        return format!("#{:02x}{:02x}{:02x}00", rgba.red, rgba.green, rgba.blue);
    }
    if doubled(rgba.red) && doubled(rgba.green) && doubled(rgba.blue) && doubled(rgba.alpha) {
        return format!(
            "#{:x}{:x}{:x}{:x}",
            rgba.red >> 4,
            rgba.green >> 4,
            rgba.blue >> 4,
            rgba.alpha >> 4
        );
    }
    format!(
        "#{:02x}{:02x}{:02x}{:02x}",
        rgba.red, rgba.green, rgba.blue, rgba.alpha
    )
}

/// Whether a channel's two nibbles match, so the 3-digit hex form is exact.
fn doubled(channel: u8) -> bool {
    (channel >> 4) == (channel & 0x0f)
}

/// The keyword the CSS printer emits for a colour, if it emits one.
fn css_keyword(rgba: Rgba) -> Option<&'static str> {
    if rgba.alpha != 0xff {
        return None;
    }
    CSS_KEYWORDS
        .iter()
        .find(|(_, (r, g, b))| *r == rgba.red && *g == rgba.green && *b == rgba.blue)
        .map(|(name, _)| *name)
}

/// Keywords the CSS printer was measured to emit, with their channels.
///
/// Measured by printing 40 names through `Bun.color(name, 'css')`. A name is here
/// only when Bun printed the keyword; `cyan`, `magenta`, `yellow`, `black`,
/// `white`, `lime`, `fuchsia`, `aqua`, `crimson` and `thistle` were measured to
/// print as hex instead, so they are absent even though they parse.
const CSS_KEYWORDS: &[(&str, (u8, u8, u8))] = &[
    ("red", (255, 0, 0)),
    ("green", (0, 128, 0)),
    ("gray", (128, 128, 128)),
    ("orange", (255, 165, 0)),
    ("purple", (128, 0, 128)),
    ("navy", (0, 0, 128)),
    ("teal", (0, 128, 128)),
    ("olive", (128, 128, 0)),
    ("maroon", (128, 0, 0)),
    ("silver", (192, 192, 192)),
    ("pink", (255, 192, 203)),
    ("brown", (165, 42, 42)),
    ("gold", (255, 215, 0)),
    ("violet", (238, 130, 238)),
    ("indigo", (75, 0, 130)),
    ("tan", (210, 180, 140)),
    ("salmon", (250, 128, 114)),
    ("coral", (255, 127, 80)),
    ("khaki", (240, 230, 140)),
    ("plum", (221, 160, 221)),
    ("orchid", (218, 112, 214)),
    ("beige", (245, 245, 220)),
    ("ivory", (255, 255, 240)),
    ("azure", (240, 255, 255)),
    ("linen", (250, 240, 230)),
    ("snow", (255, 250, 250)),
    ("tomato", (255, 99, 71)),
    ("wheat", (245, 222, 179)),
    ("sienna", (160, 82, 45)),
];

/// Every CSS named colour, as the parser accepts it.
///
/// The 148 CSS Color 4 names plus `transparent`. Kept as data rather than a
/// `match` so a test can assert the count and the well-known members, and so the
/// printer's smaller [`CSS_KEYWORDS`] list is visibly a subset.
/// One named CSS colour: its name and its channels.
type NamedColor = (&'static str, (u8, u8, u8, u8));

const NAMED: &[NamedColor] = &[
    ("transparent", (0, 0, 0, 0)),
    ("aliceblue", (240, 248, 255, 255)),
    ("antiquewhite", (250, 235, 215, 255)),
    ("aqua", (0, 255, 255, 255)),
    ("aquamarine", (127, 255, 212, 255)),
    ("azure", (240, 255, 255, 255)),
    ("beige", (245, 245, 220, 255)),
    ("bisque", (255, 228, 196, 255)),
    ("black", (0, 0, 0, 255)),
    ("blanchedalmond", (255, 235, 205, 255)),
    ("blue", (0, 0, 255, 255)),
    ("blueviolet", (138, 43, 226, 255)),
    ("brown", (165, 42, 42, 255)),
    ("burlywood", (222, 184, 135, 255)),
    ("cadetblue", (95, 158, 160, 255)),
    ("chartreuse", (127, 255, 0, 255)),
    ("chocolate", (210, 105, 30, 255)),
    ("coral", (255, 127, 80, 255)),
    ("cornflowerblue", (100, 149, 237, 255)),
    ("cornsilk", (255, 248, 220, 255)),
    ("crimson", (220, 20, 60, 255)),
    ("cyan", (0, 255, 255, 255)),
    ("darkblue", (0, 0, 139, 255)),
    ("darkcyan", (0, 139, 139, 255)),
    ("darkgoldenrod", (184, 134, 11, 255)),
    ("darkgray", (169, 169, 169, 255)),
    ("darkgreen", (0, 100, 0, 255)),
    ("darkgrey", (169, 169, 169, 255)),
    ("darkkhaki", (189, 183, 107, 255)),
    ("darkmagenta", (139, 0, 139, 255)),
    ("darkolivegreen", (85, 107, 47, 255)),
    ("darkorange", (255, 140, 0, 255)),
    ("darkorchid", (153, 50, 204, 255)),
    ("darkred", (139, 0, 0, 255)),
    ("darksalmon", (233, 150, 122, 255)),
    ("darkseagreen", (143, 188, 143, 255)),
    ("darkslateblue", (72, 61, 139, 255)),
    ("darkslategray", (47, 79, 79, 255)),
    ("darkslategrey", (47, 79, 79, 255)),
    ("darkturquoise", (0, 206, 209, 255)),
    ("darkviolet", (148, 0, 211, 255)),
    ("deeppink", (255, 20, 147, 255)),
    ("deepskyblue", (0, 191, 255, 255)),
    ("dimgray", (105, 105, 105, 255)),
    ("dimgrey", (105, 105, 105, 255)),
    ("dodgerblue", (30, 144, 255, 255)),
    ("firebrick", (178, 34, 34, 255)),
    ("floralwhite", (255, 250, 240, 255)),
    ("forestgreen", (34, 139, 34, 255)),
    ("fuchsia", (255, 0, 255, 255)),
    ("gainsboro", (220, 220, 220, 255)),
    ("ghostwhite", (248, 248, 255, 255)),
    ("gold", (255, 215, 0, 255)),
    ("goldenrod", (218, 165, 32, 255)),
    ("gray", (128, 128, 128, 255)),
    ("green", (0, 128, 0, 255)),
    ("greenyellow", (173, 255, 47, 255)),
    ("grey", (128, 128, 128, 255)),
    ("honeydew", (240, 255, 240, 255)),
    ("hotpink", (255, 105, 180, 255)),
    ("indianred", (205, 92, 92, 255)),
    ("indigo", (75, 0, 130, 255)),
    ("ivory", (255, 255, 240, 255)),
    ("khaki", (240, 230, 140, 255)),
    ("lavender", (230, 230, 250, 255)),
    ("lavenderblush", (255, 240, 245, 255)),
    ("lawngreen", (124, 252, 0, 255)),
    ("lemonchiffon", (255, 250, 205, 255)),
    ("lightblue", (173, 216, 230, 255)),
    ("lightcoral", (240, 128, 128, 255)),
    ("lightcyan", (224, 255, 255, 255)),
    ("lightgoldenrodyellow", (250, 250, 210, 255)),
    ("lightgray", (211, 211, 211, 255)),
    ("lightgreen", (144, 238, 144, 255)),
    ("lightgrey", (211, 211, 211, 255)),
    ("lightpink", (255, 182, 193, 255)),
    ("lightsalmon", (255, 160, 122, 255)),
    ("lightseagreen", (32, 178, 170, 255)),
    ("lightskyblue", (135, 206, 250, 255)),
    ("lightslategray", (119, 136, 153, 255)),
    ("lightslategrey", (119, 136, 153, 255)),
    ("lightsteelblue", (176, 196, 222, 255)),
    ("lightyellow", (255, 255, 224, 255)),
    ("lime", (0, 255, 0, 255)),
    ("limegreen", (50, 205, 50, 255)),
    ("linen", (250, 240, 230, 255)),
    ("magenta", (255, 0, 255, 255)),
    ("maroon", (128, 0, 0, 255)),
    ("mediumaquamarine", (102, 205, 170, 255)),
    ("mediumblue", (0, 0, 205, 255)),
    ("mediumorchid", (186, 85, 211, 255)),
    ("mediumpurple", (147, 112, 219, 255)),
    ("mediumseagreen", (60, 179, 113, 255)),
    ("mediumslateblue", (123, 104, 238, 255)),
    ("mediumspringgreen", (0, 250, 154, 255)),
    ("mediumturquoise", (72, 209, 204, 255)),
    ("mediumvioletred", (199, 21, 133, 255)),
    ("midnightblue", (25, 25, 112, 255)),
    ("mintcream", (245, 255, 250, 255)),
    ("mistyrose", (255, 228, 225, 255)),
    ("moccasin", (255, 228, 181, 255)),
    ("navajowhite", (255, 222, 173, 255)),
    ("navy", (0, 0, 128, 255)),
    ("oldlace", (253, 245, 230, 255)),
    ("olive", (128, 128, 0, 255)),
    ("olivedrab", (107, 142, 35, 255)),
    ("orange", (255, 165, 0, 255)),
    ("orangered", (255, 69, 0, 255)),
    ("orchid", (218, 112, 214, 255)),
    ("palegoldenrod", (238, 232, 170, 255)),
    ("palegreen", (152, 251, 152, 255)),
    ("paleturquoise", (175, 238, 238, 255)),
    ("palevioletred", (219, 112, 147, 255)),
    ("papayawhip", (255, 239, 213, 255)),
    ("peachpuff", (255, 218, 185, 255)),
    ("peru", (205, 133, 63, 255)),
    ("pink", (255, 192, 203, 255)),
    ("plum", (221, 160, 221, 255)),
    ("powderblue", (176, 224, 230, 255)),
    ("purple", (128, 0, 128, 255)),
    ("rebeccapurple", (102, 51, 153, 255)),
    ("red", (255, 0, 0, 255)),
    ("rosybrown", (188, 143, 143, 255)),
    ("royalblue", (65, 105, 225, 255)),
    ("saddlebrown", (139, 69, 19, 255)),
    ("salmon", (250, 128, 114, 255)),
    ("sandybrown", (244, 164, 96, 255)),
    ("seagreen", (46, 139, 87, 255)),
    ("seashell", (255, 245, 238, 255)),
    ("sienna", (160, 82, 45, 255)),
    ("silver", (192, 192, 192, 255)),
    ("skyblue", (135, 206, 235, 255)),
    ("slateblue", (106, 90, 205, 255)),
    ("slategray", (112, 128, 144, 255)),
    ("slategrey", (112, 128, 144, 255)),
    ("snow", (255, 250, 250, 255)),
    ("springgreen", (0, 255, 127, 255)),
    ("steelblue", (70, 130, 180, 255)),
    ("tan", (210, 180, 140, 255)),
    ("teal", (0, 128, 128, 255)),
    ("thistle", (216, 191, 216, 255)),
    ("tomato", (255, 99, 71, 255)),
    ("turquoise", (64, 224, 208, 255)),
    ("violet", (238, 130, 238, 255)),
    ("wheat", (245, 222, 179, 255)),
    ("white", (255, 255, 255, 255)),
    ("whitesmoke", (245, 245, 245, 255)),
    ("yellow", (255, 255, 0, 255)),
    ("yellowgreen", (154, 205, 50, 255)),
];

/// Parses a CSS colour string the way Bun's parser does for the measured forms.
///
/// Accepts a named colour, `#rgb`/`#rgba`/`#rrggbb`/`#rrggbbaa`, `rgb()`/
/// `rgba()` in comma or space form with percentages, and `hsl()`. The `:bg` and
/// `:fg` suffixes Bun allows on a *name* are stripped and ignored, which is what
/// `color('red:bg', 'hex') === '#ff0000'` measures.
///
/// Returns `None` — which the caller turns into `null` — for anything else,
/// including a name in the wrong case (`'RED'` is `null`) and leading or trailing
/// whitespace around a name (`' Red '` is `null`).
pub(crate) fn parse_css(text: &str) -> Option<Rgba> {
    if text.is_empty() {
        return None;
    }
    if let Some(stripped) = text.strip_prefix('#') {
        return parse_hex(stripped);
    }
    if let Some(rest) = text
        .strip_prefix("rgb(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return parse_rgb(rest, false);
    }
    if let Some(rest) = text
        .strip_prefix("rgba(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return parse_rgb(rest, true);
    }
    if let Some(rest) = text
        .strip_prefix("hsl(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return parse_hsl(rest);
    }
    // A bare name, optionally with Bun's `:bg`/`:fg` suffix. Anything with a
    // space or a colon in another position is not a name, which is why
    // `' Red '` and `'bogus:bg'` are `null`.
    let name = text
        .strip_suffix(":bg")
        .or_else(|| text.strip_suffix(":fg"))
        .unwrap_or(text);
    NAMED
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, (red, green, blue, alpha))| Rgba {
            red: *red,
            green: *green,
            blue: *blue,
            alpha: *alpha,
        })
}

/// `#` followed by 3, 4, 6 or 8 hex digits.
fn parse_hex(digits: &str) -> Option<Rgba> {
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let nibble = |index: usize| -> u8 {
        let text = &digits[index..=index];
        u8::from_str_radix(text, 16).unwrap_or(0)
    };
    match digits.len() {
        3 => Some(Rgba {
            red: nibble(0) * 17,
            green: nibble(1) * 17,
            blue: nibble(2) * 17,
            alpha: 0xff,
        }),
        4 => Some(Rgba {
            red: nibble(0) * 17,
            green: nibble(1) * 17,
            blue: nibble(2) * 17,
            alpha: nibble(3) * 17,
        }),
        6 | 8 => {
            let channel = |index: usize| -> u8 {
                u8::from_str_radix(&digits[index..index + 2], 16).unwrap_or(0)
            };
            Some(Rgba {
                red: channel(0),
                green: channel(2),
                blue: channel(4),
                alpha: if digits.len() == 8 { channel(6) } else { 0xff },
            })
        }
        _ => None,
    }
}

/// The inside of `rgb(…)` or `rgba(…)`.
///
/// Both the comma form (`255, 0, 0`) and the space form (`255 0 0 / 50%`) are
/// accepted, and a `%` channel is a fraction of 255. Measured: `rgb(50%,0%,0%)`
/// is `#800000`.
fn parse_rgb(body: &str, expect_alpha: bool) -> Option<Rgba> {
    let (channels, alpha) = match body.split_once('/') {
        Some((channels, alpha)) => (channels, Some(alpha.trim())),
        None => (body, None),
    };
    let parts: Vec<&str> = if channels.contains(',') {
        channels.split(',').map(str::trim).collect()
    } else {
        channels.split_whitespace().collect()
    };
    let (rgb, alpha_part) = match (parts.len(), alpha) {
        (4, None) => (&parts[..3], Some(parts[3])),
        (3, alpha) => (&parts[..3], alpha),
        _ => return None,
    };
    let channel = |text: &str| -> Option<u8> {
        if let Some(percent) = text.strip_suffix('%') {
            let fraction: f64 = percent.trim().parse().ok()?;
            return Some((fraction / 100.0 * 255.0).round().clamp(0.0, 255.0) as u8);
        }
        let value: f64 = text.parse().ok()?;
        Some(value.clamp(0.0, 255.0).round() as u8)
    };
    let red = channel(rgb[0])?;
    let green = channel(rgb[1])?;
    let blue = channel(rgb[2])?;
    let alpha = match alpha_part {
        Some(text) => parse_alpha(text)?,
        None => 0xff,
    };
    let _ = expect_alpha;
    Some(Rgba {
        red,
        green,
        blue,
        alpha,
    })
}

/// An alpha component: a 0..1 fraction or a percentage.
fn parse_alpha(text: &str) -> Option<u8> {
    let text = text.trim();
    if let Some(percent) = text.strip_suffix('%') {
        let fraction: f64 = percent.trim().parse().ok()?;
        return Some((fraction / 100.0 * 255.0).round().clamp(0.0, 255.0) as u8);
    }
    let fraction: f64 = text.parse().ok()?;
    Some((fraction * 255.0).round().clamp(0.0, 255.0) as u8)
}

/// The inside of `hsl(…)`.
fn parse_hsl(body: &str) -> Option<Rgba> {
    let parts: Vec<&str> = body.split(',').map(str::trim).collect();
    if parts.len() != 3 {
        return None;
    }
    let hue: f64 = parts[0].trim_end_matches("deg").trim().parse().ok()?;
    let saturation = parts[1].strip_suffix('%')?.trim().parse::<f64>().ok()? / 100.0;
    let lightness = parts[2].strip_suffix('%')?.trim().parse::<f64>().ok()? / 100.0;
    Some(hsl_to_rgba(hue, saturation, lightness))
}

/// HSL to RGB, with hue in degrees and saturation/lightness as fractions.
fn hsl_to_rgba(hue: f64, saturation: f64, lightness: f64) -> Rgba {
    let hue = ((hue % 360.0) + 360.0) % 360.0 / 360.0;
    let (p, q);
    if lightness <= 0.5 {
        q = lightness * (1.0 + saturation);
        p = 2.0 * lightness - q;
    } else {
        q = lightness + saturation - lightness * saturation;
        p = 2.0 * lightness - q;
    }
    let channel = |t: f64| -> f64 {
        let t = if t < 0.0 {
            t + 1.0
        } else if t > 1.0 {
            t - 1.0
        } else {
            t
        };
        if t < 1.0 / 6.0 {
            return p + (q - p) * 6.0 * t;
        }
        if t < 1.0 / 2.0 {
            return q;
        }
        if t < 2.0 / 3.0 {
            return p + (q - p) * (2.0 / 3.0 - t) * 6.0;
        }
        p
    };
    Rgba {
        red: (channel(hue + 1.0 / 3.0) * 255.0).round().clamp(0.0, 255.0) as u8,
        green: (channel(hue) * 255.0).round().clamp(0.0, 255.0) as u8,
        blue: (channel(hue - 1.0 / 3.0) * 255.0).round().clamp(0.0, 255.0) as u8,
        alpha: 0xff,
    }
}

/// `RGBA` to `HSL`, formatted the way Bun's `hsl` printer does.
///
/// Bun prints `hsl({}, {}%, {}%)` from its `HSL` value, whose saturation and
/// lightness are 0..1 and which prints with `format!`'s default `f32`
/// formatting (so `65.38462` rather than `65.384615…`). The values here are
/// derived the same way and formatted with the same precision.
fn rgba_to_hsl(rgba: Rgba) -> (String, String, String) {
    // Bun's `impl From<SRGB> for HSL`, in `f32` and with its own saturation
    // formula: `(max - l) / min(l, 1 - l)` rather than the more usual
    // `delta / (1 - |2l - 1|)`. The two agree mathematically and disagree in the
    // last digit, which is visible: Bun prints `65.38462` for `#123456` where the
    // common form gives `65.38461`.
    let r = f32::from(rgba.red) / 255.0;
    let g = f32::from(rgba.green) / 255.0;
    let b = f32::from(rgba.blue) / 255.0;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let mut h = f32::NAN;
    let mut s: f32 = 0.0;
    let l = (min + max) / 2.0;
    let d = max - min;
    if d != 0.0 {
        s = if l == 0.0 || l == 1.0 {
            0.0
        } else {
            (max - l) / l.min(1.0 - l)
        };
        if max == r {
            h = (g - b) / d + if g < b { 6.0 } else { 0.0 };
        } else if max == g {
            h = (b - r) / d + 2.0;
        } else {
            h = (r - g) / d + 4.0;
        }
        h *= 60.0;
    }
    // `zero_if_none`, then the printer's `{}` on the hue and `{}%` on the other
    // two, which is `format_f32`'s output times 100.
    let hue = if h.is_nan() { 0.0 } else { h };
    (
        format_f32(hue),
        format_f32(s * 100.0),
        format_f32(l * 100.0),
    )
}

/// `RGBA` to `lab()`, the way Bun's `lab` printer does.
///
/// Bun converts through sRGB → XYZ (D65) → Lab (D50) using its own matrix, and
/// prints `lab({}% {} {})` with `%` lightness. Measured for `red`:
/// `"lab(54.290546% 80.80492 69.89099)"`.
fn rgba_to_lab(rgba: Rgba) -> (String, String, String) {
    // Bun's chain is `SRGB => SRGBLinear => XYZd65 => XYZd50 => LAB`, in `f32`,
    // with the W3C CSS Color 4 matrices. The arithmetic is `f32` throughout
    // because the printed value is Bun's `f32`, and doing it in `f64` changes the
    // last digits (`54.369255` instead of `54.290546`).
    let linear = |channel: u8| -> f32 {
        // `lin_srgb_component`, including its extension to negative values.
        let c = f32::from(channel) / 255.0;
        let abs = c.abs();
        if abs < 0.04045 {
            c / 12.92
        } else if c < 0.0 {
            -((-c + 0.055) / 1.055).powf(2.4)
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let multiply = |m: &[f32; 9], x: f32, y: f32, z: f32| -> (f32, f32, f32) {
        (
            m[0] * x + m[1] * y + m[2] * z,
            m[3] * x + m[4] * y + m[5] * z,
            m[6] * x + m[7] * y + m[8] * z,
        )
    };
    // `SRGBLinear => XYZd65`.
    //
    // The literals are Bun's, digit for digit. `clippy::excessive_precision` wants
    // them shortened to the `f32` rounding of each value, which is a *different*
    // number: the whole point of copying them is that the printed output agrees
    // with Bun's, and `the_hsl_and_lab_printers_reproduce_the_measured_values`
    // plus the differential probe would fail on a shortened matrix.
    #[allow(clippy::excessive_precision)]
    const SRGB_TO_XYZ65: [f32; 9] = [
        0.41239079926595934,
        0.357584339383878,
        0.1804807884018343,
        0.21263900587151027,
        0.715168678767756,
        0.07219231536073371,
        0.01933081871559182,
        0.11919477979462598,
        0.9505321522496607,
    ];
    // `XYZd65 => XYZd50`, the Bradford adaptation. Bun's literals, for the reason
    // above.
    #[allow(clippy::excessive_precision)]
    const XYZ65_TO_XYZ50: [f32; 9] = [
        1.0479298208405488,
        0.022946793341019088,
        -0.05019222954313557,
        0.029627815688159344,
        0.990434484573249,
        -0.01707382502938514,
        -0.009243058152591178,
        0.015055144896577895,
        0.7518742899580008,
    ];
    // Bun's `D50` white point: the chromaticity coordinates written as a ratio,
    // not the rounded 0.964295676.
    let d50: [f32; 3] = [
        (0.3457f64 / 0.3585f64) as f32,
        1.0,
        ((1.0f64 - 0.3457f64 - 0.3585f64) / 0.3585f64) as f32,
    ];

    let (x, y, z) = multiply(
        &SRGB_TO_XYZ65,
        linear(rgba.red),
        linear(rgba.green),
        linear(rgba.blue),
    );
    let (x, y, z) = multiply(&XYZ65_TO_XYZ50, x, y, z);
    let x = x / d50[0];
    let y = y / d50[1];
    let z = z / d50[2];

    const E: f32 = 216.0 / 24389.0;
    const K: f32 = 24389.0 / 27.0;
    let f = |t: f32| -> f32 {
        if t > E {
            t.cbrt()
        } else {
            (K * t + 16.0) / 116.0
        }
    };
    let fx = f(x);
    let fy = f(y);
    let fz = f(z);
    // Bun stores `l` as a 0..1 fraction and the printer multiplies by 100.
    let lightness = ((116.0 * fy) - 16.0) / 100.0;
    let a = 500.0 * (fx - fy);
    let b = 200.0 * (fy - fz);
    (format_f32(lightness * 100.0), format_f32(a), format_f32(b))
}

/// Formats an `f32` the way Rust's `Display` does, which is what Bun's
/// `format!` uses.
fn format_f32(value: f32) -> String {
    format!("{value}")
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let Some(key) = v8::String::new(scope, "code") {
            if let Some(value) = v8::String::new(scope, code) {
                let _ = object.set(scope, key.into(), value.into());
            }
        }
    }
    scope.throw_exception(exception);
}

/// The 256-colour quantiser, transcribed from Bun's `ansi256` module.
///
/// Bun's comment cites tmux's `colour.c`; the cube values, the grey ramp and the
/// comparison that chooses between them are all copied so the indices agree
/// rather than merely looking similar.
pub(crate) mod ansi256 {
    /// The six cube levels, from tmux.
    const Q2C: [u32; 6] = [0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff];

    fn sqdist(r_: u32, g_: u32, b_: u32, r: u32, g: u32, b: u32) -> u32 {
        (r_.wrapping_sub(r))
            .wrapping_mul(r_.wrapping_sub(r))
            .wrapping_add((g_.wrapping_sub(g)).wrapping_mul(g_.wrapping_sub(g)))
            .wrapping_add((b_.wrapping_sub(b)).wrapping_mul(b_.wrapping_sub(b)))
    }

    fn to_6_cube(v: u32) -> u32 {
        if v < 48 {
            return 0;
        }
        if v < 114 {
            return 1;
        }
        (v - 35) / 40
    }

    /// The palette index for a colour.
    pub(crate) fn get(r: u32, g: u32, b: u32) -> u32 {
        let qr = to_6_cube(r);
        let cr = Q2C[qr as usize];
        let qg = to_6_cube(g);
        let cg = Q2C[qg as usize];
        let qb = to_6_cube(b);
        let cb = Q2C[qb as usize];

        if cr == r && cg == g && cb == b {
            return 16 + 36 * qr + 6 * qg + qb;
        }

        let grey_avg = (r + g + b) / 3;
        let grey_idx = if grey_avg > 238 {
            23
        } else {
            grey_avg.saturating_sub(3) / 10
        };
        let grey = 8 + 10 * grey_idx;

        if sqdist(grey, grey, grey, r, g, b) < sqdist(cr, cg, cb, r, g, b) {
            232 + grey_idx
        } else {
            16 + 36 * qr + 6 * qg + qb
        }
    }

    /// The 256-index to 16-colour table, copied from Bun.
    const TABLE_256: [u8; 256] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 4, 4, 4, 12, 12, 2, 6, 4, 4, 12,
        12, 2, 2, 6, 4, 12, 12, 2, 2, 2, 6, 12, 12, 10, 10, 10, 10, 14, 12, 10, 10, 10, 10, 10, 14,
        1, 5, 4, 4, 12, 12, 3, 8, 4, 4, 12, 12, 2, 2, 6, 4, 12, 12, 2, 2, 2, 6, 12, 12, 10, 10, 10,
        10, 14, 12, 10, 10, 10, 10, 10, 14, 1, 1, 5, 4, 12, 12, 1, 1, 5, 4, 12, 12, 3, 3, 8, 4, 12,
        12, 2, 2, 2, 6, 12, 12, 10, 10, 10, 10, 14, 12, 10, 10, 10, 10, 10, 14, 1, 1, 1, 5, 12, 12,
        1, 1, 1, 5, 12, 12, 1, 1, 1, 5, 12, 12, 3, 3, 3, 7, 12, 12, 10, 10, 10, 10, 14, 12, 10, 10,
        10, 10, 10, 14, 9, 9, 9, 9, 13, 12, 9, 9, 9, 9, 13, 12, 9, 9, 9, 9, 13, 12, 9, 9, 9, 9, 13,
        12, 11, 11, 11, 11, 7, 12, 10, 10, 10, 10, 10, 14, 9, 9, 9, 9, 9, 13, 9, 9, 9, 9, 9, 13, 9,
        9, 9, 9, 9, 13, 9, 9, 9, 9, 9, 13, 9, 9, 9, 9, 9, 13, 11, 11, 11, 11, 11, 15, 0, 0, 0, 0,
        0, 0, 8, 8, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15,
    ];

    /// The 16-colour index for a colour.
    pub(crate) fn get16(r: u32, g: u32, b: u32) -> u8 {
        TABLE_256[(get(r, g, b) & 0xff) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgba(red: u8, green: u8, blue: u8, alpha: u8) -> Rgba {
        Rgba {
            red,
            green,
            blue,
            alpha,
        }
    }

    #[test]
    fn the_ansi_tables_reproduce_buns_measured_indices() {
        // Every value here is a recorded `Bun.color(hex, 'ansi-256')` result.
        assert_eq!(
            ansi256::get(255, 0, 0),
            196,
            "red is the 196th palette entry"
        );
        assert_eq!(ansi256::get(0, 0, 255), 21);
        assert_eq!(ansi256::get(0x12, 0x34, 0x56), 23);
        assert_eq!(ansi256::get(255, 255, 255), 231);
        assert_eq!(ansi256::get(0x80, 0x80, 0x80), 244);
    }

    #[test]
    fn the_16_colour_table_reproduces_buns_measured_sgr() {
        // `Bun.color('red','ansi-16') === '\\u{1b}[91m'` is index 9.
        assert_eq!(ansi256::get16(255, 0, 0), 9);
        assert_eq!(ansi256::get16(0, 0, 0), 0);
        assert_eq!(ansi256::get16(255, 255, 255), 15);
        assert_eq!(ansi256::get16(0x12, 0x34, 0x56), 6);
    }

    #[test]
    fn named_colours_parse_and_stay_case_sensitive() {
        assert_eq!(parse_css("red"), Some(rgba(255, 0, 0, 255)));
        assert_eq!(parse_css("rebeccapurple"), Some(rgba(102, 51, 153, 255)));
        assert_eq!(parse_css("transparent"), Some(rgba(0, 0, 0, 0)));
        // Measured: `RED` and ` Red ` are both `null`, so a name is not trimmed
        // or lowercased.
        assert_eq!(parse_css("RED"), None);
        assert_eq!(parse_css(" Red "), None);
        assert_eq!(parse_css("boguscolor"), None);
        assert_eq!(parse_css(""), None);
    }

    #[test]
    fn the_bg_suffix_is_stripped_from_a_name_only() {
        assert_eq!(parse_css("red:bg"), Some(rgba(255, 0, 0, 255)));
        assert_eq!(parse_css("red:fg"), Some(rgba(255, 0, 0, 255)));
        // `bogus:bg` is `null` on Bun: the suffix is parsed off and `bogus` is
        // then an unknown colour.
        assert_eq!(parse_css("bogus:bg"), None);
    }

    #[test]
    fn every_hex_form_parses() {
        assert_eq!(parse_css("#f00"), Some(rgba(255, 0, 0, 255)));
        assert_eq!(parse_css("#ff0000"), Some(rgba(255, 0, 0, 255)));
        assert_eq!(parse_css("#ff000080"), Some(rgba(255, 0, 0, 0x80)));
        assert_eq!(parse_css("#123456"), Some(rgba(0x12, 0x34, 0x56, 255)));
        assert_eq!(parse_css("#abc"), Some(rgba(0xaa, 0xbb, 0xcc, 255)));
        assert_eq!(parse_css("#abcd"), Some(rgba(0xaa, 0xbb, 0xcc, 0xdd)));
        assert_eq!(parse_css("#12345"), None);
        assert_eq!(parse_css("#gggggg"), None);
    }

    #[test]
    fn rgb_accepts_both_syntaxes_and_percentages() {
        assert_eq!(parse_css("rgb(255,0,0)"), Some(rgba(255, 0, 0, 255)));
        assert_eq!(parse_css("rgb(255 0 0)"), Some(rgba(255, 0, 0, 255)));
        // Measured: `#800000`, i.e. 50% of 255 rounded.
        assert_eq!(parse_css("rgb(50%,0%,0%)"), Some(rgba(128, 0, 0, 255)));
        assert_eq!(parse_css("rgba(255,0,0,0.5)"), Some(rgba(255, 0, 0, 128)));
        assert_eq!(parse_css("rgb(255 0 0 / 50%)"), Some(rgba(255, 0, 0, 128)));
    }

    #[test]
    fn hsl_round_trips_to_the_measured_hex() {
        assert_eq!(parse_css("hsl(0,100%,50%)"), Some(rgba(255, 0, 0, 255)));
        assert_eq!(parse_css("hsl(120,100%,25%)"), Some(rgba(0, 128, 0, 255)));
        assert_eq!(
            parse_css("hsl(210,65%,20%)"),
            Some(rgba(0x12, 0x33, 0x54, 255))
        );
        assert_eq!(parse_css("hsl(0,100%,50%,)"), None);
    }

    #[test]
    fn the_css_printer_reproduces_buns_measured_output() {
        // The measured table from §6.2 plus the wider sweep.
        let cases: &[(&str, &str)] = &[
            ("red", "red"),
            ("#ff0000", "red"),
            ("#f00", "red"),
            ("blue", "#00f"),
            ("green", "green"),
            ("cyan", "#0ff"),
            ("magenta", "#f0f"),
            ("yellow", "#ff0"),
            ("black", "#000"),
            ("white", "#fff"),
            ("grey", "gray"),
            ("rgb(1,2,3)", "#010203"),
            ("#123456", "#123456"),
            ("#aabbcc", "#abc"),
            ("#aabbccdd", "#abcd"),
            ("transparent", "#0000"),
            ("#ff000080", "#ff000080"),
        ];
        for (input, expected) in cases {
            let color = parse_css(input).unwrap_or_else(|| panic!("{input} must parse"));
            assert_eq!(&to_css(color), expected, "{input}");
        }
    }

    #[test]
    fn the_hsl_and_lab_printers_reproduce_the_measured_values() {
        let red = rgba(255, 0, 0, 255);
        assert_eq!(
            rgba_to_hsl(red),
            ("0".to_string(), "100".to_string(), "50".to_string())
        );
        let teal = rgba(0x12, 0x34, 0x56, 255);
        let (h, s, l) = rgba_to_hsl(teal);
        assert_eq!(h, "210", "hue must match Bun's measured 210");
        // Bun reports `hsl(210, 65.38462%, 20.392157%)`.
        assert!(s.starts_with("65.384"), "{s}");
        assert!(l.starts_with("20.392"), "{l}");

        let (lab_l, lab_a, lab_b) = rgba_to_lab(red);
        assert!(lab_l.starts_with("54.290"), "{lab_l}");
        assert!(lab_a.starts_with("80.80"), "{lab_a}");
        assert!(lab_b.starts_with("69.89"), "{lab_b}");
    }

    #[test]
    fn a_number_is_rrggbb_and_a_wide_number_carries_alpha() {
        assert_eq!(
            rgba_from_number(0xff0000 as f64),
            Some(rgba(255, 0, 0, 255))
        );
        assert_eq!(
            rgba_from_number(0x123456 as f64),
            Some(rgba(0x12, 0x34, 0x56, 255))
        );
        // Measured: `color(-1, 'hex')` is `"#ffffff"`, the truncation of -1.
        assert_eq!(rgba_from_number(-1.0), Some(rgba(255, 255, 255, 255)));
    }

    #[test]
    fn the_format_list_is_the_message_order() {
        // The error message is built by walking this list, so its order is what
        // users see. The first and last entries are measured.
        assert_eq!(FORMATS.first().copied(), Some("[r,g,b,a]"));
        assert_eq!(FORMATS.last().copied(), Some("rgba"));
        assert_eq!(
            FORMATS.len(),
            24,
            "Bun's message lists 23 spellings and 4 aliases"
        );
    }

    #[test]
    fn every_format_spelling_resolves() {
        for spelling in FORMATS {
            assert!(
                Format::parse(spelling).is_some(),
                "{spelling} is listed in the message but does not resolve"
            );
        }
        assert_eq!(Format::parse("bogus"), None);
    }
}
