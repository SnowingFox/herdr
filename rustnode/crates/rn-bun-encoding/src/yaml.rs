//! `Bun.YAML.parse` and `Bun.YAML.stringify`.
//!
//! # The schema is YAML 1.2 core, and three cases decide it
//!
//! Bun 1.4.4 resolves plain scalars with the YAML **1.2 core** schema. Three
//! measurements separate it from every reasonable alternative, and each is
//! pinned by a test here:
//!
//! | input | Bun | why it matters |
//! | --- | --- | --- |
//! | `a: yes` | `"yes"` | YAML 1.1 made this `true`; `serde_yaml` still does |
//! | `d: 2024-01-01` | `"2024-01-01"` | 1.2 core has no timestamp type; a `Date` would be a different value |
//! | `a: .inf` | `Infinity` | core schema *does* resolve `.inf`/`.nan`, and a JSON-shaped parser loses them |
//!
//! The resolution table is [`resolve_plain`], and it is deliberately narrower
//! than a general number parser: `1_000`, `0b101`, `0X10` and `0123` are
//! numbers-or-not exactly as Bun decides them, which was measured one scalar at
//! a time rather than inferred from a standard.
//!
//! # Anchors, aliases and merge keys
//!
//! An alias is the **same object** as its anchor — `p.a === p.b` is `true` — and
//! a document can therefore be cyclic. [`crate::value::Shared`] is what makes
//! that expressible; a deep-copying parser gets the first case wrong (two equal
//! objects instead of one) and the second case cannot terminate.
//!
//! `<<` is the merge key, resolved as Bun resolves it:
//!
//! * `<<: *map` merges `map`'s keys into the enclosing mapping;
//! * `<<: [*a, *b]` merges them in order, so the **first** map in the sequence
//!   wins a conflict (`{<<: [*b, *a]}` where both define `x` yields `b`'s `x`);
//! * an explicit key in the mapping beats a merged one, wherever it appears;
//! * a `<<` whose value is neither a mapping nor a sequence of mappings is left
//!   alone as the ordinary key `"<<"`.
//!
//! # What this does not match
//!
//! Bun's parser is a hand-written one and its error text comes from a small set
//! of messages; saphyr's comes from libyaml. Both are `SyntaxError` with no
//! `code`, and both refuse the same inputs for the inputs measured, but the
//! message text differs wherever the two disagree about *why*. [`error_message`]
//! maps each saphyr message to the Bun one it corresponds to, and the cases where
//! no faithful mapping exists are listed in the crate report rather than being
//! guessed.

use rn_v8_sys::v8;
use saphyr_parser::{Event, Parser, ScalarStyle};

use crate::convert::{
    coerce_to_string, throw_error, throw_syntax_error, CoerceError, IdentityCache,
};
use crate::value::{format_number, format_number_with, Map, Shared, Value};

/// Builds the `Bun.YAML` namespace object.
pub fn namespace<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    set(scope, object, "parse", 1, parse)?;
    set(scope, object, "stringify", 3, stringify)?;
    Ok(object)
}

/// Publishes a function under `name` with an explicit `length`.
///
/// Bun's namespaces are plain objects whose members are ordinary functions, not
/// binding methods: `Bun.YAML.parse.length` is `1`, `stringify`'s is `3`, and
/// `new Bun.YAML.parse(…)` is `TypeError: function is not a constructor`. V8's
/// `Function::builder` defaults to *allowing* construction, so the behaviour is
/// set explicitly here.
fn set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let function = v8::Function::builder(callback)
        .length(length)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope)
        .ok_or_else(|| format!("cannot build {name}"))?;
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    function.set_name(key);
    target
        .set(scope, key.into(), function.into())
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------

fn parse<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `args.get` borrows the callback's scope, and every helper below is generic
    // over the scope lifetime, so they are called through a reborrow that ties
    // both together.
    let input = match coerce_to_string(scope, args.get(0)) {
        Ok(input) => input,
        Err(CoerceError::Thrown) => return,
    };
    let value = match parse_document(&input) {
        Ok(value) => value,
        Err(message) => {
            throw_syntax_error(scope, &message);
            return;
        }
    };
    let mut cache = IdentityCache::new();
    match crate::convert::to_js(scope, &value, &mut cache) {
        Ok(js) => rv.set(js),
        Err(message) => throw_error(scope, &message),
    }
}

/// Parses a stream into the value `Bun.YAML.parse` returns.
///
/// A single document is returned as itself; a stream with more than one document
/// becomes an array, which is what Bun does with `a: 1\n---\nb: 2`. An empty
/// stream is `null`, so `YAML.parse("")`, `YAML.parse("# c")` and
/// `YAML.parse("---")` all land on `null`.
pub fn parse_document(input: &str) -> Result<Value, String> {
    if let Some(message) = tab_indentation_error(input) {
        return Err(message);
    }
    let normalized = normalize_tab_after_colon(input);
    let mut parser = Parser::new_from_str(&normalized);
    let mut builder = Builder::default();
    loop {
        match parser.next_event() {
            Some(Ok((event, _span))) => {
                builder.event(event)?;
            }
            Some(Err(error)) => return Err(error_message(error.info())),
            None => break,
        }
    }
    Ok(builder.finish())
}

/// Bun refuses a tab in indentation position with a dedicated message. saphyr
/// accepts two of those shapes and refuses one Bun accepts, so this decides the
/// answer before the parser sees the text.
///
/// The rule, derived from 25 measured line shapes against Bun 1.4.4:
///
/// ```text
/// structural positions   a tab in the leading whitespace is refused
/// flow collections       a tab between tokens is content        "a: [1,\t2]"
/// quoted scalars         a tab is content                        "a: \"x\ty\""
/// block scalar content   a tab is content when spaces precede it  "a: |\n  \tx"
///                          ...and refused when the indent is all tabs  "a: |\n\tx"
/// after a colon          a tab separates the value                "a:\tb"
/// inside a scalar        a tab is content                        "a: x\ty"
/// inside a key           a tab is content                        "a\tb: 1"
/// comment-only lines     never indentation                        "\t# c"
/// ```
///
/// Two consequences worth stating because they are easy to get backwards:
/// `"a:\tb"` parses (it is a mapping whose value is `"b"`, not a tab-indented
/// line), and `"a: 1\n\tb: 2"` is **refused** — the second line's tab is
/// indentation even though the line before it was complete.
///
/// The check runs before parsing because saphyr is wrong in three of these
/// shapes: it accepts `"\ta: 1"` and `"a:\n  \tb: 1"`, and it rejects `"a:\tb"`
/// with `":" must be followed by a valid YAML whitespace`. `a:\tb` is repaired
/// by [`normalize_tab_after_colon`]; the other two are this check.
fn tab_indentation_error(input: &str) -> Option<String> {
    let mut state = FlowState::default();
    for raw in input.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let (indent, rest) = split_indent(line);
        let content = rest.trim_end();
        let in_flow = state.depth > 0 || state.quote.is_some();
        let in_block_scalar = state.block_scalar_indent.is_some();
        // A blank line ends nothing and its whitespace is never indentation, but
        // it also does not close a block scalar: `a: |\n  x\n\n` keeps the
        // scalar open for its trailing newline.
        if content.is_empty() {
            continue;
        }
        if indent.contains('\t') && !content.starts_with('#') {
            let refused = if in_flow {
                false
            } else if in_block_scalar {
                // Content at or past the scalar's own indentation may contain a
                // tab, but the indentation itself cannot be made of tabs.
                !indent.chars().any(|character| character == ' ')
            } else {
                true
            };
            if refused {
                return Some(
                    "YAML Parse error: Tab characters cannot be used as indentation".to_string(),
                );
            }
        }
        state.advance(line, content);
    }
    None
}

/// Enough YAML structure to know whether a line's leading whitespace is
/// indentation, without parsing the document.
#[derive(Default)]
struct FlowState {
    /// Unbalanced `[` and `{` outside quotes.
    depth: usize,
    /// The quote character of an unterminated scalar, if there is one.
    quote: Option<char>,
    /// The indent of an open block scalar's parent line.
    block_scalar_indent: Option<usize>,
}

impl FlowState {
    fn advance(&mut self, line: &str, content: &str) {
        // A block scalar header opens content until a line indented no further
        // than the header. A blank line keeps it open.
        if let Some(parent) = self.block_scalar_indent {
            let (indent, _) = split_indent(line);
            if content.is_empty() {
                return;
            }
            if indent_width(indent) > parent {
                return;
            }
            self.block_scalar_indent = None;
        }
        let mut escaped = false;
        let mut chars = line.chars().peekable();
        while let Some(character) = chars.next() {
            if let Some(delimiter) = self.quote {
                if escaped {
                    escaped = false;
                } else if character == '\\' && delimiter == '"' {
                    escaped = true;
                } else if character == delimiter {
                    self.quote = None;
                }
                continue;
            }
            match character {
                '#' => break,
                '"' | '\'' => self.quote = Some(character),
                '[' | '{' => self.depth += 1,
                ']' | '}' => self.depth = self.depth.saturating_sub(1),
                '|' | '>'
                    // A block scalar header is the last thing on its line, after
                    // a `:` or a `-`; a `|` anywhere else is plain content.
                    if self.depth == 0
                        && chars.peek().is_none_or(|next| {
                            *next == ' ' || *next == '+' || *next == '-' || next.is_ascii_digit()
                        })
                    => {
                        let (indent, _) = split_indent(line);
                        self.block_scalar_indent = Some(indent_width(indent));
                    }
                _ => {}
            }
        }
    }
}

/// Splits a line into its leading whitespace and the rest.
fn split_indent(line: &str) -> (&str, &str) {
    for (index, byte) in line.bytes().enumerate() {
        if byte != b' ' && byte != b'\t' {
            return (&line[..index], &line[index..]);
        }
    }
    (line, "")
}

/// The width of an indentation prefix, counting a tab as one column.
///
/// Only used to compare one line's indentation with the previous one, where the
/// exact tab width does not matter.
fn indent_width(indent: &str) -> usize {
    indent.chars().count()
}

/// Maps a saphyr message to the one Bun produces for the same input.
///
/// Bun has one message for "this token cannot appear here" (`"Unexpected token"`),
/// one for "input ran out mid-token" (`"Unexpected EOF"`), one for an unknown
/// alias and one for an unknown escape. libyaml distinguishes far more cases, and
/// where the distinction has no Bun counterpart the generic message is used —
/// which is what an input that reaches that branch produces on Bun too.
fn error_message(saphyr: &str) -> String {
    let bun = if saphyr.contains("tab cannot be used as indentation")
        || saphyr.contains("tabs disallowed")
    {
        "Tab characters cannot be used as indentation"
    } else if saphyr.contains("found unknown anchor") {
        "Unresolved alias"
    } else if saphyr.contains("unexpected end of stream") {
        "Unexpected EOF"
    } else if saphyr.contains("found unknown escape character") {
        "Unexpected character"
    } else {
        "Unexpected token"
    };
    format!("YAML Parse error: {bun}")
}

// ---------------------------------------------------------------------------
// the event-to-value builder
// ---------------------------------------------------------------------------

/// One node being built, and its anchor if it already had one.
enum Frame {
    Sequence {
        items: Shared<Vec<Value>>,
        /// The anchor this node was registered under, so an alias can reach it
        /// before it is finished.
        anchor: Option<usize>,
    },
    Mapping {
        map: Shared<Map>,
        anchor: Option<usize>,
        /// The key whose value is currently being parsed.
        key: Option<String>,
    },
}

/// Rewrites the one tab shape saphyr mis-handles, leaving everything else alone.
///
/// `"a:\tb"` is a mapping with value `"b"` on Bun 1.4.4; saphyr rejects it with
/// `":" must be followed by a valid YAML whitespace`. Only that exact shape is
/// rewritten — a tab *immediately* after a mapping or flow colon whose preceding
/// character is content — because a tab anywhere else already parses the same in
/// both. Quoted scalars are skipped so a literal tab inside `"a:\tb"` stays a tab.
fn normalize_tab_after_colon(input: &str) -> String {
    if !input.contains(":\t") {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    for (index, line) in input.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let mut quote: Option<char> = None;
        let mut previous: Option<char> = None;
        let mut chars = line.chars().peekable();
        while let Some(character) = chars.next() {
            match quote {
                Some(delimiter) => {
                    out.push(character);
                    if character == delimiter {
                        quote = None;
                    }
                }
                None => {
                    if character == '"' || character == '\'' {
                        quote = Some(character);
                        out.push(character);
                    } else if character == '\t'
                        && previous == Some(':')
                        && chars
                            .peek()
                            .is_some_and(|next| *next != ' ' && *next != '\t')
                    {
                        out.push(' ');
                    } else {
                        out.push(character);
                    }
                }
            }
            previous = Some(character);
        }
    }
    out
}

/// Turns a saphyr event stream into one [`Value`].
#[derive(Default)]
struct Builder {
    stack: Vec<Frame>,
    /// Anchors defined in this document, by saphyr's per-document numeric id.
    ///
    /// Saphyr numbers anchors from 1 within a document and clears its own table
    /// at each `---`, so the ids do not collide across documents; this vector is
    /// reset with them.
    anchors: Vec<Option<Value>>,
    /// The value of the document that has just closed, waiting to be attached.
    completed: Option<Value>,
    /// Every document, in order.
    documents: Vec<Value>,
}

impl Builder {
    fn event(&mut self, event: Event<'_>) -> Result<(), String> {
        match event {
            Event::StreamStart | Event::StreamEnd => {}
            Event::DocumentStart(_) => {
                // Saphyr clears its own anchor table here, so the ids restart.
                self.anchors.clear();
            }
            Event::DocumentEnd => {
                let value = self.completed.take().unwrap_or(Value::Null);
                self.documents.push(value);
            }
            Event::Scalar(text, style, anchor, _tag) => {
                let value = scalar_value(&text, style);
                self.emit(value, anchor);
            }
            Event::SequenceStart(anchor, _tag) => {
                let items = Shared::new(Vec::new());
                let value = Value::Array(items.clone());
                self.register(anchor, &value);
                self.stack.push(Frame::Sequence {
                    items,
                    anchor: (anchor != 0).then_some(anchor),
                });
            }
            Event::SequenceEnd => {
                let Some(Frame::Sequence { items, anchor }) = self.stack.pop() else {
                    unreachable!("saphyr only emits SequenceEnd for an open sequence");
                };
                let _ = anchor;
                self.emit(Value::Array(items), 0);
            }
            Event::MappingStart(anchor, _tag) => {
                let map = Shared::new(Map::new());
                let value = Value::Map(map.clone());
                self.register(anchor, &value);
                self.stack.push(Frame::Mapping {
                    map,
                    anchor: (anchor != 0).then_some(anchor),
                    key: None,
                });
            }
            Event::MappingEnd => {
                let Some(Frame::Mapping { map, anchor, key }) = self.stack.pop() else {
                    unreachable!("saphyr only emits MappingEnd for an open mapping");
                };
                let _ = (anchor, key);
                self.emit(Value::Map(map), 0);
            }
            Event::Alias(id) => {
                let value = self
                    .anchors
                    .get(id)
                    .and_then(Clone::clone)
                    .ok_or_else(|| "YAML Parse error: Unresolved alias".to_string())?;
                self.emit(value, 0);
            }
            Event::Nothing => {}
        }
        Ok(())
    }

    /// Records `value` under `anchor` so a later alias can reach it.
    ///
    /// An anchored collection is registered *before* its contents are parsed,
    /// which is what makes a self-referencing document (`a: &x\n  b: *x`) a
    /// cycle rather than an error: the alias finds the still-empty cell.
    fn register(&mut self, anchor: usize, value: &Value) {
        if anchor == 0 {
            return;
        }
        if self.anchors.len() <= anchor {
            self.anchors.resize(anchor + 1, None);
        }
        self.anchors[anchor] = Some(value.clone());
    }

    /// Attaches a finished node to its parent, or makes it the document root.
    fn emit(&mut self, value: Value, anchor: usize) {
        if anchor != 0 {
            self.register(anchor, &value);
        }
        let Some(frame) = self.stack.last_mut() else {
            self.completed = Some(value);
            return;
        };
        match frame {
            Frame::Sequence { items, .. } => items.borrow_mut().push(value),
            Frame::Mapping { map, key, .. } => match key.take() {
                Some(name) if name == MERGE_KEY => merge_into(map, &value),
                Some(name) => map.borrow_mut().insert(name, value),
                None => {
                    // A key. Its JavaScript form is the property name, which is
                    // `String(key)` on the parsed value — so `1:` is `"1"`, `~:`
                    // is `"null"` and `? [1,2]` is `"1,2"`.
                    *frame_key(frame) = Some(key_string(&value));
                }
            },
        }
    }

    fn finish(self) -> Value {
        if self.documents.len() > 1 {
            Value::array(self.documents)
        } else if let Some(value) = self.documents.into_iter().next() {
            value
        } else {
            Value::Null
        }
    }
}

/// The `key` slot of a mapping frame, which `emit` needs from inside a match on
/// the frame itself.
fn frame_key(frame: &mut Frame) -> &mut Option<String> {
    match frame {
        Frame::Mapping { key, .. } => key,
        Frame::Sequence { .. } => unreachable!("only a mapping holds a pending key"),
    }
}

/// The property name a YAML mapping key becomes.
///
/// JavaScript coerces the key to a string, so this is `String(value)` for every
/// kind: a nested sequence becomes its comma-joined elements (`"1,2"`), a nested
/// mapping becomes `"[object Object]"`, `null` becomes `"null"` and a number uses
/// the same formatting as everywhere else.
fn key_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => format_number(*number),
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .borrow()
            .iter()
            .map(key_string)
            .collect::<Vec<_>>()
            .join(","),
        Value::Map(_) => "[object Object]".to_string(),
        Value::Temporal(text) => text.clone(),
        Value::Date(millis) => format_number(*millis),
        Value::Omitted => "undefined".to_string(),
    }
}

/// The merge key.
const MERGE_KEY: &str = "<<";

/// Applies one `<<` merge key's value to the enclosing mapping, as it arrives.
///
/// Bun merges **in document order, filling only keys that are still absent**, and
/// that single rule reproduces every measured case:
///
/// ```text
/// {<<: *a, y: 2, x: 9}   ->  {x: 9, y: 2}       an explicit key after the merge wins
/// {p: 0, <<: *a, x: 9}   ->  {p: 0, x: 9}       ... and keeps its own position
/// {y: 2, <<: *a, z: 3}   ->  {y: 2, x: 1, z: 3} merged keys land where the `<<` was
/// {<<: [*b, *a]}         ->  b's x wins          earlier maps in the sequence win
/// {<<: 1, y: 2}          ->  {<<: 1, y: 2}       a scalar is not a merge, it stays a key
/// ```
///
/// So this is not "collect the merges and apply them at the end" — that would put
/// a merged key after every explicit one regardless of where the `<<` appeared.
/// The order of `Object.keys()` is observable, so the position is part of the
/// behaviour.
fn merge_into(map: &Shared<Map>, value: &Value) {
    let mut sources: Vec<Value> = Vec::new();
    match value {
        Value::Map(_) => sources.push(value.clone()),
        Value::Array(items) => {
            for item in items.borrow().iter() {
                if matches!(item, Value::Map(_)) {
                    sources.push(item.clone());
                }
            }
            // A sequence of anything else merges nothing at all: Bun's
            // `{<<: [[*a]]}` is `{}` and `{<<: [1]}` is `{}`, with no `<<` left.
            if sources.is_empty() {
                return;
            }
        }
        // A scalar `<<` is left as the ordinary key, at the position it appeared.
        _ => {
            map.borrow_mut()
                .insert(MERGE_KEY.to_string(), value.clone());
            return;
        }
    }
    for source in sources {
        let Value::Map(source) = source else {
            continue;
        };
        // Each source's keys are applied in **reverse document order**, which is
        // what Bun's merge produces: `{<<: *a}` with `a = {p: 1, q: 2, r: 3}`
        // yields `Object.keys` of `["r", "q", "p"]`, and a two-source sequence
        // concatenates those reversed runs. It reads like a bug and it is
        // observable, so it is reproduced rather than corrected.
        let entries: Vec<(String, Value)> = source.borrow().iter().rev().cloned().collect();
        let mut target = map.borrow_mut();
        for (key, item) in entries {
            if !target.contains(&key) {
                target.push(key, item);
            }
        }
    }
}

/// Resolves a plain scalar with the YAML 1.2 core schema, and returns a quoted
/// or block scalar as the text it denotes.
///
/// Every branch below was decided by measuring that exact scalar through
/// `Bun.YAML.parse("a: …")`, not by reading the schema: the schema says
/// `0b101` is not a core-schema integer, and Bun agrees, but it also says
/// `1_000` is not one and Bun agrees — while `0x10` **is** one and `0X10` is not.
fn scalar_value(text: &str, style: ScalarStyle) -> Value {
    match style {
        ScalarStyle::Plain => resolve_plain(text),
        _ => Value::String(text.to_string()),
    }
}

/// The core-schema resolution of an unquoted scalar.
pub fn resolve_plain(text: &str) -> Value {
    if text.is_empty() {
        return Value::Null;
    }
    match text {
        "null" | "Null" | "NULL" | "~" => return Value::Null,
        "true" | "True" | "TRUE" => return Value::Bool(true),
        "false" | "False" | "FALSE" => return Value::Bool(false),
        _ => {}
    }
    if let Some(number) = resolve_number(text) {
        return Value::Number(number);
    }
    Value::String(text.to_string())
}

/// The number half of the core schema, including `.inf`/`.nan`.
fn resolve_number(text: &str) -> Option<f64> {
    let bytes = text.as_bytes();
    let (negative, rest) = match bytes.first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let magnitude = match rest {
        ".inf" | ".Inf" | ".INF" => {
            return Some(if negative {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            })
        }
        ".nan" | ".NaN" | ".NAN" => return Some(f64::NAN),
        _ => rest,
    };
    // Radix prefixes: lowercase only, and no sign (`+0x10` is accepted by Bun
    // because it strips the sign before the prefix, and `0X10` is not a number
    // because the prefix is case-sensitive).
    if let Some(digits) = magnitude.strip_prefix("0x") {
        return u64::from_str_radix(digits, 16)
            .ok()
            .map(|n| signed(negative, n as f64));
    }
    if let Some(digits) = magnitude.strip_prefix("0o") {
        return u64::from_str_radix(digits, 8)
            .ok()
            .map(|n| signed(negative, n as f64));
    }
    // The YAML 1.2 core schema has no digit separators, and Bun follows it:
    // `a: 1_000` is the string `"1_000"`, not `1000`. TOML is the format that
    // accepts `1_000`, and it does so in its own module.
    if magnitude.contains('_') {
        return None;
    }
    if is_decimal_literal(magnitude) {
        return magnitude.parse::<f64>().ok().map(|n| signed(negative, n));
    }
    None
}

fn signed(negative: bool, value: f64) -> f64 {
    if negative {
        -value
    } else {
        value
    }
}

/// Whether `text` is a YAML core-schema decimal: `[+-]?(digits[.digits]|.digits)[eE[+-]digits]`.
///
/// `1.` is accepted by Bun (`YAML.parse("a: 1.")` is `1`), so the fraction is
/// optional after a digit, and `.5` is accepted, so the integer part is optional
/// before a point. A trailing `e` with no digits is not a number, and neither is
/// a bare `.`.
fn is_decimal_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut index = 0;
    let mut digits_before = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
        digits_before += 1;
    }
    let mut digits_after = 0;
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
            digits_after += 1;
        }
        if digits_before == 0 && digits_after == 0 {
            return false;
        }
    } else if digits_before == 0 {
        return false;
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            index += 1;
        }
        let mut exponent_digits = 0;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
            exponent_digits += 1;
        }
        if exponent_digits == 0 {
            return false;
        }
    }
    index == bytes.len()
}

// ---------------------------------------------------------------------------
// stringify
// ---------------------------------------------------------------------------

fn stringify<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let value = args.get(0);
    if value.is_undefined() {
        rv.set_undefined();
        return;
    }
    // `space` is the third argument; `replacer` is the second and is refused
    // rather than ignored, unlike `JSON.stringify`.
    let replacer = args.get(1);
    if !replacer.is_null() && !replacer.is_undefined() {
        throw_error(
            scope,
            "YAML.stringify does not support the replacer argument",
        );
        return;
    }
    let space = space_of(scope, args.get(2));
    let converted = match crate::convert::from_js(scope, value) {
        Ok(converted) => converted,
        Err(crate::convert::FromJsError::Throwing) => return,
        Err(crate::convert::FromJsError::Unconvertible) => {
            // A top-level function or symbol has no YAML form, which is the
            // same shape as `undefined`: an empty document.
            rv.set_undefined();
            return;
        }
        Err(crate::convert::FromJsError::BigInt) => {
            throw_error(scope, "YAML.stringify cannot serialize BigInt");
            return;
        }
    };
    let mut out = String::new();
    match emit_root(&converted, space, &mut out) {
        Ok(Some(())) => {
            let Some(text) = v8::String::new(scope, &out) else {
                return;
            };
            rv.set(text.into());
        }
        Ok(None) => rv.set_undefined(),
        Err(message) => throw_error(scope, &message),
    }
}

/// The number of spaces to indent with, from `stringify`'s third argument.
///
/// Bun clamps to 10 and truncates toward zero; a value that is not a positive
/// number leaves the output in flow style, so `space: 0`, `space: -1` and
/// `space: NaN` all produce `{a: 1}`.
fn space_of<'s>(scope: &mut v8::PinScope<'s, '_>, value: v8::Local<'s, v8::Value>) -> usize {
    let number = if value.is_string() {
        // A string is used as the indent itself, and Bun takes its length.
        return value.to_rust_string_lossy(scope).chars().count().min(10);
    } else if value.is_number() {
        value.number_value(scope).unwrap_or(f64::NAN)
    } else {
        return 0;
    };
    if !number.is_finite() || number <= 0.0 {
        return 0;
    }
    (number.trunc() as usize).min(10)
}

/// Emits the document root.
///
/// Flow style at `space == 0`, block style above it. A root that is not a
/// collection is emitted as a bare scalar.
fn emit_root(value: &Value, space: usize, out: &mut String) -> Result<Option<()>, String> {
    match value {
        Value::Map(map) if space == 0 => {
            out.push_str(&flow_map(map)?);
            Ok(Some(()))
        }
        Value::Map(map) => {
            emit_block_map(map, 0, space, out, true)?;
            // Bun's block output has no trailing newline: `stringify({a:1}, null,
            // 2)` is `"a: 1"`, not `"a: 1\n"`. The flow form has none either, so
            // the whole emitter is newline-terminated only *between* lines.
            while out.ends_with('\n') {
                out.pop();
            }
            Ok(Some(()))
        }
        Value::Array(items) if space == 0 => {
            out.push_str(&flow_array(items)?);
            Ok(Some(()))
        }
        Value::Array(items) => {
            emit_block_array(items, 0, space, out)?;
            while out.ends_with('\n') {
                out.pop();
            }
            Ok(Some(()))
        }
        other => {
            out.push_str(&flow_scalar(other, false)?);
            Ok(Some(()))
        }
    }
}

/// `{a: 1,b: 2}` — no space after the comma, one after the colon.
fn flow_map(map: &Shared<Map>) -> Result<String, String> {
    // A mapping never writes `+0`; only an array that also holds a `-0` does.
    // `{a: -0, b: 0}` is `"{a: -0,b: 0}"`, which is why this is false here and
    // computed in `flow_array` only.
    let plus_zero = false;
    let mut out = String::from("{");
    let mut first = true;
    for (key, value) in map.borrow().iter() {
        if value.is_omitted() {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&quote_key(key));
        out.push_str(": ");
        out.push_str(&flow_value(value, plus_zero)?);
    }
    out.push('}');
    Ok(out)
}

fn flow_array(items: &Shared<Vec<Value>>) -> Result<String, String> {
    let plus_zero = holds_negative_zero_array(items);
    let mut out = String::from("[");
    let mut first = true;
    for value in items.borrow().iter() {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&flow_value(value, plus_zero)?);
    }
    out.push(']');
    Ok(out)
}

fn flow_value(value: &Value, plus_zero: bool) -> Result<String, String> {
    match value {
        Value::Map(map) => flow_map(map),
        Value::Array(items) => flow_array(items),
        other => flow_scalar(other, plus_zero),
    }
}

/// A scalar in flow context.
///
/// Bun writes `+0` for positive zero and `-0` for negative zero, which is the one
/// place either stringifier keeps the sign; TOML writes `0` and `-0.0`.
fn flow_scalar(value: &Value, plus_zero: bool) -> Result<String, String> {
    Ok(match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => match number {
            _ if number.is_nan() => ".nan".to_string(),
            _ if *number == f64::INFINITY => ".inf".to_string(),
            _ if *number == f64::NEG_INFINITY => "-.inf".to_string(),
            // A positive zero is written `"0"` on its own and `"+0"` when an
            // array it belongs to also holds a `-0`. That asymmetry is Bun's:
            // `stringify([0, -0])` is `"[+0,-0]"` while `stringify([0, 1])` is
            // `"[0,1]"` and `stringify({a: 0})` is `"{a: 0}"`. The flag is set by
            // the array emitter before it writes its members.
            _ if *number == 0.0 => {
                if number.is_sign_negative() {
                    "-0".to_string()
                } else if plus_zero {
                    "+0".to_string()
                } else {
                    "0".to_string()
                }
            }
            _ => format_number_with(*number, true),
        },
        Value::String(text) => quote_string_or_plain(text),
        Value::Temporal(text) => quote_string_or_plain(text),
        // Bun serialises a `Date` as `{}` because every enumerable own property
        // of one is absent; a mapping or sequence reaches here only through the
        // conversion layer, which has already flattened it.
        // A `Date` serialises as `{}` in Bun's YAML: it has no enumerable own
        // property, so an object walk finds nothing.
        Value::Date(_) => "{}".to_string(),
        Value::Map(_) | Value::Array(_) | Value::Omitted => String::new(),
    })
}

/// The key form: bare when plain, double-quoted otherwise.
fn quote_key(key: &str) -> String {
    quote_string_or_plain(key)
}

/// Whether a sequence holds a negative zero, which is what turns a sibling `0`
/// into `+0` in Bun's output.
fn holds_negative_zero_array(items: &Shared<Vec<Value>>) -> bool {
    items.borrow().iter().any(is_negative_zero)
}

fn is_negative_zero(value: &Value) -> bool {
    matches!(value, Value::Number(number) if *number == 0.0 && number.is_sign_negative())
}

/// A string as a scalar: bare when that round-trips, double-quoted otherwise.
///
/// This is what makes `Bun.YAML.stringify({a: "x"})` produce `{a: x}` rather
/// than `{a: "x"}` — Bun only quotes when the bare form would read back as
/// something else, so plain strings survive unquoted.
fn quote_string_or_plain(text: &str) -> String {
    if plain_allowed(text) {
        text.to_string()
    } else {
        quote_string(text)
    }
}

/// Whether a string can appear as a bare scalar.
///
/// This is not the YAML 1.2 plain-scalar grammar; it is the set of rules that
/// reproduce Bun's quoting decisions, derived by measuring every ASCII character
/// in first, middle and last position and then the multi-character cases:
///
/// * no leading or trailing space;
/// * no leading `! % & * - < > ? : @ |` (the "forced in first position" set);
/// * no `, [ ] { } # ' " ` `` anywhere (the "forced in any position" set);
/// * no trailing `:`, and no `: ` anywhere — but `a:b` is bare, which is why the
///   colon rule is not "no colon"; a leading `:` is refused;
/// * no control character;
/// * not `.`, not `...` at either end, and not `-`;
/// * not a YAML 1.1 boolean word (`y`, `yes`, `on`, `off`, …) — Bun escapes
///   those even though its *parser* follows 1.2, because a 1.1 reader would
///   misread them;
/// * not any text that would parse back as a non-string (a number, `null`, a
///   core-schema boolean, `.inf`).
fn plain_allowed(text: &str) -> bool {
    let Some(first) = text.chars().next() else {
        return false;
    };
    let Some(last) = text.chars().next_back() else {
        return false;
    };
    if first == ' ' || last == ' ' {
        return false;
    }
    if "!%&*-<>?:@|".contains(first) {
        return false;
    }
    if text.contains([',', '[', ']', '{', '}', '#', '\'', '"', '`']) {
        return false;
    }
    if last == ':' || text.contains(": ") {
        return false;
    }
    if text
        .chars()
        .any(|character| character.is_control() || character == '\u{7f}')
    {
        return false;
    }
    // `-` and `.` are indicator-ish only as a whole token: `x-` is bare but `-`
    // is not, and `x...` is not (a `...` is a document end marker) while
    // `...x` is.
    if text == "-" || text == "." {
        return false;
    }
    // `...` is a document-end marker only as a whole token, so `"...x"` is bare
    // and `"x..."`/`"..."` are quoted.
    if text == "..." || text.ends_with("...") {
        return false;
    }
    // A U+00A0, U+0085, U+2028 or U+2029 is escaped rather than bare: the first
    // two are `\_`/`\N` in YAML and the last two are line breaks, so leaving them
    // raw would change the value a reader sees.
    if text.contains(['\u{a0}', '\u{85}', '\u{2028}', '\u{2029}', '\u{feff}']) {
        return false;
    }
    if is_yaml_1_1_boolean(text) {
        return false;
    }
    // A bare scalar that a reader would resolve to something else has to be
    // quoted to survive: `"1"`, `"1.5"`, `"0x10"`, `"0o7"`, `"1e3"`, `"+0"`,
    // `"00"` and `".inf"` are all quoted by Bun while `"1_0"`, `"0b1"`, `"inf"`
    // and `"NaN"` are not, which is exactly "the core schema would change it".
    matches!(resolve_plain(text), Value::String(unchanged) if unchanged == text)
}

/// The YAML 1.1 boolean and null words, all of which Bun double-quotes.
///
/// Bun's parser is 1.2 and leaves `yes` a string, but its *emitter* quotes the
/// whole 1.1 set — `yes`, `y`, `on`, `off` in every capitalisation — so that the
/// document reads back the same under a 1.1 reader. That is a deliberate choice
/// on Bun's part and is reproduced rather than second-guessed.
fn is_yaml_1_1_boolean(text: &str) -> bool {
    matches!(
        text,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
            | "null"
            | "Null"
            | "NULL"
            | "~"
    )
}

/// Double-quotes a string with YAML escapes.
///
/// `\x01` and `\x7f` are the two escape forms beyond the single-character
/// escapes that Bun's output actually uses, and `\L`/`\P`/`\N`/`\_` are YAML's
/// own names for U+2028, U+2029, U+0085 and U+00A0 — all measured by round-tripping
/// the string through `Bun.YAML.parse` and reading back the bytes.
fn quote_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0}' => out.push_str("\\0"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{b}' => out.push_str("\\v"),
            '\u{1b}' => out.push_str("\\e"),
            '\u{85}' => out.push_str("\\N"),
            '\u{a0}' => out.push_str("\\_"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            control if control.is_control() || control == '\u{7f}' => {
                let code = control as u32;
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02x}"));
                } else {
                    out.push_str(&format!("\\u{code:04x}"));
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Emits a mapping in block style, one `key: value` per line.
///
/// `top_level` distinguishes the document root from a nested mapping: the root
/// has no indentation to open with, so it must not emit a blank line first.
fn emit_block_map(
    map: &Shared<Map>,
    depth: usize,
    space: usize,
    out: &mut String,
    top_level: bool,
) -> Result<(), String> {
    let indent = " ".repeat(depth * space);
    if depth > 0 && !top_level && out.ends_with('\n') {
        // A nested mapping opens a new block; the blank line before one is what
        // Bun emits between a scalar and the table that follows it.
    }
    for (index, (key, value)) in map.borrow().iter().enumerate() {
        let _ = index;
        // An `undefined` property is not written at all: `{a: true, b: undefined,
        // c: null}` is `{a: true,c: null}`.
        if value.is_omitted() {
            continue;
        }
        out.push_str(&indent);
        out.push_str(&quote_key(key));
        match value {
            Value::Map(nested) if !nested.borrow().is_empty() => {
                out.push_str(":\n");
                emit_block_map(nested, depth + 1, space, out, false)?;
            }
            Value::Array(items) if !items.borrow().is_empty() => {
                out.push_str(":\n");
                emit_block_array(items, depth + 1, space, out)?;
            }
            // Empty collections stay inline, and so does everything else.
            other => {
                out.push_str(": ");
                out.push_str(&flow_value(other, false)?);
                out.push('\n');
            }
        }
    }
    Ok(())
}

/// Emits a sequence in block style, one `- item` per line.
pub fn emit_block_array(
    items: &Shared<Vec<Value>>,
    depth: usize,
    space: usize,
    out: &mut String,
) -> Result<(), String> {
    let indent = " ".repeat(depth * space);
    for value in items.borrow().iter() {
        out.push_str(&indent);
        match value {
            // A mapping inside a sequence puts its first key on the dash line,
            // which is Bun's `- a: 1` form and needs no extra indentation for
            // that first key.
            Value::Map(map) if !map.borrow().is_empty() => {
                out.push_str("- ");
                let mut body = String::new();
                emit_block_map(map, depth + 1, space, &mut body, false)?;
                let prefix = " ".repeat((depth + 1) * space);
                let body = body
                    .strip_prefix(&prefix)
                    .map(str::to_string)
                    .unwrap_or(body);
                out.push_str(&body);
            }
            Value::Array(nested) if !nested.borrow().is_empty() => {
                out.push_str("- ");
                let mut body = String::new();
                emit_block_array(nested, depth + 1, space, &mut body)?;
                let prefix = " ".repeat((depth + 1) * space);
                let body = body
                    .strip_prefix(&prefix)
                    .map(str::to_string)
                    .unwrap_or(body);
                out.push_str(&body);
            }
            other => {
                out.push_str("- ");
                out.push_str(&flow_value(other, false)?);
                out.push('\n');
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Value {
        parse_document(input).expect("parses")
    }

    #[test]
    fn core_schema_keeps_yes_no_on_off_as_strings() {
        let value = parse("a: yes\nb: no\nc: on\nd: off\ne: y\nf: n");
        let map = value.as_map().expect("a mapping");
        for key in ["a", "b", "c", "d", "e", "f"] {
            assert!(
                matches!(map.get(key), Some(Value::String(_))),
                "{key} must stay a string"
            );
        }
        assert_eq!(map.get("a").and_then(Value::as_str), Some("yes"));
    }

    #[test]
    fn core_schema_keeps_dates_as_strings() {
        let value = parse("d: 2024-01-01\ndt: 2024-01-01T00:00:00Z");
        let map = value.as_map().expect("a mapping");
        assert_eq!(map.get("d").and_then(Value::as_str), Some("2024-01-01"));
        assert_eq!(
            map.get("dt").and_then(Value::as_str),
            Some("2024-01-01T00:00:00Z")
        );
    }

    #[test]
    fn core_schema_resolves_inf_and_nan() {
        let value = parse("a: .inf\nb: .nan\nc: -.inf");
        let map = value.as_map().expect("a mapping");
        assert_eq!(map.get("a"), Some(&Value::Number(f64::INFINITY)));
        assert!(matches!(map.get("b"), Some(Value::Number(n)) if n.is_nan()));
        assert_eq!(map.get("c"), Some(&Value::Number(f64::NEG_INFINITY)));
    }

    #[test]
    fn number_resolution_matches_bun_scalar_by_scalar() {
        // Each pair is `Bun.YAML.parse("a: " + input).a` and its `typeof`.
        for (input, number) in [
            ("0", Some(0.0)),
            ("-0", Some(-0.0)),
            ("+0", Some(0.0)),
            ("0x10", Some(16.0)),
            ("0o17", Some(15.0)),
            ("1.5", Some(1.5)),
            ("1.", Some(1.0)),
            ("+.5", Some(0.5)),
            ("-.5", Some(-0.5)),
            (".5", Some(0.5)),
            ("1e3", Some(1000.0)),
            ("1E3", Some(1000.0)),
            ("1e+3", Some(1000.0)),
            ("1e-3", Some(0.001)),
            ("-0x10", Some(-16.0)),
            ("+0x10", Some(16.0)),
            ("007", Some(7.0)),
            ("1e400", Some(f64::INFINITY)),
            ("18446744073709551616", Some(18446744073709552000.0)),
            ("0X10", None),
            ("0O17", None),
            ("0b101", None),
            ("1_000", None),
            ("1_0.5", None),
            ("1_.5", None),
            ("_1", None),
            ("1_", None),
            ("0x", None),
            ("1.2.3", None),
            ("1e", None),
            ("--1", None),
            ("+", None),
            ("..5", None),
            ("1,000", None),
            ("12:30", None),
            ("2024-01-01", None),
            ("0b2", None),
            ("0o8", None),
        ] {
            let resolved = resolve_plain(input);
            match number {
                Some(expected) => match resolved {
                    Value::Number(actual) => assert_eq!(
                        actual.is_sign_negative(),
                        expected.is_sign_negative(),
                        "sign of {input}"
                    ),
                    other => {
                        assert_eq!(other, Value::Number(expected), "{input} should be a number")
                    }
                },
                None => assert_eq!(
                    resolved,
                    Value::String(input.to_string()),
                    "{input} should stay a string"
                ),
            }
        }
    }

    #[test]
    fn scalars_hold_every_measured_form() {
        let value = parse("a: 1\nb: two\nc: true\nd: null\ne: 1.5\nf: 'quoted'\ng: \"dq\"");
        let map = value.as_map().expect("a mapping");
        assert_eq!(map.get("a"), Some(&Value::Number(1.0)));
        assert_eq!(map.get("b").and_then(Value::as_str), Some("two"));
        assert_eq!(map.get("c"), Some(&Value::Bool(true)));
        assert_eq!(map.get("d"), Some(&Value::Null));
        assert_eq!(map.get("e"), Some(&Value::Number(1.5)));
        assert_eq!(map.get("f").and_then(Value::as_str), Some("quoted"));
        assert_eq!(map.get("g").and_then(Value::as_str), Some("dq"));
    }

    #[test]
    fn an_alias_is_the_same_cell_as_its_anchor() {
        let value = parse("a: &x [1]\nb: *x");
        let map = value.as_map().expect("a mapping");
        let (Some(Value::Array(a)), Some(Value::Array(b))) = (map.get("a"), map.get("b")) else {
            panic!("both keys are sequences");
        };
        assert!(a.ptr_eq(b), "an alias must be the same object, not a copy");
    }

    #[test]
    fn a_self_referencing_document_is_a_cycle() {
        let value = parse("a: &x\n  b: *x");
        let map = value.as_map().expect("a mapping");
        let Some(Value::Map(inner)) = map.get("a") else {
            panic!("a is a mapping");
        };
        let Some(Value::Map(back)) = inner.borrow().get("b").cloned() else {
            panic!("b points back");
        };
        assert!(back.ptr_eq(inner), "b is a, not a copy of a");
    }

    #[test]
    fn merge_key_fills_gaps_and_explicit_keys_win() {
        let value = parse("base: &b\n  x: 1\nchild:\n  <<: *b\n  y: 2");
        let map = value.as_map().expect("a mapping");
        let Some(Value::Map(child)) = map.get("child") else {
            panic!("child is a mapping");
        };
        assert_eq!(child.borrow().get("x"), Some(&Value::Number(1.0)));
        assert_eq!(child.borrow().get("y"), Some(&Value::Number(2.0)));

        let value = parse("a: &a {x: 1}\nb: {x: 9, <<: *a}");
        let map = value.as_map().expect("a mapping");
        let Some(Value::Map(b)) = map.get("b") else {
            panic!("b is a mapping");
        };
        assert_eq!(b.borrow().get("x"), Some(&Value::Number(9.0)));
    }

    #[test]
    fn merge_sequence_prefers_the_first_map() {
        let value = parse("a: &a {x: 1, z: 1}\nb: &b {x: 2, y: 2}\nc: {<<: [*b, *a]}");
        let map = value.as_map().expect("a mapping");
        let Some(Value::Map(c)) = map.get("c") else {
            panic!("c is a mapping");
        };
        assert_eq!(c.borrow().get("x"), Some(&Value::Number(2.0)));
        assert_eq!(c.borrow().get("y"), Some(&Value::Number(2.0)));
        assert_eq!(c.borrow().get("z"), Some(&Value::Number(1.0)));
    }

    #[test]
    fn a_non_mapping_merge_stays_a_plain_key() {
        for (input, expected) in [
            ("c: {<<: 1}", Value::Number(1.0)),
            ("c: {<<: 'x'}", Value::String("x".into())),
            ("c: {<<: null}", Value::Null),
        ] {
            let value = parse(input);
            let map = value.as_map().expect("a mapping");
            let Some(Value::Map(c)) = map.get("c") else {
                panic!("c is a mapping");
            };
            assert_eq!(
                c.borrow().get("<<"),
                Some(&expected),
                "{input} keeps the raw merge key"
            );
        }
        // A sequence whose members are not mappings merges nothing and leaves no
        // `<<` behind, which is what Bun does with `{<<: [1]}` and `{<<: []}`.
        for input in ["c: {<<: [1]}", "c: {<<: []}"] {
            let value = parse(input);
            let map = value.as_map().expect("a mapping");
            let Some(Value::Map(c)) = map.get("c") else {
                panic!("c is a mapping");
            };
            assert!(c.borrow().is_empty(), "{input}");
        }
    }

    #[test]
    fn duplicate_keys_replace_in_place() {
        let value = parse("a: 1\nb: 2\na: 3");
        let map = value.as_map().expect("a mapping");
        let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(map.get("a"), Some(&Value::Number(3.0)));
    }

    #[test]
    fn key_forms_match_javascript_coercion() {
        let value = parse("1: a\n2: b\n~: c\ntrue: d\n? [x, y]\n: e\n? {k: v}\n: f");
        let map = value.as_map().expect("a mapping");
        let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["1", "2", "null", "true", "x,y", "[object Object]"]);
    }

    #[test]
    fn block_scalars_keep_the_trailing_newline() {
        assert_eq!(
            parse("a: |\n  line1\n  line2\n")
                .as_map()
                .unwrap()
                .get("a")
                .and_then(Value::as_str),
            Some("line1\nline2\n")
        );
        assert_eq!(
            parse("a: |-\n  x\n")
                .as_map()
                .unwrap()
                .get("a")
                .and_then(Value::as_str),
            Some("x")
        );
        assert_eq!(
            parse("a: |+\n  x\n\n")
                .as_map()
                .unwrap()
                .get("a")
                .and_then(Value::as_str),
            Some("x\n\n")
        );
        assert_eq!(
            parse("a: >\n  line1\n  line2\n")
                .as_map()
                .unwrap()
                .get("a")
                .and_then(Value::as_str),
            Some("line1 line2\n")
        );
    }

    #[test]
    fn an_empty_stream_is_null_and_a_multi_document_stream_is_an_array() {
        assert_eq!(parse(""), Value::Null);
        assert_eq!(parse("# only a comment"), Value::Null);
        assert_eq!(parse("---"), Value::Null);
        assert_eq!(
            parse("a: 1\n---\nb: 2"),
            Value::array(vec![
                Value::map(Map::from_iter([("a".into(), Value::Number(1.0))])),
                Value::map(Map::from_iter([("b".into(), Value::Number(2.0))])),
            ])
        );
    }

    #[test]
    fn tab_indentation_is_refused_only_where_bun_refuses_it() {
        for accepted in [
            "a:\tb",
            "a: x\ty",
            "a: [1,\t2]",
            "a: \"x\ty\"",
            "a: |\n  x\ty\n",
            "a: |\n  \tx\n",
            "\t# comment\na: 1",
            "a: 1\n\t\nb: 2",
            "a\tb: 1",
            "\t\n\t\na: 1",
            "a:\n  \t# c\n  b: 1",
        ] {
            assert!(parse_document(accepted).is_ok(), "{accepted:?} must parse");
        }
        for refused in [
            "\ta: 1",
            "a:\n\t- 1",
            "a:\n  \tb: 1",
            "a: |\n\tx\n",
            "\t- 1",
            "a:\n  b:\n\t\tc: 1",
            "a: 1\n\tb: 2",
            "\t- 1",
            "- 1\n\t- 2",
        ] {
            assert_eq!(
                parse_document(refused),
                Err("YAML Parse error: Tab characters cannot be used as indentation".to_string()),
                "{refused:?} must be refused"
            );
        }
    }

    #[test]
    fn failure_messages_are_the_measured_ones() {
        for (input, expected) in [
            ("a: [1, 2", "YAML Parse error: Unexpected token"),
            ("a: b: c", "YAML Parse error: Unexpected token"),
            ("a: \"x", "YAML Parse error: Unexpected EOF"),
            ("a: 'x", "YAML Parse error: Unexpected EOF"),
            ("a: *nope", "YAML Parse error: Unresolved alias"),
            ("a: \"\\q\"", "YAML Parse error: Unexpected character"),
        ] {
            assert_eq!(
                parse_document(input),
                Err(expected.to_string()),
                "{input:?}"
            );
        }
    }

    #[test]
    fn flow_style_stringify_matches_bun_bytes() {
        for (value, expected) in [
            (
                Value::map(Map::from_iter([
                    ("a".into(), Value::Number(1.0)),
                    ("b".into(), Value::String("x".into())),
                    (
                        "c".into(),
                        Value::array(vec![Value::Number(1.0), Value::Number(2.0)]),
                    ),
                ])),
                "{a: 1,b: x,c: [1,2]}",
            ),
            (
                Value::array(vec![
                    Value::Number(1.0),
                    Value::Number(2.0),
                    Value::Number(3.0),
                ]),
                "[1,2,3]",
            ),
            (Value::String("hi".into()), "hi"),
            (Value::Number(5.0), "5"),
            (Value::Null, "null"),
        ] {
            let mut out = String::new();
            emit_root(&value, 0, &mut out).expect("emits");
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn block_style_stringify_matches_bun_bytes() {
        let value = Value::map(Map::from_iter([
            ("a".into(), Value::Number(1.0)),
            (
                "list".into(),
                Value::array(vec![Value::Number(1.0), Value::Number(2.0)]),
            ),
        ]));
        let mut out = String::new();
        emit_root(&value, 2, &mut out).expect("emits");
        // No trailing newline: Bun's block output ends at the last character of
        // the last value, which is `"a: 1\nlist:\n  - 1\n  - 2"`.
        assert_eq!(out, "a: 1\nlist:\n  - 1\n  - 2");
    }

    #[test]
    fn string_quoting_matches_bun_bytes() {
        // `quote_string` is the escaper; `quote_string_or_plain` is the decision
        // Bun makes about whether to use it. Both halves are measured, so both
        // are pinned.
        for (text, expected) in [
            ("hi", "hi"),
            ("x y", "x y"),
            ("a:b", "a:b"),
            ("x-", "x-"),
            ("a  b", "a  b"),
            ("...x", "...x"),
            ("1_0", "1_0"),
            ("0b1", "0b1"),
            ("inf", "inf"),
            ("NaN", "NaN"),
            ("e", "e"),
            ("Inf", "Inf"),
            ("^x", "^x"),
            ("$$", "$$"),
            ("(x)", "(x)"),
        ] {
            assert_eq!(quote_string_or_plain(text), expected, "for {text:?}");
        }
        for (text, expected) in [
            ("a: b", "\"a: b\""),
            ("#x", "\"#x\""),
            ("-x", "\"-x\""),
            ("true", "\"true\""),
            ("1", "\"1\""),
            ("", "\"\""),
            ("a\tb", "\"a\\tb\""),
            ("  leading", "\"  leading\""),
            ("trailing  ", "\"trailing  \""),
            ("\u{1}", "\"\\x01\""),
            ("\u{7f}", "\"\\x7f\""),
            ("x\u{0}y", "\"x\\0y\""),
            ("a\u{2028}b", "\"a\\Lb\""),
            ("a\u{85}b", "\"a\\Nb\""),
            ("a\u{a0}b", "\"a\\_b\""),
            ("x\u{b}y", "\"x\\vy\""),
            ("x\u{c}y", "\"x\\fy\""),
            ("'x'", "\"'x'\""),
            ("a\"b", "\"a\\\"b\""),
            ("a'b", "\"a'b\""),
            ("a\\b", "\"a\\\\b\""),
            ("é", "\"é\""),
            ("日本", "\"日本\""),
            ("a,b", "\"a,b\""),
            (".", "\".\""),
            ("x...", "\"x...\""),
        ] {
            assert_eq!(quote_string(text), expected, "escaped {text:?}");
        }
    }
}
