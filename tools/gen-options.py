#!/usr/bin/env python3
"""Generates `crates/rn-bind-options/src/table.rs` from Node's own sources.

    python3 tools/gen-options.py --node-src /path/to/node
    python3 tools/gen-options.py --node-src /path/to/node --check

The `options` namespace is almost entirely a 251-entry table: every
`AddOption(...)` call in `src/node_options.cc` becomes one `OptionInfo` with a
name, help text, type, `OptionEnvvarSettings`, namespace and the default value
taken from the field it binds in `src/node_options.h`. Hand-transcribing that
table would drift from Node silently, so it is extracted instead. The output is
committed, so a normal build needs no Node checkout.

`--check` regenerates into memory and diffs against the committed file; it
exits 1 when the table is stale. CI runs it when a Node source tree is
available.

What is extracted
-----------------
* `src/node_options.cc`: every `AddOption(...)` and `AddAlias(...)` call, in
  source order, with the constructor it appears in (which identifies the
  `Options` struct whose field it binds).
* `src/node_options.h`: each option struct's field declarations, giving the
  C++ type (which selects the `OptionType`) and the initializer (the default).
* `src/node_constants.h`: `DEFAULT_CIPHER_LIST_CORE`, the default of
  `--tls-cipher-list`, which is a macro rather than a literal.

C++ has no runtime reflection, so a preprocessor pass is unavoidable: options
live inside `#if` blocks. The macro configuration below describes one concrete
Node build and is deliberately explicit rather than "whatever this machine
has". Every entry states where its value comes from, so a reader can re-check
it instead of trusting it. The configuration is chosen to match Node's default
`./configure && make` on Linux x64, which is what rustnode targets.

Two counts are emitted, `SOURCE_ADD_OPTION_SITES` (raw textual occurrences) and
`PARSED_OPTION_COUNT` (entries that survived preprocessing). A unit test in the
crate asserts both equal `OPTIONS.len()`, so a parser regression that silently
drops a call fails the build instead of shipping a short table.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import sys
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Build configuration
# --------------------------------------------------------------------------
#
# Each macro mirrors what `./configure` produces for a default Linux x64 build
# of Node 28, which is the build rustnode reproduces. `src/node_options.cc`
# gates options on these, so they decide which options the table contains.
#
#   HAVE_OPENSSL=1              node.gypi, node_use_openssl defaults to true
#   HAVE_INSPECTOR=1            node.gypi, v8_enable_inspector defaults to 1
#   HAVE_SQLITE=1               node.gypi, node_use_sqlite defaults to true
#   HAVE_AMARO=1                node.gyp, node_use_amaro defaults to true
#   HAVE_FFI=1                  node.gyp, node_use_ffi defaults to false but
#                               configure_ffi() enables it on x64/arm64 with the
#                               bundled libffi (configure.py bundled_ffi_supported)
#   HAVE_DTLS=0                 configure.py: node_use_dtls is only set by the
#                               opt-in --experimental-dtls flag
#   NODE_HAVE_I18N_SUPPORT=1    default; only --without-intl clears it
#   NODE_HAVE_SMALL_ICU=0       only the small-icu configure option sets it
#   NODE_OPENSSL_CERT_STORE=0   only --openssl-use-def-ca-store sets it
#   OPENSSL_IS_BORINGSSL=0      Node links upstream OpenSSL (4.1.0), not BoringSSL
#   OPENSSL_NO_QUIC=0           the bundled OpenSSL configuration defines no
#                               OPENSSL_NO_* for QUIC, so the option keeps its
#                               boolean form; `node_use_quic` only decides
#                               whether the QUIC sources are compiled in
#   V8_ENABLE_SANDBOX=0         only --experimental-pointer-compression-shared-cage
#   DEBUG=0                     release build
#   NODE_WITHOUT_NODE_OPTIONS=0 only embedder/Android builds set it
#   V8_USE_PERFETTO=0           default; selects the .log trace file pattern
#
MACROS = {
    "NODE_WANT_INTERNALS": "1",
    "HAVE_OPENSSL": "1",
    "HAVE_INSPECTOR": "1",
    "HAVE_SQLITE": "1",
    "HAVE_AMARO": "1",
    "HAVE_FFI": "1",
    "HAVE_DTLS": "0",
    "NODE_HAVE_I18N_SUPPORT": "1",
    "NODE_HAVE_SMALL_ICU": "0",
    "NODE_OPENSSL_CERT_STORE": "0",
    "OPENSSL_IS_BORINGSSL": "0",
    "OPENSSL_NO_QUIC": "0",
    "V8_ENABLE_SANDBOX": "0",
    "DEBUG": "0",
    "NODE_WITHOUT_NODE_OPTIONS": "0",
    "V8_USE_PERFETTO": "0",
}

# `OptionType`, from `src/node_options.h`. The numbers are the values Node
# reports through `types` and through each option's `type`, so they are wire
# data, not an implementation detail.
OPTION_TYPES = {
    "kNoOp": 0,
    "kV8Option": 1,
    "kBoolean": 2,
    "kInteger": 3,
    "kUInteger": 4,
    "kString": 5,
    "kHostPort": 6,
    "kStringList": 7,
}

# `OptionEnvvarSettings`, from `src/node.h`.
ENV_SETTINGS = {"kAllowedInEnvvar": 0, "kDisallowedInEnvvar": 1}

# `OPTION_NAMESPACE_LIST`, from `src/node_options.h`: C++ enum name -> the
# string `namespace_id` the parser stores on the option.
NAMESPACES = {
    "OptionNamespaces::kNoNamespace": "",
    "OptionNamespaces::kBenchRunnerNamespace": "bench",
    "OptionNamespaces::kTestRunnerNamespace": "test",
    "OptionNamespaces::kWatchNamespace": "watch",
    "OptionNamespaces::kPermissionNamespace": "permission",
}

# C++ field type -> OptionType. `uint64_t Options::*` selects the kUInteger
# overload, `int64_t Options::*` kInteger, and so on; taking the type from the
# declaration keeps the two in step without hand-copying either.
FIELD_TYPES = {
    "bool": "kBoolean",
    "uint64_t": "kUInteger",
    "int64_t": "kInteger",
    "std::string": "kString",
    "std::vector<std::string>": "kStringList",
    "HostPort": "kHostPort",
}


# --------------------------------------------------------------------------
# Lexing: comments, string literals, call sites
# --------------------------------------------------------------------------

def strip_comments(src: str) -> str:
    """Replaces comments with whitespace, preserving offsets and newlines."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            i += 2
            out.append(" ")
        elif c in ('"', "'"):
            quote = c
            out.append(c)
            i += 1
            while i < n:
                out.append(src[i])
                if src[i] == "\\":
                    i += 1
                    if i < n:
                        out.append(src[i])
                elif src[i] == quote:
                    i += 1
                    break
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def split_top_level(body: str) -> list[str]:
    """Splits on commas that are not inside parentheses, braces or strings."""
    parts: list[str] = []
    depth = 0
    in_string = False
    escaped = False
    current = ""
    for c in body:
        if in_string:
            current += c
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
            current += c
            continue
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += c
    if current.strip():
        parts.append(current.strip())
    return parts


@dataclass
class CallSite:
    line: int
    offset: int
    arguments: list[str]


def call_sites(src: str, name: str) -> list[CallSite]:
    """Every `name(...)` invocation with its arguments split."""
    out: list[CallSite] = []
    i, n = 0, len(src)
    while True:
        j = src.find(name + "(", i)
        if j < 0:
            break
        if j > 0 and (src[j - 1].isalnum() or src[j - 1] == "_"):
            i = j + 1
            continue
        k = j + len(name) + 1
        depth = 1
        in_string = False
        escaped = False
        while k < n and depth > 0:
            c = src[k]
            if in_string:
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    in_string = False
            else:
                if c == '"':
                    in_string = True
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
            k += 1
        out.append(
            CallSite(
                line=src[:j].count("\n") + 1,
                offset=j,
                arguments=split_top_level(src[j + len(name) + 1 : k - 1]),
            )
        )
        i = k
    return out


class Preprocessor:
    """Cuts the source down to one build configuration.

    Only what `node_options.cc` and `node_options.h` actually use: `#if` /
    `#ifdef` / `#ifndef` / `#elif` / `#else` / `#endif` with `defined()`,
    identifiers, `!`, `&&`, `||` and parentheses, plus `#define` of an object
    macro. Function-like macros in a condition (`OPENSSL_VERSION_PREREQ(3, 4)`)
    are treated as 0: they belong to openssl version checks that never gate an
    option, and treating them as 0 keeps the modern branch.

    Inactive lines become empty instead of being deleted, so line numbers in a
    parse error keep matching the file on disk.
    """

    def __init__(self, macros: dict[str, str]):
        self.macros = dict(macros)

    def truth(self, name: str) -> bool:
        value = self.macros.get(name, "0")
        return value in ("1", "true")

    def evaluate(self, expression: str) -> bool:
        text = expression.strip()
        text = re.sub(
            r"defined\s*\(\s*([A-Za-z_]\w*)\s*\)",
            lambda m: "1" if self.truth(m.group(1)) else "0",
            text,
        )
        text = re.sub(
            r"defined\s+([A-Za-z_]\w*)",
            lambda m: "1" if self.truth(m.group(1)) else "0",
            text,
        )
        for name, value in self.macros.items():
            if value in ("true", "false", "0", "1"):
                text = re.sub(
                    r"\b" + name + r"\b", "1" if value in ("true", "1") else "0", text
                )
        text = re.sub(r"[A-Za-z_]\w*\s*\([^()]*\)", "0", text)
        text = re.sub(r"[A-Za-z_]\w*", lambda m: "1" if self.truth(m.group(0)) else "0", text)
        text = text.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
        try:
            return bool(eval(text, {"__builtins__": {}}, {}))  # noqa: S307 - digits and operators only
        except Exception as exc:  # pragma: no cover - a source change would trip this
            raise SystemExit(f"cannot evaluate #{'if'} {expression!r} as {text!r}: {exc}")

    def run(self, src: str) -> str:
        out: list[str] = []
        stack: list[list[bool]] = []
        active = True
        for line in src.split("\n"):
            directive = re.match(
                r"\s*#\s*(if|ifdef|ifndef|elif|else|endif|define|undef)\b(.*)", line
            )
            if not directive:
                out.append(line if active else "")
                continue
            kind, rest = directive.group(1), directive.group(2).strip()
            if kind in ("if", "ifdef", "ifndef"):
                if kind == "if":
                    condition = self.evaluate(rest)
                elif kind == "ifdef":
                    condition = self.truth(rest)
                else:
                    condition = not self.truth(rest)
                stack.append([active, condition])
                active = active and condition
            elif kind == "elif":
                parent, taken = stack[-1]
                condition = self.evaluate(rest)
                stack[-1] = [parent, taken or condition]
                active = parent and not taken and condition
            elif kind == "else":
                parent, taken = stack[-1]
                stack[-1] = [parent, True]
                active = parent and not taken
            elif kind == "endif":
                if not stack:
                    raise SystemExit("unbalanced #endif")
                active = stack.pop()[0]
            elif kind == "define" and active:
                definition = re.match(r"([A-Za-z_]\w*)(\([^)]*\))?\s*(.*)", rest)
                if definition and not definition.group(2):
                    self.macros[definition.group(1)] = definition.group(3).strip() or "1"
                # An object macro's body is kept in the output: callers look
                # for it by name (e.g. DEFAULT_CIPHER_LIST_CORE), and it can
                # never be mistaken for a call site.
                out.append(line)
                continue
            elif kind == "undef" and active:
                self.macros.pop(rest.split()[0], None)
            out.append("")
        if stack:
            raise SystemExit("unterminated #if block")
        return "\n".join(out)


# --------------------------------------------------------------------------
# C++ literals and constant expressions
# --------------------------------------------------------------------------

ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "\\": "\\",
    '"': '"',
    "'": "'",
    "?": "?",
}


def cpp_string(tokens: str) -> str:
    """Concatenates adjacent C++ string literals and decodes their escapes."""
    literals = re.findall(r'"((?:[^"\\]|\\.)*)"', tokens)
    if not literals:
        raise SystemExit(f"no string literal in {tokens!r}")
    out: list[str] = []
    for literal in literals:
        i = 0
        while i < len(literal):
            c = literal[i]
            if c != "\\":
                out.append(c)
                i += 1
                continue
            i += 1
            if i >= len(literal):
                raise SystemExit(f"dangling escape in {tokens!r}")
            escape = literal[i]
            if escape in ESCAPES:
                out.append(ESCAPES[escape])
                i += 1
            elif escape == "x":
                match = re.match(r"[0-9A-Fa-f]+", literal[i + 1 :])
                if not match:
                    raise SystemExit(f"bad \\x escape in {tokens!r}")
                out.append(chr(int(match.group(0), 16)))
                i += 1 + len(match.group(0))
            else:
                raise SystemExit(f"unsupported escape \\{escape} in {tokens!r}")
    return "".join(out)


class Expression:
    """Recursive-descent evaluator for the integer expressions in defaults.

    Only what the header's initializers use: decimal and hex literals,
    identifiers resolved through a constant table, parentheses, and `*`, `+`,
    `-`, `/`, `%`, `<<`, `>>`. Anything else raises, so an initializer the
    generator does not understand fails generation rather than defaulting to 0.
    """

    def __init__(self, text: str, constants: dict[str, int], where: str):
        self.tokens = re.findall(r"\d+[uUlL]*|0[xX][0-9A-Fa-f]+|[A-Za-z_]\w*|<<|>>|[()+\-*/%]", text)
        self.position = 0
        self.constants = constants
        self.where = where

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise SystemExit(f"{self.where}: unexpected end of expression")
        self.position += 1
        return token

    def parse(self) -> int:
        value = self.shift()
        if self.peek() is not None:
            raise SystemExit(f"{self.where}: trailing input at {self.peek()!r}")
        return value

    def shift(self) -> int:
        value = self.additive()
        while self.peek() in ("<<", ">>"):
            operator = self.take()
            rhs = self.additive()
            value = value << rhs if operator == "<<" else value >> rhs
        return value

    def additive(self) -> int:
        value = self.multiplicative()
        while self.peek() in ("+", "-"):
            operator = self.take()
            rhs = self.multiplicative()
            value = value + rhs if operator == "+" else value - rhs
        return value

    def multiplicative(self) -> int:
        value = self.unary()
        while self.peek() in ("*", "/", "%"):
            operator = self.take()
            rhs = self.unary()
            if operator == "*":
                value *= rhs
            elif operator == "/":
                if rhs == 0:
                    raise SystemExit(f"{self.where}: division by zero")
                value //= rhs
            else:
                if rhs == 0:
                    raise SystemExit(f"{self.where}: modulo by zero")
                value %= rhs
        return value

    def unary(self) -> int:
        token = self.take()
        if token == "(":
            value = self.shift()
            if self.take() != ")":
                raise SystemExit(f"{self.where}: missing ')'")
            return value
        if token in ("+", "-"):
            value = self.unary()
            return value if token == "+" else -value
        if re.fullmatch(r"\d+[uUlL]*", token):
            return int(re.sub(r"[uUlL]+$", "", token))
        if re.fullmatch(r"0[xX][0-9A-Fa-f]+", token):
            return int(token, 16)
        if token in self.constants:
            return self.constants[token]
        raise SystemExit(f"{self.where}: unknown identifier {token!r}")


def cpp_bool(text: str) -> bool:
    value = text.strip()
    if value in ("true", "1"):
        return True
    if value in ("false", "0"):
        return False
    raise SystemExit(f"expected a bool initializer, got {text!r}")


def expand_bool(text: str, macros: dict[str, str]) -> str:
    """Replaces the build macros a bool initializer may be written with.

    `DEFINE_BOOL_FIELD(experimental_bench) = EXPERIMENTALS_DEFAULT_VALUE;` and
    `= HAVE_FFI;` are the same configuration MACROS describes; resolving them
    here keeps the "true"/"false" spelling the rest of the generator assumes.
    The macros come from the preprocessor run, so a `#define` in the header is
    honoured without a second list to keep in step.
    """
    resolved = text.strip()
    known = dict(MACROS_CONSTANTS)
    for name, value in macros.items():
        if value in ("true", "false"):
            known[name] = 1 if value == "true" else 0
    for name, value in known.items():
        resolved = re.sub(r"\b" + name + r"\b", "true" if value else "false", resolved)
    return resolved


# --------------------------------------------------------------------------
# Structs from src/node_options.h
# --------------------------------------------------------------------------

@dataclass
class FieldInfo:
    name: str
    cpp_type: str
    initializer: str


@dataclass
class StructInfo:
    name: str
    fields: dict[str, FieldInfo] = field(default_factory=dict)
    constants: dict[str, int] = field(default_factory=dict)
    macros: dict[str, str] = field(default_factory=dict)


def class_body(src: str, name: str) -> str:
    match = re.search(r"(?:class|struct)\s+" + name + r"\b[^;{]*\{", src)
    if not match:
        raise SystemExit(f"could not find {name} in node_options.h")
    i = match.end() - 1
    depth = 0
    start = i
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                body = src[start + 1 : i]
                # `private:` usually introduces the child-options member, which
                # is not bound by any AddOption in this class.
                return body.split("private:")[0]
        i += 1
    raise SystemExit(f"unterminated body for {name}")


def parse_struct(src: str, name: str, macros: dict[str, str]) -> StructInfo:
    body = class_body(src, name)
    info = StructInfo(name=name)
    info.macros = dict(macros)

    for match in re.finditer(r"static\s+constexpr\s+(\w+)\s+(\w+)\s*=\s*([^;]+);", body):
        constants = dict(MACROS_CONSTANTS)
        info.constants[match.group(2)] = Expression(
            match.group(3), constants, f"{name}::{match.group(2)}"
        ).parse()

    # `enum { kDefaultInspectorPort = 9229 };` is the only anonymous enum in
    # these structs, and it holds a plain compile-time integer.
    for match in re.finditer(r"enum\s*\{([^}]*)\}", body):
        for entry in split_top_level(match.group(1)):
            pair = re.fullmatch(r"(\w+)\s*=\s*(.+)", entry)
            if not pair:
                continue
            constants = dict(MACROS_CONSTANTS)
            constants.update(info.constants)
            info.constants[pair.group(1)] = Expression(
                pair.group(2), constants, f"{name}::{pair.group(1)}"
            ).parse()

    for match in re.finditer(r"DEFINE_BOOL_FIELD\(\s*(\w+)\s*\)(?:\s*=\s*([^;]+))?;", body):
        info.fields[match.group(1)] = FieldInfo(
            name=match.group(1),
            cpp_type="bool",
            initializer=(match.group(2) or "false").strip(),
        )

    declaration = re.compile(
        r"^\s*(std::vector<std::string>|std::string|uint64_t|int64_t|bool|HostPort)"
        r"\s+(\w+)\s*(?:=\s*([^;]+)|\{([^;]*)\})?;",
        re.M,
    )
    for match in declaration.finditer(body):
        cpp_type, field_name, initializer, braces = match.groups()
        if field_name in info.fields:
            continue
        if braces is not None:
            info.fields[field_name] = FieldInfo(field_name, cpp_type, "{" + braces + "}")
        else:
            info.fields[field_name] = FieldInfo(field_name, cpp_type, (initializer or "").strip())

    return info


# Fields whose initializer is a build macro rather than a literal. The values
# are the same configuration described by MACROS above.
MACROS_CONSTANTS: dict[str, int] = {
    "true": 1,
    "false": 0,
    "HAVE_FFI": 1,
    "HAVE_SQLITE": 1,
    "HAVE_AMARO": 1,
    "HAVE_INSPECTOR": 1,
    "HAVE_OPENSSL": 1,
}


# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------

def parse_host_port(initializer: str, constants: dict[str, int], where: str) -> tuple[str, int]:
    match = re.fullmatch(r"\{\s*(\"(?:[^\"\\]|\\.)*\")\s*,\s*(.+?)\s*\}", initializer)
    if not match:
        raise SystemExit(f"{where}: cannot read HostPort initializer {initializer!r}")
    host = cpp_string(match.group(1))
    port = Expression(match.group(2), constants, where).parse()
    if not 0 <= port <= 0xFFFF:
        raise SystemExit(f"{where}: port {port} does not fit a uint16_t")
    return host, port


@dataclass
class Default:
    """The Rust spelling of one option's initial value."""

    kind: str  # "undef" | "bool" | "int" | "uint" | "str" | "list" | "host_port"
    value: object = None

    def render(self) -> str:
        if self.kind == "undef":
            return "DefaultValue::Undefined"
        if self.kind == "bool":
            return f"DefaultValue::Bool({'true' if self.value else 'false'})"
        if self.kind == "int":
            return f"DefaultValue::Int({self.value})"
        if self.kind == "uint":
            return f"DefaultValue::Uint({self.value})"
        if self.kind == "str":
            return f'DefaultValue::Str({rust_str(self.value)})'
        if self.kind == "list":
            items = ", ".join(rust_str(item) for item in self.value)
            return f"DefaultValue::List(&[{items}])"
        if self.kind == "host_port":
            host, port = self.value
            return f"DefaultValue::HostPort({rust_str(host)}, {port})"
        raise SystemExit(f"unknown default kind {self.kind}")


def rust_str(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    escaped = escaped.replace("\0", "\\0")
    return f'"{escaped}"'


DEFAULT_CIPHER_LIST_SYMBOL = "DEFAULT_CIPHER_LIST_CORE"


def splice_continuations(src: str) -> str:
    """Joins `\\`-continued logical lines, as translation phase 2 does.

    `DEFAULT_CIPHER_LIST_CORE` is written as a dozen adjacent string literals
    split across physical lines, and no other pass here needs to see them
    separately.
    """
    return re.sub(r"\\[ \t]*\n", "", src)


def read_cipher_list(node_src: str) -> str:
    """Resolves `DEFAULT_CIPHER_LIST_CORE` from `src/node_constants.h`.

    `--tls-cipher-list` defaults to that macro: either a configure override or
    a long concatenation of TLS suite names. The bundled OpenSSL is used, so
    the `NODE_OPENSSL_DEFAULT_CIPHER_LIST` branch is not taken.
    """
    path = os.path.join(node_src, "src", "node_constants.h")
    with open(path, encoding="utf-8") as handle:
        text = Preprocessor(MACROS).run(splice_continuations(strip_comments(handle.read())))
    match = re.search(r"#\s*define\s+" + DEFAULT_CIPHER_LIST_SYMBOL + r"\s+(.*)", text)
    if not match:
        raise SystemExit(f"{path}: {DEFAULT_CIPHER_LIST_SYMBOL} not found")
    return cpp_string(match.group(1))


def field_default(info: StructInfo, field_info: FieldInfo, cipher_list: str) -> Default:
    where = f"{info.name}::{field_info.name}"
    constants = dict(MACROS_CONSTANTS)
    constants.update(info.constants)
    cpp_type = field_info.cpp_type
    initializer = field_info.initializer

    if cpp_type == "bool":
        resolved = expand_bool(initializer, info.macros)
        # `DEFINE_BOOL_FIELD(verify_base_objects) = IS_DEBUG;` binds a
        # class-scope `static constexpr bool` rather than a literal or macro.
        if resolved in info.constants:
            return Default("bool", bool(info.constants[resolved]))
        return Default("bool", cpp_bool(resolved))
    if cpp_type in ("uint64_t", "int64_t"):
        value = Expression(initializer, constants, where).parse()
        if cpp_type == "uint64_t":
            if value < 0:
                raise SystemExit(f"{where}: negative default for an unsigned field")
            return Default("uint", value)
        return Default("int", value)
    if cpp_type == "std::string":
        if initializer == DEFAULT_CIPHER_LIST_SYMBOL:
            return Default("str", cipher_list)
        if not initializer:
            return Default("str", "")
        return Default("str", cpp_string(initializer))
    if cpp_type == "std::vector<std::string>":
        if initializer:
            raise SystemExit(f"{where}: non-empty vector default {initializer!r} is unsupported")
        return Default("list", [])
    if cpp_type == "HostPort":
        return Default("host_port", parse_host_port(initializer, constants, where))
    raise SystemExit(f"{where}: unsupported field type {cpp_type}")


# --------------------------------------------------------------------------
# Option and alias extraction
# --------------------------------------------------------------------------

PARSER_STRUCTS = {
    "DebugOptionsParser": "DebugOptions",
    "EnvironmentOptionsParser": "EnvironmentOptions",
    "PerIsolateOptionsParser": "PerIsolateOptions",
    "PerProcessOptionsParser": "PerProcessOptions",
}


@dataclass
class Option:
    name: str
    help_text: str
    option_type: str
    env_setting: str
    default_is_true: bool
    namespace: str
    default: Default
    source_line: int


@dataclass
class Alias:
    source: str
    targets: list[str]


def constructor_offsets(src: str) -> list[tuple[int, str]]:
    offsets: list[tuple[int, str]] = []
    pattern = r"(DebugOptionsParser|EnvironmentOptionsParser|PerIsolateOptionsParser|PerProcessOptionsParser)::\1\("
    for match in re.finditer(pattern, src):
        offsets.append((match.start(), PARSER_STRUCTS[match.group(1)]))
    return offsets


def struct_at(offsets: list[tuple[int, str]], offset: int) -> str:
    candidates = [name for start, name in offsets if start <= offset]
    if not candidates:
        raise SystemExit(f"offset {offset} is outside every options parser constructor")
    return candidates[-1]


def extract_options(
    src: str, structs: dict[str, StructInfo], cipher_list: str
) -> tuple[list[Option], list[Alias], int]:
    calls = call_sites(src, "AddOption")
    raw_sites = len(calls)
    offsets = constructor_offsets(src)
    options: list[Option] = []

    for call in calls:
        where = f"node_options.cc:{call.line}"
        arguments = call.arguments
        if len(arguments) < 3:
            raise SystemExit(f"{where}: AddOption with {len(arguments)} arguments")
        name = cpp_string(arguments[0])
        help_text = cpp_string(arguments[1]) if arguments[1] else ""
        target = arguments[2]
        struct_name = struct_at(offsets, call.offset)
        info = structs[struct_name]

        bool_field = re.fullmatch(r"BOOL_FIELD\(\s*(\w+)\s*\)", target)
        plain_field = re.fullmatch(r"&(\w+)::(\w+)", target)
        if bool_field:
            field_name = bool_field.group(1)
            field_struct = info
        elif plain_field:
            field_struct = structs.get(plain_field.group(1))
            if field_struct is None:
                raise SystemExit(f"{where}: unknown options struct {plain_field.group(1)}")
            field_name = plain_field.group(2)
        else:
            field_name = ""
            field_struct = None

        if target.startswith("NoOp"):
            option_type = "kNoOp"
        elif target.startswith("V8Option"):
            option_type = "kV8Option"
        elif field_struct is not None:
            declared = field_struct.fields.get(field_name)
            if declared is None:
                raise SystemExit(f"{where}: {field_struct.name} has no field {field_name}")
            if declared.cpp_type not in FIELD_TYPES:
                raise SystemExit(f"{where}: unsupported field type {declared.cpp_type}")
            option_type = FIELD_TYPES[declared.cpp_type]
            if bool_field and declared.cpp_type != "bool":
                raise SystemExit(f"{where}: BOOL_FIELD on a {declared.cpp_type} field")
        else:
            raise SystemExit(f"{where}: unrecognised AddOption target {target!r}")

        # The trailing arguments are positional per overload. Boolean options
        # take (env_setting, default_is_true, namespace_id); every other
        # overload takes (env_setting, namespace_id, strict).
        rest = []
        for argument in arguments[3:]:
            collapsed = " ".join(argument.split())
            # `AddOption("--experimental-ffi", ..., kAllowedInEnvvar, HAVE_FFI)`
            # passes a build macro where a bool is expected; resolve it first.
            collapsed = expand_bool(collapsed, MACROS)
            if collapsed in ("true", "false"):
                rest.append("true" if collapsed == "true" else "false")
            elif collapsed.startswith("OptionNamespaces::"):
                rest.append(collapsed)
            elif collapsed in ENV_SETTINGS:
                rest.append(collapsed)
            elif collapsed == "kStrictOptionParsing":
                rest.append("strict")
            else:
                raise SystemExit(f"{where}: unrecognised trailing argument {argument!r}")

        env_setting = "kDisallowedInEnvvar"  # the declared default
        default_is_true = False
        namespace = ""
        positional = [token for token in rest]
        if positional and positional[0] in ENV_SETTINGS:
            env_setting = positional.pop(0)
        if option_type == "kBoolean":
            if positional and positional[0] in ("true", "false"):
                default_is_true = positional.pop(0) == "true"
        if positional and positional[0].startswith("OptionNamespaces::"):
            namespace = NAMESPACES[positional.pop(0)]
        if positional and positional[0] == "strict":
            positional.pop(0)
        if positional:
            raise SystemExit(f"{where}: leftover arguments {positional}")

        if option_type in ("kNoOp", "kV8Option"):
            default = Default("undef")
        else:
            if field_struct is None:
                raise SystemExit(f"{where}: {option_type} without a field")
            default = field_default(field_struct, field_struct.fields[field_name], cipher_list)

        options.append(
            Option(
                name=name,
                help_text=help_text,
                option_type=option_type,
                env_setting=env_setting,
                default_is_true=default_is_true,
                namespace=namespace,
                default=default,
                source_line=call.line,
            )
        )

    aliases: list[Alias] = []
    for call in call_sites(src, "AddAlias"):
        where = f"node_options.cc:{call.line}"
        arguments = call.arguments
        if len(arguments) != 2:
            raise SystemExit(f"{where}: AddAlias with {len(arguments)} arguments")
        source = cpp_string(arguments[0])
        target = arguments[1].strip()
        if target.startswith("{"):
            inner = target[1:-1]
            targets = [cpp_string(part) for part in split_top_level(inner)]
        else:
            targets = [cpp_string(target)]
        aliases.append(Alias(source=source, targets=targets))

    return options, aliases, raw_sites


# --------------------------------------------------------------------------
# Rust output
# --------------------------------------------------------------------------

HEADER = """\
// Generated by tools/gen-options.py. Do not edit by hand.
//
// Node's option table, extracted from src/node_options.cc and
// src/node_options.h at the revision pinned in tools/node-pin.toml. Regenerate
// with:
//
//     python3 tools/gen-options.py --node-src /path/to/node
//
// The counts below are the guard against a silent parse failure: a generator
// change that drops a call makes `table_len_matches_source` fail rather than
// shipping a short table.
"""


def render(options: list[Option], aliases: list[Alias], raw_sites: int) -> str:
    out: list[str] = [HEADER]
    out.append("use crate::option::{AliasInfo, DefaultValue, OptionInfo, OptionNamespace};\n")
    out.append("/// `AddOption(` occurrences in `src/node_options.cc`.")
    out.append(f"pub const SOURCE_ADD_OPTION_SITES: usize = {raw_sites};\n")
    out.append("/// Options that survived the documented build configuration.")
    out.append(f"pub const PARSED_OPTION_COUNT: usize = {len(options)};\n")
    out.append("/// `AddAlias(` occurrences in `src/node_options.cc`.")
    out.append(f"pub const SOURCE_ADD_ALIAS_SITES: usize = {len(aliases)};\n")

    out.append("/// Every option `options_parser::_ppop_instance` registers, in source order.")
    out.append("#[rustfmt::skip]")
    out.append("pub static OPTIONS: &[OptionInfo] = &[")
    for option in options:
        namespace = {
            "": "OptionNamespace::None",
            "bench": "OptionNamespace::Bench",
            "test": "OptionNamespace::Test",
            "watch": "OptionNamespace::Watch",
            "permission": "OptionNamespace::Permission",
        }[option.namespace]
        out.append("    OptionInfo {")
        out.append(f"        name: {rust_str(option.name)},")
        out.append(f"        help_text: {rust_str(option.help_text)},")
        out.append(f"        kind: {OPTION_TYPES[option.option_type]},")
        out.append(f"        env_setting: {ENV_SETTINGS[option.env_setting]},")
        out.append(f"        default_is_true: {'true' if option.default_is_true else 'false'},")
        out.append(f"        namespace: {namespace},")
        out.append(f"        default: {option.default.render()},")
        out.append("    },")
    out.append("];\n")

    out.append("/// `AddAlias` expansions, in source order.")
    out.append("#[rustfmt::skip]")
    out.append("pub static ALIASES: &[AliasInfo] = &[")
    for alias in aliases:
        targets = ", ".join(rust_str(target) for target in alias.targets)
        out.append(
            "    AliasInfo { from: %s, to: &[%s] },"
            % (rust_str(alias.source), targets)
        )
    out.append("];\n")

    out.append("/// `OptionEnvvarSettings`, from `src/node.h`.")
    out.append("#[rustfmt::skip]")
    out.append("pub static ENV_SETTINGS: &[(&str, i32)] = &[")
    out.append('    ("kAllowedInEnvvar", 0),')
    out.append('    ("kDisallowedInEnvvar", 1),')
    out.append("];\n")

    out.append("/// `OptionType`, from `src/node_options.h`, in enum order.")
    out.append("#[rustfmt::skip]")
    out.append("pub static TYPES: &[(&str, i32)] = &[")
    for name, value in OPTION_TYPES.items():
        out.append(f'    ("{name}", {value}),')
    out.append("];\n")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def generate(node_src: str) -> str:
    options_cc = os.path.join(node_src, "src", "node_options.cc")
    options_h = os.path.join(node_src, "src", "node_options.h")
    for path in (options_cc, options_h):
        if not os.path.isfile(path):
            raise SystemExit(f"missing {path}; pass --node-src <node checkout>")

    with open(options_cc, encoding="utf-8") as handle:
        source = Preprocessor(MACROS).run(strip_comments(handle.read()))
    header_preprocessor = Preprocessor(MACROS)
    with open(options_h, encoding="utf-8") as handle:
        header = header_preprocessor.run(strip_comments(handle.read()))

    structs = {
        name: parse_struct(header, name, header_preprocessor.macros)
        for name in PARSER_STRUCTS.values()
    }
    cipher_list = read_cipher_list(node_src)
    options, aliases, raw_sites = extract_options(source, structs, cipher_list)

    names = [option.name for option in options]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SystemExit(f"duplicate option names: {duplicates}")
    for option in options:
        if option.option_type not in OPTION_TYPES:
            raise SystemExit(f"{option.name}: unknown type {option.option_type}")
    for option in options:
        if not option.name:
            raise SystemExit("an option with an empty name cannot be reached")

    return render(options, aliases, raw_sites)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--node-src", default=os.environ.get("NODE_SRC", "/tmp/node"))
    parser.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "crates", "rn-bind-options", "src", "table.rs"),
    )
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()

    generated = generate(arguments.node_src)

    if arguments.check:
        try:
            with open(arguments.out, encoding="utf-8") as handle:
                committed = handle.read()
        except FileNotFoundError:
            print(f"{arguments.out} is missing; run tools/gen-options.py", file=sys.stderr)
            return 1
        if committed == generated:
            print(f"{arguments.out} is up to date")
            return 0
        diff = difflib.unified_diff(
            committed.splitlines(keepends=True),
            generated.splitlines(keepends=True),
            fromfile=f"{arguments.out} (committed)",
            tofile=f"{arguments.out} (generated)",
        )
        sys.stdout.writelines(diff)
        print(f"{arguments.out} is stale; run tools/gen-options.py", file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(arguments.out), exist_ok=True)
    with open(arguments.out, "w", encoding="utf-8") as handle:
        handle.write(generated)
    count = generated.count("    OptionInfo {")
    print(f"wrote {arguments.out}: {count} options")
    return 0


if __name__ == "__main__":
    sys.exit(main())
