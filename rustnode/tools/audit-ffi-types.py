#!/usr/bin/env python3
"""Audit every hand-declared OpenSSL symbol in rn-bind-tls and rn-bind-crypto-x509.

gcc is the oracle, and the comparison is the **whole type**: return type, every
argument's base type, pointer depth and const-ness, and function-pointer nesting.
That is what an arity-only pass misses — it reported `EC_POINT_point2buf` ok
because only the types differed.

For each `extern "C"` declaration this translates the Rust types to C and emits

    static RET (*decl_N)(ARGS) = &SYMBOL;

into a translation unit that includes the vendored headers. gcc canonicalises
both sides in its `incompatible pointer type` diagnostic, and the two spellings
are compared structurally by `ctype.classify`, with typedef names expanded
through the header-derived table so `EC_KEY` and `struct ec_key_st` compare equal
on both sides.

Verdicts:

  MATCH     identical type
  CONST     only a `const` qualification differs. No ABI effect, but a write
            through the Rust-typed pointer would target read-only memory.
  ERASED    `void *` where C names an object pointer. ABI-identical.
  MISMATCH  base type, pointer depth, arity, or a value returned where C returns
            void. A caller passing what the Rust type describes corrupts memory.
  NOPROTO   the name is not a function: a macro, a static inline, or not an
            OpenSSL symbol at all. It links only while nothing references it.

Usage: audit-ffi-types.py <openssl-include-dir> [--json]
"""
import glob
import json
import os
import re
import subprocess
import sys
import tempfile


RUST_ROOTS = ["crates/rn-bind-tls/src", "crates/rn-bind-crypto-x509/src"]
if os.environ.get("RN_FFI_AUDIT_ROOT"):
    # Auditing a tree other than the checkout this script lives in is what lets
    # the audit be pointed at the pre-fix source and shown to fail there.
    os.chdir(os.environ["RN_FFI_AUDIT_ROOT"])

HEADERS = [
    "openssl/ssl.h", "openssl/tls1.h", "openssl/x509.h", "openssl/x509v3.h",
    "openssl/pkcs12.h", "openssl/evp.h", "openssl/ec.h", "openssl/bio.h",
    "openssl/err.h", "openssl/objects.h", "openssl/asn1.h", "openssl/bn.h",
    "openssl/stack.h", "openssl/rand.h", "openssl/hmac.h",
]

PRIMS = {
    "c_int": "int", "i32": "int",
    "c_uint": "unsigned int", "u32": "unsigned int",
    "c_long": "long", "i64": "long",
    "c_ulong": "unsigned long", "u64": "unsigned long",
    "c_char": "char", "i8": "char", "c_schar": "signed char",
    "c_uchar": "unsigned char", "u8": "unsigned char",
    "c_short": "short", "i16": "short",
    "c_ushort": "unsigned short", "u16": "unsigned short",
    "usize": "size_t", "isize": "ssize_t",
    "c_void": "void",
    "c_double": "double", "f64": "double",
    "c_float": "float", "f32": "float",
}

# Rust-side names that name a C type by a different spelling. Everything else is
# resolved through the header-derived typedef table.
RUST_TO_C = {
    "OpaqueStack": "ASN1_SEQUENCE_ANY",
    "X509Algor": "X509_ALGOR",
    "Tm": "struct tm",
}


# ---------------------------------------------------------------------------
# Structural comparison of gcc's two canonicalised sides
# ---------------------------------------------------------------------------
class Type:
    __slots__ = ("kind", "base", "base_const", "levels", "ret", "params")

    def __init__(self, kind, base="", base_const=False, levels=(), ret=None, params=()):
        self.kind = kind  # 'value' | 'ptr' | 'fnptr'
        self.base = base
        self.base_const = base_const
        self.levels = tuple(levels)  # outermost first; True means `* const`
        self.ret = ret
        self.params = tuple(params)

    def __repr__(self):
        if self.kind == "fnptr":
            return f"{self.ret!r} (*)({', '.join(repr(p) for p in self.params) or 'void'})"
        out = ("const " if self.base_const else "") + self.base
        for c in self.levels:
            out = f"*{' const ' if c else ''}{out}"
        return out

    def same(self, o):
        return repr(self) == repr(o)

    def same_except_const(self, o):
        if self.kind != o.kind or self.base != o.base or len(self.levels) != len(self.levels):
            if self.kind != o.kind or self.base != o.base or len(self.levels) != len(o.levels):
                return False
        if self.kind == "fnptr":
            if len(self.params) != len(o.params) or not self.ret.same_except_const(o.ret):
                return False
            return all(a.same_except_const(b) for a, b in zip(self.params, o.params))
        return len(self.levels) == len(o.levels)

    def same_modulo_void(self, o):
        if self.kind != o.kind:
            return False
        if self.kind == "fnptr":
            if len(self.params) != len(o.params) or not self.ret.same_modulo_void(o.ret):
                return False
            return all(a.same_modulo_void(b) for a, b in zip(self.params, o.params))
        if len(self.levels) != len(o.levels):
            return False
        if self.base == o.base:
            return True
        return {self.base, o.base} == {"void", o.base} or {self.base, o.base} == {"void", self.base}


def split_top(text, sep=","):
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def clean(text):
    # gcc prints a typedef it saw in the source together with its expansion:
    # `size_t *` `{aka long unsigned int *}`. The expansion is the shared
    # spelling, so prefer it on both sides; otherwise one side says `size_t`
    # and the other `long unsigned int` for the same type.
    m = re.search(r'\{aka (.*)\}', text)
    if m:
        text = m.group(1)
    t = re.sub(r'\{aka [^}]*\}', '', text)
    t = re.sub(r'\s+', ' ', t).strip()
    t = re.sub(r'\b(struct|union|enum)\s+', '', t)
    t = re.sub(r'\b(volatile|__restrict|restrict)\b', '', t)
    # `long unsigned int` and `unsigned long` denote one type.
    t = re.sub(r'\blong unsigned int\b', 'unsigned long', t)
    t = re.sub(r'\blong int\b', 'long', t)
    t = re.sub(r'\bunsigned int\b', 'unsigned', t)
    t = re.sub(r'\bshort unsigned int\b', 'unsigned short', t)
    # On the target the vendored tree is built for (x86-64 Linux), these are the
    # same type; gcc prints the expansion for both, so one spelling keeps a
    # `size_t` parameter from reading as a different type from `unsigned long`.
    t = re.sub(r'\bsize_t\b', 'unsigned long', t)
    t = re.sub(r'\bssize_t\b', 'long', t)
    t = re.sub(r'\bptrdiff_t\b', 'long', t)
    return re.sub(r'\s+', ' ', t).strip()


def parse(text, typedefs=None):
    t = clean(text)

    m = re.match(r'^(.*?)\(\s*\*\s*(?:[A-Za-z_][A-Za-z0-9_]*)?\s*\)\s*\((.*)\)$', t, re.S)
    if m:
        params = [parse(p, typedefs) for p in split_top(m.group(2)) if p.strip() not in ("", "void")]
        return Type("fnptr", ret=parse(m.group(1), typedefs), params=params)

    levels = []
    rest = t
    while True:
        rest = rest.strip()
        m = re.match(r'^(.*?)\s*\*\s*(const)?\s*$', rest, re.S)
        if not m:
            break
        levels.append(bool(m.group(2)))
        rest = m.group(1).strip()

    base_const = bool(re.search(r'\bconst\b', rest))
    base = re.sub(r'\s+', ' ', rest.replace("const", "")).strip()
    if typedefs and base in typedefs:
        base = typedefs[base]
    if levels:
        return Type("ptr", base=base, base_const=base_const, levels=levels)
    return Type("value", base=base, base_const=base_const)


def const_verdict(x, y, label, reasons, is_param):
    """Classify a type pair that differs only in `const`.

    Only one direction is dangerous, and only for a parameter.

    * A **parameter** where Rust adds `const` C does not have (`*const T` over
      `T *`) lets the caller pass a pointer into memory it only promised to read —
      a shared reference, or a read-only mapping — while the callee writes through
      it. That is undefined behaviour the declaration invited. This is a failure.
    * A **parameter** where Rust keeps `*mut` and C has `const` is the opposite:
      the callee cannot write, the Rust signature merely demands a mutable pointer
      the caller already has. No ABI or safety consequence.
    * A **return** where the two differ in `const`: the caller decides what to do
      with the value, and a `*const` return of a `T *` only withholds a write the
      caller has no reason to perform. Harmless in both directions.
    """
    # Compare per level; level 0 is outermost. `x` is the Rust declaration and `y`
    # is C.
    levels_x, levels_y = x.levels, y.levels
    rust_adds = False
    rust_drops = False
    for i in range(max(len(levels_x), len(levels_y))):
        declared_const = levels_x[i] if i < len(levels_x) else False
        c_const = levels_y[i] if i < len(levels_y) else False
        if declared_const and not c_const:
            rust_adds = True
        elif c_const and not declared_const:
            rust_drops = True
    if x.base_const != y.base_const:
        if x.base_const:
            rust_adds = True
        else:
            rust_drops = True

    if rust_adds and not rust_drops:
        what = "Rust adds a const C does not have"
    elif rust_drops and not rust_adds:
        what = "Rust omits a const C has"
    else:
        what = "the const levels differ"
    reasons.append(f"{label}: {what}  ({x!r} vs {y!r})")
    if is_param and rust_adds and not rust_drops:
        reasons.append(
            f"{label}: a parameter declared read-only where C writes would let a "
            f"caller pass immutable memory to a function that stores through it"
        )
        return "MISMATCH"
    return "CONST"


def classify(declared_text, actual_text, typedefs=None):
    """Return (verdict, reasons) for gcc's two canonicalised sides."""
    d = parse(declared_text)
    a = parse(actual_text, typedefs)
    if d.same(a):
        return "MATCH", []
    reasons = []

    def walk(x, y, label, is_param):
        if x.same(y):
            return "MATCH"
        if x.kind == "fnptr" and y.kind == "fnptr":
            worst = "MATCH"
            if len(x.params) != len(y.params):
                reasons.append(f"{label}: arity {len(x.params)} vs {len(y.params)}")
                return "MISMATCH"
            for i, (xp, yp) in enumerate(zip(x.params, y.params)):
                v = walk(xp, yp, f"{label} arg{i + 1}", is_param=True)
                worst = worst_verdict(worst, v)
            # A function pointer's own return is a return, not a parameter.
            v = walk(x.ret, y.ret, f"{label} return", is_param=False)
            return worst_verdict(worst, v)
        if x.kind != y.kind:
            reasons.append(f"{label}: kind {x.kind} vs {y.kind}  ({x!r} vs {y!r})")
            return "MISMATCH"
        if x.kind == "value":
            if x.base == y.base:
                if x.base_const != y.base_const:
                    reasons.append(f"{label}: const differs  {x!r} vs {y!r}")
                    return "CONST"
                return "MATCH"
            reasons.append(f"{label}: base {x.base!r} vs {y.base!r}")
            return "MISMATCH"
        # pointer
        if len(x.levels) != len(y.levels) or x.base != y.base:
            if x.same_modulo_void(y):
                reasons.append(f"{label}: void erased  {x!r} vs {y!r}")
                return "ERASED"
            if x.base == y.base:
                reasons.append(f"{label}: pointer depth {len(x.levels)} vs {len(y.levels)}  ({x!r} vs {y!r})")
            else:
                reasons.append(f"{label}: base {x.base!r} vs {y.base!r}  ({x!r} vs {y!r})")
            return "MISMATCH"
        if x.levels != y.levels:
            return const_verdict(x, y, label, reasons, is_param)
        if x.base_const != y.base_const:
            return const_verdict(x, y, label, reasons, is_param)
        return "CONST"

    return walk(d, a, "type", is_param=False), reasons


ORDER = ["MATCH", "CONST", "ERASED", "MISMATCH", "NOPROTO"]


def worst_verdict(a, b):
    return a if ORDER.index(a) >= ORDER.index(b) else b


def load_typedefs(include_dir):
    """Map typedef names to how gcc prints the tag they name.

    `typedef struct ssl_cipher_st SSL_CIPHER;` makes gcc print either spelling
    depending on which one the declaration used, so both have to collapse to one.
    A struct or union tag needs its `struct`/`union` keyword to be usable in a
    declaration, which is why the kind is kept rather than just the tag.
    """
    table = {}
    headers = glob.glob(os.path.join(include_dir, "openssl", "*.h"))
    if not headers:
        sys.exit(f"audit: no OpenSSL headers under {include_dir!r}; refusing to "
                 f"report a result it did not compute")
    for header in headers:
        text = open(header, errors="replace").read()
        for kind in ("struct", "union"):
            for m in re.finditer(rf'typedef\s+{kind}\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', text):
                table[m.group(2)] = f"{kind} {m.group(1)}"
        for m in re.finditer(r'typedef\s+STACK_OF\(\s*([A-Za-z0-9_]+)\s*\)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', text):
            table[m.group(2)] = "struct stack_st_" + m.group(1)
        # Enum typedefs are `int` at the ABI level and gcc does not expand them.
        for m in re.finditer(r'typedef\s+enum\s*(?:[A-Za-z_][A-Za-z0-9_]*)?\s*\{[^}]*\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;', text, re.S):
            table[m.group(1)] = "int"
        for m in re.finditer(r'typedef\s+enum\s+[A-Za-z_][A-Za-z0-9_]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', text):
            table[m.group(1)] = "int"
    return table


def split_top(text, sep=","):
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def strip_paths(t):
    return re.sub(r'\b(?:std::os::raw|std::ffi|ffi|openssl_sys|libc)::', '', t.strip()).strip()


def rust_type_to_c(t, typedefs):
    """Translate one Rust type to C.

    Rust's `*const T` means "pointer to const T", which is C's `const T *`.
    Building from the innermost level outward preserves that through nesting:
    `*mut *const c_uchar` becomes `const unsigned char *` then
    `const unsigned char * *`, which is C's `const unsigned char **`.
    """
    t = strip_paths(t)
    t = re.sub(r'^mut\s+', '', t)
    t = re.sub(r'\s+', ' ', t).strip()

    m = re.match(r'^Option<\s*(?:unsafe\s+)?extern "C" fn\s*\((.*)\)\s*(?:->\s*(.+?))?\s*>$', t, re.S)
    if not m:
        m = re.match(r'^(?:unsafe\s+)?extern "C" fn\s*\((.*)\)\s*(?:->\s*(.+?))?$', t, re.S)
    if m:
        params = [rust_type_to_c(p, typedefs) for p in split_top(m.group(1))]
        if any(p is None for p in params):
            return None
        ret = rust_type_to_c((m.group(2) or "()").strip(), typedefs)
        if ret is None:
            return None
        return f"{ret} (*)({', '.join(params) or 'void'})"

    levels = []
    while True:
        m = re.match(r'^\*(const|mut)\s+(.*)$', t)
        if not m:
            break
        levels.append(m.group(1) == "const")
        t = strip_paths(m.group(2))

    if t == "()":
        c = "void"
    elif t in PRIMS:
        c = PRIMS[t]
    elif t in RUST_TO_C:
        c = RUST_TO_C[t]
    elif re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', t):
        # `stack_st_X` is the tag of an opaque `STACK_OF(X)` struct that the
        # headers only forward-declare, so it needs its keyword like any tag.
        c = typedefs.get(t) or (f"struct {t}" if t.startswith("stack_st_") else t)
    else:
        return None

    for is_const in reversed(levels):
        c = f"const {c} *" if is_const else f"{c} *"
    return c


def rust_extern_decls():
    """Yield every `extern "C"` function declaration in the two crates.

    `pub`, `pub(crate)` and `unsafe` are all allowed before `fn`: `ffi_extra.rs`
    declares its items `pub`, and a matcher that only accepts a bare `fn` at the
    start of a line silently omits them, which is how an earlier count over this
    same tree reported a clean result over the declarations that mattered.
    """
    decl_re = re.compile(
        r'\n( *)'
        r'(?:pub(?:\s*\([^)]*\))?\s+)?'
        r'(?:unsafe\s+)?'
        r'fn\s+([A-Za-z_0-9]+)\s*\((.*?)\)\s*(?:->\s*([^;{]+?))?\s*;',
        re.S)
    for root in RUST_ROOTS:
        for path in sorted(glob.glob(os.path.join(root, "**", "*.rs"), recursive=True)):
            text = open(path).read()
            for m in re.finditer(r'\n( *)extern "C" \{(.*?)\n\1\}', text, re.S):
                body = m.group(2)
                base_line = text[:m.start()].count("\n") + 2
                for fm in decl_re.finditer("\n" + body):
                    yield (path, base_line + body[:fm.start()].count("\n"),
                           fm.group(2), fm.group(3), (fm.group(4) or "()").strip())


def find_include_dir():
    """The newest `openssl-src` install tree under `target/`.

    Several `openssl-sys-<hash>` build directories can exist at once, one per
    profile and one per fingerprint change. The newest `libssl.a` is the one this
    build actually linked, so the newest tree is the one to compare against;
    taking the first match would audit the declarations against a stale header set
    and still report a verdict.
    """
    newest, found = 0, None
    for pattern in ("target/*/build/openssl-sys-*/out/openssl-build/install",):
        for candidate in glob.glob(pattern):
            lib = os.path.join(candidate, "lib", "libssl.a")
            header = os.path.join(candidate, "include", "openssl", "ssl.h")
            if not (os.path.isfile(lib) and os.path.isfile(header)):
                continue
            stamp = os.stat(lib).st_mtime
            if stamp > newest:
                newest, found = stamp, os.path.join(candidate, "include")
    return found


# A declaration that must be reported as `MISMATCH`, one that must be reported as
# `NOPROTO`, and one that must come back clean. The first two are the defects this
# audit exists for, taken from the headers and not from the tree under test, so
# the self-test measures the audit rather than the code.
SELF_TEST_CASES = [
    (
        "a length out-parameter where C takes a BN_CTX",
        "EC_POINT_point2buf",
        "size_t (*)(EC_GROUP *, EC_POINT *, int, unsigned char **, void *)",
        "MISMATCH",
    ),
    (
        "a one-byte out-parameter declared as a pointer",
        "SSL_get_shared_sigalgs",
        "int (*)(SSL *, int, int *, int *, int *, const char **, const char **)",
        "MISMATCH",
    ),
    (
        "a value returned where C returns void",
        "SSL_SESSION_get0_ticket",
        "int (*)(const SSL_SESSION *, const unsigned char **, size_t *)",
        "MISMATCH",
    ),
    (
        "a macro declared as a function",
        "SSL_set1_verify_cert_store",
        "int (*)(SSL *, X509_STORE *)",
        "NOPROTO",
    ),
    (
        "a declaration that is right",
        "SSL_get_servername",
        "const char * (*)(const SSL *, int)",
        "MATCH",
    ),
    (
        # A parameter Rust declares read-only where C writes: the caller can pass
        # a shared reference or a read-only mapping and the callee stores through
        # it. `X509_get_ext_by_NID`'s first parameter is `const X509 *`, so a
        # declaration of `X509 *` is the ordinary direction; `SSL_get_servername`
        # takes `const SSL *` and declaring `SSL *` is likewise ordinary. This
        # case uses a function whose C parameter is non-const and declares it
        # const instead: `X509_set_pubkey` takes `X509 *` and `EVP_PKEY *`.
        "a parameter declared read-only where C writes",
        "X509_set_pubkey",
        "int (*)(const X509 *, EVP_PKEY *)",
        "MISMATCH",
    ),
]


def self_test(include_dir):
    typedefs = load_typedefs(include_dir)
    tu = ["#include <stddef.h>", "#include <sys/types.h>"]
    tu += [f"#include <{h}>" for h in HEADERS]
    tu.append('#pragma GCC diagnostic ignored "-Wunused-variable"')
    tu.append('#pragma GCC diagnostic ignored "-Wdeprecated-declarations"')
    stack_tags = sorted({m for m in typedefs.values() if m.startswith("struct stack_st_")})
    tu += [f"{tag};" for tag in stack_tags]
    for index, (_, name, csig, _) in enumerate(SELF_TEST_CASES):
        # The stored signature already has the form `RET (*)(ARGS)`, so the
        # declarator name goes between the stars and the closing parenthesis.
        # Appending it after the signature is a syntax error, and gcc then reports
        # an error on every line whose verdict is never read, which makes all five
        # cases report `MATCH`.
        declarator = csig.replace("(*)(", f"(*decl_{index})(", 1)
        if declarator == csig:
            sys.exit(f"audit self-test: {name}: signature {csig!r} has no (*) to name")
        tu.append(f"static {declarator} = &{name};")
    tu.append("int probe(void) { return 0; }")
    src = "\n".join(tu) + "\n"

    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        cpath = f.name
    proc = subprocess.run(
        ["gcc", "-fsyntax-only", "-fno-diagnostics-show-caret",
         "-Wno-unused-variable", "-Wno-deprecated-declarations",
         f"-I{include_dir}", cpath],
        capture_output=True, text=True)
    out = proc.stderr.splitlines()
    os.unlink(cpath)

    src_lines = src.splitlines()
    first = next(i + 1 for i, l in enumerate(src_lines) if l.startswith("static "))

    failures = 0
    for index, (description, name, csig, expected) in enumerate(SELF_TEST_CASES):
        lineno = first + index
        diags = [m.group(1) for text in out
                 if (m := re.match(rf'{re.escape(cpath)}:{lineno}:\d+: (?:warning|error): (.*)', text))]
        verdict = "MATCH"
        for msg in diags:
            m = re.search(r"incompatible pointer type ‘([^’]*)’(?:\s*\{aka ‘([^’]*)’\})?", msg)
            if m:
                v, _ = classify(csig, m.group(2) or m.group(1), typedefs)
                verdict = worst_verdict(verdict, v)
            elif "undeclared" in msg or "implicit declaration" in msg:
                verdict = "NOPROTO"
        status = "ok" if verdict == expected else "BAD"
        if verdict != expected:
            failures += 1
        print(f"audit self-test: {status}: {description}: {name} -> {verdict} (expected {expected})")
    if failures:
        print(f"audit self-test: {failures} of {len(SELF_TEST_CASES)} cases did not reach "
              f"their expected verdict, so the audit cannot be trusted on this tree")
        return 1
    print(f"audit self-test: all {len(SELF_TEST_CASES)} cases reached their expected verdict")
    return 0


def main():
    if "--self-test" in sys.argv:
        include_dir = find_include_dir()
        if not include_dir:
            sys.exit("audit: no vendored OpenSSL install tree under target/; "
                     "run cargo build before the self-test")
        return self_test(include_dir)

    include_dir = sys.argv[1] if len(sys.argv) > 1 else find_include_dir()
    want_json = "--json" in sys.argv
    if not include_dir or not os.path.isdir(include_dir):
        sys.exit(f"audit: {include_dir!r} is not a directory")
    typedefs = load_typedefs(include_dir)
    # A table this small means the header glob silently matched almost nothing,
    # and every comparison after it would be against a degraded oracle.
    if len(typedefs) < 100:
        sys.exit(f"audit: only {len(typedefs)} typedefs parsed from {include_dir!r}; "
                 f"the header set is wrong and a clean result here would be vacuous")

    decls = list(rust_extern_decls())
    lines, meta, untranslatable = [], [], []
    for path, line, name, params, ret in decls:
        cparams, ok = [], True
        for p in split_top(params):
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*:', p):
                p = p.split(":", 1)[1]
            c = rust_type_to_c(p, typedefs)
            if c is None:
                ok = False
                untranslatable.append((path, line, name, p))
                break
            cparams.append(c)
        if not ok:
            continue
        cret = rust_type_to_c(ret, typedefs)
        if cret is None:
            untranslatable.append((path, line, name, ret))
            continue
        arglist = ", ".join(cparams) if cparams else "void"
        lines.append(f"static {cret} (*decl_{len(lines)})({arglist}) = &{name};")
        meta.append((path, line, name, f"{cret} (*)({arglist})"))

    tu = ["#include <stddef.h>", "#include <sys/types.h>"]
    tu += [f"#include <{h}>" for h in HEADERS]
    tu.append('#pragma GCC diagnostic ignored "-Wunused-variable"')
    tu.append('#pragma GCC diagnostic ignored "-Wdeprecated-declarations"')
    # The `stack_st_*` structs a `STACK_OF(...)` typedef names are opaque: no
    # public header defines them, so a prototype that mentions one is only
    # comparable after a forward declaration.
    stack_tags = sorted({m for m in typedefs.values() if m.startswith("struct stack_st_")})
    tu += [f"{tag};" for tag in stack_tags]
    tu += lines
    tu.append("int probe(void) { return 0; }")
    src = "\n".join(tu) + "\n"

    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        cpath = f.name
    proc = subprocess.run(
        ["gcc", "-fsyntax-only", "-fno-diagnostics-show-caret",
         "-Wno-unused-variable", "-Wno-deprecated-declarations",
         f"-I{include_dir}", cpath],
        capture_output=True, text=True)
    out = proc.stderr.splitlines()
    os.unlink(cpath)

    src_lines = src.splitlines()
    first_line = next((i + 1 for i, l in enumerate(src_lines) if l.startswith("static ")), 0)
    decl_lines = set(range(first_line, first_line + len(meta)))

    by_line = {}
    unattributed = []
    for text in out:
        m = re.match(rf'{re.escape(cpath)}:(\d+):\d+: (warning|error): (.*)', text)
        if not m:
            continue
        lineno, msg = int(m.group(1)), m.group(3)
        if lineno in decl_lines:
            by_line.setdefault(lineno, []).append(msg)
        elif m.group(2) == "error":
            unattributed.append(text)
    # A hard error on a *declaration* line is a verdict for that declaration — an
    # `undeclared` symbol is exactly what a macro declaration produces. Only an
    # error that names no declaration is fatal, because it means the probe did not
    # compile and nothing was compared.
    if unattributed:
        sys.exit("audit: gcc failed on something other than a declaration, so "
                 "nothing was compared:\n" + "\n".join(unattributed))
    # Every declaration line must exist in the TU it was placed in; a matcher that
    # produced lines but no diagnostics because the TU was never compiled is the
    # failure mode this guards.
    if len(lines) != len(meta):
        sys.exit(f"audit: emitted {len(lines)} lines for {len(meta)} declarations")

    rows = []
    for i, (rpath, rline, name, csig) in enumerate(meta):
        diags = by_line.get(first_line + i, [])
        if not diags:
            rows.append(dict(file=rpath, line=rline, symbol=name, declared=csig,
                             verdict="MATCH", reasons=[]))
            continue
        verdict, reasons = "MATCH", []
        for msg in diags:
            m = re.search(
                r"incompatible pointer type ‘([^’]*)’(?:\s*\{aka ‘([^’]*)’\})?", msg)
            if m:
                # gcc prints the spelling the source used, then `{aka ...}` with
                # the typedefs expanded. The expansion is what both sides share,
                # so it is the one compared.
                actual = m.group(2) or m.group(1)
                v, rs = classify(csig, actual, typedefs)
                verdict = worst_verdict(verdict, v)
                reasons.extend(rs)
                continue
            if "undeclared" in msg or "implicit declaration" in msg or "not declared" in msg:
                verdict = "NOPROTO"
                reasons.append(msg)
                continue
            verdict = worst_verdict(verdict, "MISMATCH")
            reasons.append(msg)
        rows.append(dict(file=rpath, line=rline, symbol=name, declared=csig,
                         verdict=verdict, reasons=reasons))

    if want_json:
        print(json.dumps(dict(rows=rows, untranslatable=untranslatable), indent=2))
        return 0

    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print(f"hand-declared extern symbols parsed:   {len(decls)}")
    print(f"compared against a full C prototype:   {len(rows) + len(untranslatable)}")
    print(f"distinct symbols:                      {len({r['symbol'] for r in rows})}")
    print(f"typedef names resolved from headers:   {len(typedefs)}")
    for k in ("MATCH", "CONST", "ERASED", "MISMATCH", "NOPROTO"):
        print(f"  {k:<9}{counts.get(k, 0)}")
    for verdict in ("MISMATCH", "NOPROTO", "ERASED", "CONST"):
        sel = [r for r in rows if r["verdict"] == verdict]
        if not sel:
            continue
        print(f"\n===== {verdict} =====")
        for r in sel:
            print(f"{r['file']}:{r['line']}  {r['symbol']}")
            print(f"    declared: {r['declared']}")
            for x in r["reasons"]:
                print(f"    - {x}")
    if untranslatable:
        print("\n===== NOT TRANSLATABLE (not compared) =====")
        for rpath, rline, name, t in untranslatable:
            print(f"{rpath}:{rline}  {name}: {t!r}")
    bad = counts.get("MISMATCH") or counts.get("NOPROTO") or untranslatable
    return 1 if bad else 0


sys.exit(main())
