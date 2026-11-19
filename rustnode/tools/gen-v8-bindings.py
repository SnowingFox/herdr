#!/usr/bin/env python3
"""Generates src_binding.rs for the vendored rusty_v8 crate.

    gen-v8-bindings.py <v8-root> <gn-out-dir> <output.rs>

vendor/rusty-v8/build.rs runs bindgen itself, but only against a GN graph it
generated at CARGO_MANIFEST_DIR. When the crate is consumed through
RUSTY_V8_ARCHIVE the binding has to come with the archive, so this reproduces the
same bindgen::Builder call out of band.

The define set is read from project.json for //:v8_headers, the target
vendor/rusty-v8/tools/get_bindgen_args.py reads upstream, so the bindings see the
preprocessor configuration the engine was compiled with. Three details are easy
to get wrong, and each fails as a parse error inside V8's own headers rather than
as anything that names the real cause:

  * V8_EMBEDDER_STRING="-rusty" carries a quoted value. Stripping the quotes
    makes V8_VERSION_STRING, and therefore binding.hpp, invalid C++.
  * The clang resource directory must belong to the libclang doing the parsing.
    Pairing a distribution clang's stddef.h with Chromium's libc++ headers yields
    "expected ';' after top level declarator".
  * bindgen is required; this script does not install it.
"""

import json
import os
import shutil
import subprocess
import sys


def v8_defines(gn_out):
    """The //:v8_headers define list, as -D arguments."""
    with open(os.path.join(gn_out, "project.json")) as handle:
        project = json.load(handle)
    target = project["targets"]["//:v8_headers"]
    if "//:cppgc_headers" not in target["deps"]:
        sys.exit(
            "//:v8_headers no longer depends on //:cppgc_headers; "
            "tools/get_bindgen_args.py would fail the same way"
        )
    return [f"-D{define}" for define in target["defines"]]


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    root, gn_out, out_path = sys.argv[1:]
    root = os.path.abspath(root)

    bindgen = shutil.which("bindgen")
    if bindgen is None:
        sys.exit("bindgen is required: cargo install bindgen-cli")

    clang_args = [
        "-x",
        "c++",
        "-std=c++20",
        "-nostdinc++",
        f"-I{root}/include",
        f"-I{root}",
        f"-I{root}/crate",
        "-D_LIBCPP___TYPE_TRAITS_ALIGNED_UNION_H",
    ]
    for directory in (
        "buildtools/third_party/libc++",
        "third_party/libc++/src/include",
        "third_party/libc++abi/src/include",
    ):
        path = os.path.join(root, directory)
        if os.path.isdir(path):
            clang_args.append(f"-isystem{path}")

    libclang = os.environ.get("LIBCLANG_PATH")
    if libclang:
        clang = os.path.join(os.path.dirname(libclang), "bin", "clang")
        if os.path.exists(clang):
            resource = subprocess.run(
                [clang, "-print-resource-dir"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            clang_args.append(f"-resource-dir={resource}")

    command = [
        bindgen,
        os.path.join(root, "crate/src/binding.hpp"),
        "--output",
        out_path,
        "--allowlist-item",
        "v8__.*",
        "--allowlist-item",
        "cppgc__.*",
        "--allowlist-item",
        "RustObj",
        "--allowlist-item",
        "memory_span_t",
        "--allowlist-item",
        "const_memory_span_t",
        "--allowlist-item",
        "ExternalConstOneByteStringResource",
        "--blocklist-item",
        "cppgc.*Visitor",
        "--blocklist-item",
        "RustObj.*Trace",
        "--rustified-enum",
        ".*UseCounterFeature",
        "--rustified-enum",
        ".*ModuleImportPhase",
        "--rustified-enum",
        ".*Intercepted",
        "--bitfield-enum",
        ".*GCType",
        "--bitfield-enum",
        ".*GCCallbackFlags",
        "--generate-cstr",
    ]
    # One `--` introduces every clang argument; repeating it per argument makes
    # bindgen treat each as a separate trailing block.
    command.append("--")
    command.extend(clang_args + v8_defines(gn_out))

    subprocess.run(command, check=True)
    print(f"wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
