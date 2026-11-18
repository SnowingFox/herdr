fn main() {
    println!("cargo:rerun-if-changed=src/isolate_stack_limit.cc");
    println!("cargo:rerun-if-changed=src/measure_memory.cc");
    cc::Build::new()
        .cpp(true)
        // `measure_memory.cc` mirrors V8's own `std::__Cr` (libc++) type names in
        // its declarations, so it needs C++17 for the inline namespace spelling
        // and nothing more. cc-rs picks the flag from this, and the file builds
        // with either `CXX=g++` or clang.
        .std("c++17")
        .file("src/isolate_stack_limit.cc")
        .file("src/measure_memory.cc")
        .compile("rn_v8_sys_shims");
}
