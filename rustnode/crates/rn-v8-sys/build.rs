fn main() {
    println!("cargo:rerun-if-changed=src/isolate_stack_limit.cc");
    println!("cargo:rerun-if-changed=src/isolate_measure_memory.cc");
    println!("cargo:rerun-if-changed=src/query_objects.cc");
    println!("cargo:rerun-if-changed=src/take_heap_snapshot.cc");
    cc::Build::new()
        .cpp(true)
        .file("src/isolate_stack_limit.cc")
        .file("src/isolate_measure_memory.cc")
        .file("src/query_objects.cc")
        // `v8-profiler.h` requires C++20 for `v8config.h`, and the enums this
        // shim re-declares are scoped enum classes, so the standard is named
        // rather than left to cc-rs's edition-derived default.
        .std("c++20")
        .file("src/take_heap_snapshot.cc")
        .compile("rn_v8_sys_stack_limit");
}
