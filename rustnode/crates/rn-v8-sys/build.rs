fn main() {
    println!("cargo:rerun-if-changed=src/isolate_stack_limit.cc");
    println!("cargo:rerun-if-changed=src/isolate_measure_memory.cc");
    println!("cargo:rerun-if-changed=src/query_objects.cc");
    println!("cargo:rerun-if-changed=src/take_heap_snapshot.cc");
    println!("cargo:rerun-if-changed=src/embedder_graph.cc");
    cc::Build::new()
        .cpp(true)
        // `v8-profiler.h` requires C++20 for `v8config.h`, and the scoped enum
        // classes these shims re-declare need it too, so the standard is named
        // rather than left to cc-rs's edition-derived default.
        .std("c++20")
        .file("src/isolate_stack_limit.cc")
        .file("src/isolate_measure_memory.cc")
        .file("src/query_objects.cc")
        .file("src/take_heap_snapshot.cc")
        .file("src/embedder_graph.cc")
        .compile("rn_v8_sys_stack_limit");
}
