fn main() {
    println!("cargo:rerun-if-changed=src/isolate_stack_limit.cc");
    println!("cargo:rerun-if-changed=src/isolate_measure_memory.cc");
    println!("cargo:rerun-if-changed=src/query_objects.cc");
    cc::Build::new()
        .cpp(true)
        .file("src/isolate_stack_limit.cc")
        .file("src/isolate_measure_memory.cc")
        .file("src/query_objects.cc")
        .compile("rn_v8_sys_stack_limit");
}
