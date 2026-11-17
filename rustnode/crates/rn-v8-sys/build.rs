fn main() {
    println!("cargo:rerun-if-changed=src/isolate_stack_limit.cc");
    cc::Build::new()
        .cpp(true)
        .file("src/isolate_stack_limit.cc")
        .compile("rn_v8_sys_stack_limit");
}
