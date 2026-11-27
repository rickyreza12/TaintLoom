fn main() {
    println!("cargo:rerun-if-changed=native/src/taintloom.c");
    println!("cargo:rerun-if-changed=native/include/taintloom.h");
    cc::Build::new()
        .file("native/src/taintloom.c")
        .include("native/include")
        .std("c17")
        .compile("taintloom_native");
}
