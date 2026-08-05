//! Compile the BPF C program and generate a Rust skeleton at build time.
//! Requires `clang` and `bpftool` on the build host.

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "bpf/trace.bpf.c";

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("trace.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .expect("failed to build/generate BPF skeleton (need clang + bpftool)");
    println!("cargo:rerun-if-changed={SRC}");
}
