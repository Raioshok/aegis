//! # aegis-trace
//!
//! Loads the Aegis eBPF exec tracer into the kernel, attaches it to the
//! `sys_enter_execve` tracepoint, and prints every `execve` observed
//! system-wide (pid, uid, comm, filename). This is real kernel-level syscall
//! tracing — behavioural visibility no userspace-only approach can match.
//!
//! Requires root (or `CAP_BPF`+`CAP_PERFMON`). Ctrl-C to stop; the program and
//! its map are removed from the kernel on exit.

use std::mem::MaybeUninit;
use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;

mod trace {
    include!(concat!(env!("OUT_DIR"), "/trace.skel.rs"));
}
use trace::*;

/// Mirror of `struct exec_event` in bpf/trace.bpf.c (same field order + sizes).
#[repr(C)]
struct ExecEvent {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; 192],
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<ExecEvent>() {
        return 0;
    }
    // Safe field extraction by offset (no unaligned deref of the whole struct).
    let pid = u32::from_ne_bytes(data[0..4].try_into().unwrap());
    let uid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
    let comm = cstr(&data[8..24]);
    let filename = cstr(&data[24..24 + 192]);
    println!(
        "{:<8} uid={:<6} {:<16} {}",
        pid,
        uid,
        comm,
        if filename.is_empty() { "?" } else { &filename }
    );
    0
}

#[allow(clippy::print_literal)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("aegis-trace: loading eBPF exec tracer (needs root)…");

    let skel_builder = TraceSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("aegis-trace: attached to sys_enter_execve. Tracing exec() system-wide.");
    println!("{:<8} {:<10} {:<16} {}", "PID", "UID", "COMM", "FILENAME");

    let mut rbb = RingBufferBuilder::new();
    rbb.add(&skel.maps.events, handle_event)?;
    let ringbuf = rbb.build()?;

    loop {
        ringbuf.poll(Duration::from_millis(200))?;
    }
}
