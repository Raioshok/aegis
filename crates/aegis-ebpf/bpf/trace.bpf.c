// Aegis eBPF exec tracer.
//
// Attaches to the raw syscall tracepoint `sys_enter_execve` and streams one
// event per exec (pid, uid, comm, filename) to userspace over a BPF ring buffer.
// Uses a manually-declared tracepoint context so it needs no vmlinux.h / CO-RE
// relocations — the sys_enter tracepoint layout is stable kernel ABI.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define FILENAME_LEN 192
#define COMM_LEN 16

struct exec_event {
    __u32 pid;
    __u32 uid;
    char comm[COMM_LEN];
    char filename[FILENAME_LEN];
};

// BPF ring buffer (256 KiB) carrying events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Minimal sys_enter tracepoint context: 8-byte common header, syscall id, then
// the six syscall arguments. args[0] for execve is the filename pointer.
struct sys_enter_ctx {
    __u64 __common;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int aegis_trace_execve(struct sys_enter_ctx *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
