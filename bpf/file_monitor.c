#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <sys/syscall.h>

char __license[] SEC("license") = "GPL";

// Defined according to /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
struct openat_ctx {
    unsigned long pad;
    __u64 __unsused_syscall_header;
    int syscall_nr;
    int dfd;
    const char *filename;
    int flags;
    __u16 mode;
};

// Defined according to /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat/format
struct unlinkat_ctx {
    unsigned long pad;
    __u64 __unused_syscall_header;
    int syscall_nr;
    int dfd;
    const char *pathname;
    int flag;
};

struct event {
    __u32 pid;
    char command[16];
    char filename[256];
    char op[10];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct openat_ctx *ctx) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.command, sizeof(event.command));

    const char* filename = ctx->filename;
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    __builtin_memcpy(event.op, "OPEN", 5);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct unlinkat_ctx *ctx) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.command, sizeof(event.command));

    const char* pathname = ctx->pathname;
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), pathname);

    __builtin_memcpy(event.op, "DELETE", 7);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));
    return 0;
}
