#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

//#include <sys/syscall.h>

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

// Matches /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
struct write_ctx {
    unsigned long pad;
    __u64 __unused_syscall_header;
    int syscall_nr;
    int fd;
    const char *buf;
    __u64 count;
};

struct renameat2_ctx {
    unsigned long pad;
    __u64 __unused_syscall_header;
    int syscall_nr;
    int olddfd;
    const char *oldname;
    int newdfd;
    const char *newname;
    unsigned int flags;
};


struct fchmodat_ctx {
    unsigned long long __pad;
    __u64 __unused_syscall_header;
    int syscall_nr;
    int dfd;
    const char *filename;
    __u16 mode;
};

struct fchownat_ctx {
    unsigned long pad;
    __u64 __unused_syscall_header;
    int syscall_nr;
    int dfd;
    const char *filename;
    __u32 user;     // instead of uid_t
    __u32 group;    // instead of gid_t
    int flag;
};


// Defined according to /sys/kernel/debug/tracing/events/syscalls/sys_exit_close/format
struct close_ctx {
    unsigned long pad;
    __u64 __unused_syscall_header;
    int syscall_nr;
    int fd;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, char[256]);
} fd_to_filename SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct openat_ctx *ctx) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.command, sizeof(event.command));

    const char* filename = ctx->filename;
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    __builtin_memcpy(event.op, "OPEN", 5);

    int fd = ctx->dfd;
    bpf_map_update_elem(&fd_to_filename, &fd, event.filename, BPF_ANY);

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

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct write_ctx *ctx) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.command, sizeof(event.command));

    // Write doesn't give filename, just file descriptor
    // We'll format a placeholder string for the fd
    int fd = ctx->fd;
    __builtin_memcpy(event.op, "WRITE", 6);

    // Turn fd into a readable string like "fd=3"
    // Crude formatting — for robust solution use bpf_snprintf (in newer kernels)
        // Resolve filename from FD-to-Filename map
    char *filename = bpf_map_lookup_elem(&fd_to_filename, &fd);
    if (filename) {
        bpf_probe_read_kernel_str(event.filename, sizeof(event.filename), filename);
    } else {
        __builtin_memset(event.filename, 0, sizeof(event.filename)); // Clear filename if not found
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));
    return 0;

}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct renameat2_ctx *ctx) {
    struct event event = {};

    // Common event fields
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.command, sizeof(event.command));

    // Send "RENAME" event for oldname
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), ctx->oldname);
    __builtin_memcpy(event.op, "RENAME", 7);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // Send "RENAMED" event for newname
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), ctx->newname);
    __builtin_memcpy(event.op, "RENAMED", 8);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct fchmodat_ctx *ctx) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.command, sizeof(event.command));
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), ctx->filename);
    __builtin_memcpy(event.op, "CHMOD", 6);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_fchownat(struct fchownat_ctx *ctx) {
    struct event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.command, sizeof(event.command));

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), ctx->filename);
    __builtin_memcpy(event.op, "CHOWN", 6);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_close(struct close_ctx *ctx) {
    int fd = ctx->fd;

    // Remove the file descriptor from the fd_to_filename map
    bpf_map_delete_elem(&fd_to_filename, &fd);

    return 0;
}