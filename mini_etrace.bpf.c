#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "mini_etrace.h"

struct bpf_map_def SEC("maps") config_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct trace_config),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") syscall_bitmap = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = SYSCALL_BITMAP_WORDS,
};


/*
 * sys_enter 和 sys_exit 之间保存临时信息
 * key = pid_tgid
 */
struct inflight_syscall {
    __u64 ts_ns;
    __u64 args[6];
    __u64 user_stack[MAX_STACK_DEPTH];
    __s32 stack_size;
    __u32 pid;
    __u32 tid;
    __s32 syscall_id;
};

struct bpf_map_def SEC("maps") inflight = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u64),
    .value_size  = sizeof(struct inflight_syscall),
    .max_entries = 0x1000,
};

struct bpf_map_def SEC("maps") in_map = {
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct inflight_syscall),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") event_map = {
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct syscall_event),
    .max_entries = 1,
};

/*
 * 向用户态发送 syscall event
 */
struct bpf_map_def SEC("maps") events = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 16,
};

struct sys_enter_ctx {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    __s64 id;

    __u64 args[6];
};

struct sys_exit_ctx {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    __s64 id;
    __s64 ret;
};


static __always_inline int syscall_allowed(__s32 syscall_id)
{
    __u32 key;
    __u32 bit;
    __u64 *word;
    if (syscall_id < 0)
        return 0;

    if (syscall_id >= MAX_SYSCALLS)
        return 0;

    key = (__u32)syscall_id / 64;
    bit = (__u32)syscall_id % 64;

    word = bpf_map_lookup_elem(&syscall_bitmap, &key);
    if (!word)
        return 0;
    /*
     * 对应 bit 为 1： syscall 在白名单中
     */
    if (*word & ((__u64)1 << bit))
        return 1;

    return 0;
}



static __always_inline int comm_equal(const char *a,
                                      const char *b)
{
    int i;
#pragma unroll
    for (i = 0; i < COMM_LEN; i++) {
        if (a[i] != b[i])
            return 0;

        if (a[i] == '\x00')
            return 1;
    }

    return 1;
}


SEC("tracepoint/raw_syscalls/sys_enter")
int trace_enter(struct sys_enter_ctx *ctx)
{
    struct inflight_syscall *data;
    struct trace_config *cfg;
    __u64 pid_tgid;

    __u32 pid;
    __u32 tid;

    __u32 zero = 0;

    char comm[COMM_LEN] = {};

    cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    tid = (__u32)pid_tgid;
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;

    if (cfg->filter_type == FILTER_PID)
        if (pid != cfg->target_pid)
                return 0;

    if (cfg->filter_type == FILTER_COMM) {
        if (!comm_equal(comm, cfg->target_comm))
            return 0;
    }

    if (cfg->syscall_filter_enabled) {
        if (!syscall_allowed((__s32)ctx->id))
            return 0;
    }

    data = bpf_map_lookup_elem(&in_map, &zero);
    if (!data)
        return 0;

    data->ts_ns = bpf_ktime_get_ns();
    data->pid = pid;
    data->tid = tid;
    data->syscall_id = (__s32)ctx->id;

#pragma unroll
    for (int i = 0; i < 6; i++)
        data->args[i] = ctx->args[i];


    data->stack_size = bpf_get_stack(
            ctx,
            data->user_stack,
            sizeof(data->user_stack),
            BPF_F_USER_STACK
        );

    bpf_map_update_elem(&inflight,
                        &pid_tgid,
                        data,
                        BPF_ANY);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_exit(struct sys_exit_ctx *ctx)
{
    struct inflight_syscall *in;
    struct syscall_event *event;
    __u64 pid_tgid;

    int zero = 0;

    pid_tgid = bpf_get_current_pid_tgid();

    in = bpf_map_lookup_elem(&inflight, &pid_tgid);
    if (!in)
        return 0;

    event = bpf_map_lookup_elem(&event_map, &zero);
    if (!event)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    event->ts_ns = in->ts_ns;
    event->duration_ns = now - in->ts_ns;
    event->pid = in->pid;
    event->tid = in->tid;
    event->syscall_id = in->syscall_id;
    event->ret = ctx->ret;
    event->stack_size = in->stack_size;

#pragma unroll
    for (int i = 0; i < 6; i++)
        event->args[i] = in->args[i];

#pragma unroll
    for (int i = 0; i < MAX_STACK_DEPTH; i++)
         event->user_stack[i] = in->user_stack[i];

    bpf_perf_event_output(ctx,
                          &events,
                          BPF_F_CURRENT_CPU,
                          event,
                          sizeof(*event));

    bpf_map_delete_elem(&inflight, &pid_tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
