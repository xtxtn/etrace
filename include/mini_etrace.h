#ifndef __MINI_STRACE_H
#define __MINI_STRACE_H

#include <linux/types.h>

#define COMM_LEN 16

#define MAX_SYSCALLS  512
#define SYSCALL_WORD_BITS   64
#define SYSCALL_BITMAP_WORDS (MAX_SYSCALLS / SYSCALL_WORD_BITS)

#define FILTER_NONE 0
#define FILTER_PID  1
#define FILTER_COMM 2
#define FILTER_SYS  1
#define FILTER_STACK 1

#define MAX_STACK_DEPTH 64

/*
 * 用户态写入 BPF 的过滤配置
 */
struct trace_config {
    __u32 filter_type;
    __u32 target_pid;
    __u32 syscall_filter_enabled;
    char target_comm[COMM_LEN];
};

/*
 * BPF 发送给用户态的 syscall event
 */
struct syscall_event {
    __u64 ts_ns;
    __u64 duration_ns;
    __u64 args[6];
    __s64 ret;
    __u64 user_stack[MAX_STACK_DEPTH];
    __s32 stack_size;
    /*
     * pid = TGID
     * tid = thread ID
     */
    __u32 pid;
    __u32 tid;

    __s32 syscall_id;
};

#endif
