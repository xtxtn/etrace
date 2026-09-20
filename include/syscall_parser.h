#ifndef ARM_SYSCALL_PARSER_H
#define ARM_SYSCALL_PARSER_H

#include <linux/types.h>
#include <stddef.h>
#include <sys/types.h>

#include "mini_etrace.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYSCALL_MAX_ARGS 6u
#define SYSCALL_TABLE_SIZE 473u /* Known syscall numbers 0..472; independent of filter bitmap. */

#if defined(__cplusplus)
static_assert(sizeof(struct syscall_event) == 88u + 8u * MAX_STACK_DEPTH,
              "mini_etrace.h syscall_event ABI mismatch");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct syscall_event) == 88u + 8u * MAX_STACK_DEPTH,
               "mini_etrace.h syscall_event ABI mismatch");
#endif

typedef struct syscall_entry {
    const char *name;
    __u8 nargs;       /* Number of raw syscall register slots. */
    __u8 abi_bits;    /* 64 for AArch64, 32 for ARM EABI. */
    __u16 reserved;
} syscall_entry_t;

/* Complete fixed-size tables. Unassigned slots have name == NULL. */
extern const syscall_entry_t syscall_tables_64[SYSCALL_TABLE_SIZE];
extern const syscall_entry_t syscall_tables_32[SYSCALL_TABLE_SIZE];

/* Return bytes copied, or a negative errno-style value. */
typedef ssize_t (*syscall_read_mem_fn)(void *opaque, __u32 pid,
                                       __u64 remote_addr,
                                       void *local, size_t len);

typedef struct syscall_memory_reader {
    syscall_read_mem_fn read;
    void *opaque;
} syscall_memory_reader_t;

typedef struct syscall_parse_options {
    size_t max_string;
    size_t max_buffer;
    size_t max_array;
    int dereference;
    int symbolic;
} syscall_parse_options_t;

typedef struct syscall_parser {
    syscall_parse_options_t opt;
    syscall_memory_reader_t reader;
} syscall_parser_t;

void syscall_parse_options_init(syscall_parse_options_t *options);
syscall_parser_t *syscall_parser_create(
    const syscall_parse_options_t *options,
    const syscall_memory_reader_t *reader);

/*
 * Required core API. The semantic inputs are exactly syscall_id, args and
 * syscall_table. It renders only entry arguments; pointer targets are not
 * dereferenced because no PID/reader is available in this form.
 *
 * snprintf semantics: return the complete length excluding NUL; a return
 * value >= dst_size means that output was truncated.
 */
int syscall_parse(__s32 syscall_id, __u64 args[SYSCALL_MAX_ARGS],
                  const syscall_entry_t syscall_table[SYSCALL_TABLE_SIZE],
                  char *dst, size_t dst_size);

/*
 * Full-event adapter. It uses pid, ret and duration from syscall_event and may
 * dereference pointer targets through parser's memory reader.
 */
int syscall_parse_event(
    syscall_parser_t *parser,
    struct syscall_event *event,
    const syscall_entry_t syscall_table[SYSCALL_TABLE_SIZE],
    char *dst, size_t dst_size);

const syscall_entry_t *syscall_table_lookup(
    __s32 syscall_id,
    const syscall_entry_t syscall_table[SYSCALL_TABLE_SIZE]);

__u64 syscall_normalize_arg(unsigned abi_bits, __u64 raw);
__s64 syscall_normalize_retval(unsigned abi_bits, __u64 raw);
int syscall_ret_is_error(__s64 retval);

/* process_vm_readv(2) reader for the full-event API. */
ssize_t syscall_process_vm_reader(void *opaque, __u32 pid,
                                  __u64 remote_addr,
                                  void *local, size_t len);

#ifdef __cplusplus
}
#endif

#endif
