#define _GNU_SOURCE
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/resource.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "blazesym.h"
#include "mini_etrace.h"
#include "syscall_parser.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

bool enable_32;

static volatile sig_atomic_t exiting;

static void sig_handler(int signo)
{
    (void)signo;
    exiting = 1;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK,
                     &rlim);
}

static struct blaze_symbolizer *symbolizer;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
	/* If we have an input address  we have a new symbol. */
	if (input_addr != 0) {
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u\n", code_info->file, code_info->line);
		} else {
			printf("\n");
		}
	} else {
		printf("%16s  %s", "", name);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
		} else {
			printf("[inlined]\n");
		}
	}
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_syms *syms;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};

		syms = blaze_symbolize_process_abs_addrs(symbolizer, &src,
		                                (const uintptr_t *)stack, stack_sz);
	}

	if (!syms) {
		printf("  failed to symbolize addresses: %s\n",
		        blaze_err_str(blaze_err_last()));
		for (i = 0; i < stack_sz; i++)
			printf("%016llx\n", (unsigned long long)stack[i]);
		return;
	}

	for (i = 0; i < stack_sz; i++) {
		if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &syms->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(inlined->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_syms_free(syms);
}


/*
 * syscall number -> syscall name
 */
static const char *syscall_name(int nr, const char *syscall_tables[], size_t count)
{
    const char *name;

    if (nr < 0)
        return NULL;

    if ((size_t)nr >= count)
        return NULL;

    name = syscall_tables[nr];

    if (!name)
        return NULL;

    return name;
}

static int syscall_filter_add(int map_fd, int syscall_id)
{
    __u32 key;
    __u32 bit;
    __u64 value = 0;

    if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS)
        return -EINVAL;

    key = (__u32)syscall_id / 64;
    bit = (__u32)syscall_id % 64;

    if (bpf_map_lookup_elem(map_fd, &key, &value) != 0) {
        return -errno;
    }

    value |= ((__u64)1 << bit);

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        return -errno;
    }

    return 0;
}

static int set_all_syscall(int map_fd){
    __u64 value = (__u64)-1;
    for(int i = 0; i < SYSCALL_BITMAP_WORDS; i++) {
        if (bpf_map_update_elem(map_fd, &i, &value, BPF_ANY) != 0) {
            return -errno;
        }
    }
    return 0;
}


/*
 * syscall name -> syscall number
*/
static int syscall_number(const char *name, const char* syscall_tables[], size_t count)
{
    size_t i;
    for (i = 0; i < count; i++) {
        const char *n = syscall_tables[i];

        if (!n)
            continue;

        if (!strcmp(n, name))
            return (int)i;
    }

    return -1;
}

static int parse_syscall_filter(int map_fd, const char *arg)
{
    char *buf;
    char *saveptr = NULL;
    char *token;
    int count = 0;

    if (!arg || !*arg)
        return -EINVAL;

    buf = strdup(arg);
    if (!buf)
        return -ENOMEM;

    token = strtok_r(buf, ",", &saveptr);

    while (token) {
        int nr;
        int ret;

        while (*token == ' ' || *token == '\t')
            token++;

        char *end;
        end = token + strlen(token);
        while (end > token &&
                (end[-1] == ' ' ||
                end[-1] == '\t'))
        {
            end--;
        }
        *end = '\0';

        if (*token == '\0') {
            token = strtok_r(NULL, ",", &saveptr);
            continue;
        }

        if (enable_32)
            nr = syscall_number(token,
                syscall_tables_32, ARRAY_SIZE(syscall_tables_32));
        else
            nr = syscall_number(token,
                syscall_tables_64, ARRAY_SIZE(syscall_tables_64));

        if (nr < 0) {
            fprintf(stderr,
                    "unknown syscall: %s\n",
                    token);

            free(buf);
            return -EINVAL;
        }

        ret = syscall_filter_add(map_fd, nr);

        if (ret < 0) {
            fprintf(stderr,
                    "failed to add syscall %s (%d): %s\n",
                    token,
                    nr,
                    strerror(-ret));

            free(buf);
            return ret;
        }

        printf("enable syscall: %-16s nr=%d\n", token, nr);
        count++;
        token = strtok_r(NULL, ",",  &saveptr);
    }

    free(buf);
    if (count == 0)
        return -EINVAL;

    return 0;
}

static void print_return_value(long long ret)
{
    if (ret < 0 &&
        ret >= -4095) {

        int err = (int)-ret;
        printf(" = -1 errno=%d (%s)",
               err,
               strerror(err));
    } else {
        printf(" = 0x%llx\n", ret);
    }
}
char line[4096];
syscall_parser_t *parser;
static void handle_event(void *ctx,
                         int cpu,
                         void *data,
                         __u32 data_sz)
{
    struct syscall_event *e = data;

    (void)ctx;
    (void)cpu;

    if (data_sz < sizeof(*e))
        return;
    // if (enable_32)
    //     name = syscall_name(e->syscall_id,
    //         syscall_tables_32, ARRAY_SIZE(syscall_tables_32));
    // else
    //     name = syscall_name(e->syscall_id,
    //         syscall_tables_64, ARRAY_SIZE(syscall_tables_64));

    // if (e->pid != e->tid) {
    //     printf("[%u:%u] ",e->pid, e->tid);
    // } else {
    //     printf("[%u] ", e->pid);
    // }

    // if (name) {
    //     printf("%s(", name);
    // } else {
    //     printf("syscall_%d(",e->syscall_id);
    // }

    // printf("0x%llx, "
    //        "0x%llx, "
    //        "0x%llx, "
    //        "0x%llx, "
    //        "0x%llx, "
    //        "0x%llx)",
    //        (unsigned long long)e->args[0],
    //        (unsigned long long)e->args[1],
    //        (unsigned long long)e->args[2],
    //        (unsigned long long)e->args[3],
    //        (unsigned long long)e->args[4],
    //        (unsigned long long)e->args[5]);

    // print_return_value((long long)e->ret);
    memset(line, 0, sizeof(line));

    syscall_parse_event(parser, e, syscall_tables_64, line, sizeof(line));
    puts(line);
    // puts("stack:");
    // int nr_frames = e->stack_size / sizeof(__u64);
    // for (int i = 0; i < nr_frames; i++) {
    //     printf("    0x%llx\n", e->user_stack[i]);
    // }
 //    if (e->stack_size > 0) {
	// 	printf("Userspace Stack:\n");
	// 	show_stack_trace(e->user_stack, e->stack_size / sizeof(__u64), e->pid);
	// } else {
	// 	printf("No Userspace Stack\n");
	// }


    fflush(stdout);
}


static void handle_lost(void *ctx,
                        int cpu,
                        __u64 lost_cnt)
{
    (void)ctx;
    fprintf(stderr,
            "lost %llu events on CPU %d\n",
            (unsigned long long)lost_cnt,
            cpu);
}

/*
 * libbpf log
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{

    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}


static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s -p <pid>\n"
            "  %s -c <comm>\n"
            "\n"
            "Options:\n"
            "  -p <pid>   trace process by PID/TGID\n"
            "  -c <comm>  trace process by task comm\n"
            "  -e <syscall0>,<syscall1>  trace only specified syscalls\n"
            "  -h         show this help\n"
            "\n"
            "Examples:\n"
            "  %s -p 1234\n"
            "  %s -c nginx -e read,write\n",
            prog,
            prog,
            prog,
            prog);
}


int main(int argc, char **argv)
{
    struct trace_config config = {};
    char *syscall_filter_arg = NULL;

    struct bpf_object *obj = NULL;

    struct bpf_program *prog_enter;
    struct bpf_program *prog_exit;

    struct bpf_link *link_enter = NULL;
    struct bpf_link *link_exit = NULL;

    struct perf_buffer *pb = NULL;

    struct perf_buffer_opts pb_opts = {};

    bool have_pid = false;
    bool have_comm = false;

    __u32 key = 0;

    int config_fd;
    int events_fd;

    int opt;
    int err = 0;

    while ((opt = getopt(argc, argv, "p:c:e:t:h")) != -1) {
        switch (opt) {
        case 'p': {
            char *end = NULL;
            long pid;

            errno = 0;
            pid = strtol(optarg, &end, 10);
            if (errno != 0 ||
                end == optarg ||
                *end != '\0' ||
                pid <= 0 ||
                pid > 0x7fffffffL) {

                fprintf(stderr,
                        "invalid pid: %s\n",
                        optarg);

                return 1;
            }

            config.filter_type = FILTER_PID;
            config.target_pid =  (__u32)pid;
            have_pid = true;

            break;
        }

        case 'c':
            config.filter_type = FILTER_COMM;
            memset(config.target_comm,  0, sizeof(config.target_comm));

            if (strlen(optarg) >= COMM_LEN) {
                fprintf(stderr,
                        "warning: comm \"%s\" is longer "
                        "than %d characters; truncated\n",
                        optarg,
                        COMM_LEN - 1);
                if (!strncmp(optarg, "com.", 4))
                    strncpy(config.target_comm,
                            optarg + strlen(optarg) - (COMM_LEN - 1),
                            COMM_LEN - 1);
                else
                    strncpy(config.target_comm, optarg, COMM_LEN - 1);
            }
            else {
                strcpy(config.target_comm, optarg);
            }

            have_comm = true;
            break;

        case 'e':
            config.syscall_filter_enabled = FILTER_SYS;
            syscall_filter_arg = optarg;
            break;

        case 't':
            if (!strncmp(optarg, "32", 2))
                enable_32 = 1;
            break;

        case 'h':
            usage(argv[0]);
            return 0;

        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (have_pid == have_comm) {
        fprintf(stderr,
                "exactly one of -p or -c "
                "must be specified\n\n");
        usage(argv[0]);
        return 1;
    }

    if (optind != argc) {

        fprintf(stderr,
                "unexpected argument: %s\n\n",
                argv[optind]);

        usage(argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    if (bump_memlock_rlimit()) {
        fprintf(stderr,
                "failed to increase RLIMIT_MEMLOCK: %s\n",
                strerror(errno));

        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file("mini_etrace.bpf.o", NULL);
    err = libbpf_get_error(obj);
    if (err) {
        obj = NULL;
        fprintf(stderr,
                "failed to open BPF object: %s\n",
                strerror(-err));

        goto cleanup;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr,
                "failed to load BPF object: %s (%d)\n",
                strerror(-err),
                err);

        goto cleanup;
    }

    config_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    if (config_fd < 0) {
        fprintf(stderr,
                "cannot find config_map\n");
        err = config_fd;
        goto cleanup;
    }

    if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY)) {

        err = -errno;
        fprintf(stderr,
                "failed to update config_map: %s\n",
                strerror(errno));

        goto cleanup;
    }

    int  syscall_map_fd = bpf_object__find_map_fd_by_name(obj, "syscall_bitmap");

    if (syscall_map_fd < 0) {
        fprintf(stderr,
                "cannot find syscall_bitmap map\n");
        err = syscall_map_fd;
        goto cleanup;
    }

    if (config.syscall_filter_enabled){
        err = parse_syscall_filter(syscall_map_fd, syscall_filter_arg);
            if (err < 0)
                goto cleanup;
    }
    else {
        err = set_all_syscall(syscall_map_fd);
        if (err < 0)
            goto cleanup;
    }

    prog_enter = bpf_object__find_program_by_name(obj, "trace_enter");
    if (!prog_enter) {
        fprintf(stderr,
                "cannot find trace_enter program\n");
        err = -ENOENT;
        goto cleanup;
    }

    link_enter = bpf_program__attach_tracepoint(prog_enter, "raw_syscalls", "sys_enter");
    err = libbpf_get_error(link_enter);
    if (err) {
        link_enter = NULL;
        fprintf(stderr,
                "failed to attach "
                "raw_syscalls:sys_enter: %s\n",
                strerror(-err));

        goto cleanup;
    }

    prog_exit = bpf_object__find_program_by_name(obj, "trace_exit");
    if (!prog_exit) {
        fprintf(stderr,
                "cannot find trace_exit program\n");

        err = -ENOENT;
        goto cleanup;
    }

    link_exit = bpf_program__attach_tracepoint(prog_exit,
        "raw_syscalls", "sys_exit");

    err = libbpf_get_error(link_exit);
    if (err) {
        link_exit = NULL;
        fprintf(stderr,
                "failed to attach "
                "raw_syscalls:sys_exit: %s\n",
                strerror(-err));
        goto cleanup;
    }

    events_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (events_fd < 0) {
        fprintf(stderr,
                "cannot find events map\n");

        err = events_fd;
        goto cleanup;
    }

    symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

    syscall_memory_reader_t reader = {
        .read = syscall_process_vm_reader,
        .opaque = NULL,
    };
    parser = calloc(1, sizeof(syscall_parser_t));
    parser->opt.max_string = 256;
    parser->opt.max_buffer = 64;
    parser->opt.max_array = 16;
    parser->opt.dereference = 1;
    parser->opt.symbolic = 1;
    parser->reader = reader;

    /*
     * libbpf 0.5 API。
     */
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost;
    pb_opts.ctx = NULL;

    pb = perf_buffer__new(events_fd, 8, &pb_opts);

    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;

        fprintf(stderr,
                "failed to create perf buffer: %s\n",
                strerror(-err));

        goto cleanup;
    }


    if (config.filter_type == FILTER_PID) {
        printf("Tracing PID %u and all its threads...\n",
               config.target_pid);
    } else {
        printf("Tracing comm=\"%s\"...\n", config.target_comm);
    }

    printf("Press Ctrl-C to stop.\n\n");

    while (!exiting) {

        err = perf_buffer__poll(pb, 100);

        if (err < 0 && err != -EINTR) {
            fprintf(stderr,
                    "perf_buffer__poll failed: %d\n",
                    err);
            break;
        }

        /*
         * SIGINT 导致 EINTR 不算程序错误
         */
        if (err == -EINTR)
            err = 0;
    }


cleanup:

    perf_buffer__free(pb);
    bpf_link__destroy(link_exit);
    bpf_link__destroy(link_enter);
    bpf_object__close(obj);

    return err != 0;
}
