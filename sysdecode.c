#define _GNU_SOURCE
#include "syscall_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

typedef enum sd_abi {
    SD_ABI_ARM64 = 1,
    SD_ABI_ARM_EABI = 2
} sd_abi_t;


typedef struct sd_event {
    sd_abi_t abi;
    uint32_t nr;
    uint32_t pid;
    uint32_t tid;
    uint64_t args[SYSCALL_MAX_ARGS];
    int64_t retval;
    uint64_t timestamp_ns;
    uint64_t duration_ns;
} sd_event_t;

typedef syscall_parse_options_t sd_options_t;
typedef syscall_memory_reader_t sd_reader_t;
typedef syscall_parser_t sd_decoder_t;

#define SYSDECODE_MAX_ARGS SYSCALL_MAX_ARGS

static uint64_t sd_normalize_arg(sd_abi_t abi, uint64_t raw);
static int64_t sd_normalize_retval(sd_abi_t abi, uint64_t raw);
static int sd_is_linux_error(int64_t retval);

struct out {
    char *buf;
    size_t cap;
    size_t len;
};

static void
out_vprintf(struct out *o, const char *fmt, va_list ap)
{
    va_list copy;
    int n;
    size_t avail = o->len < o->cap ? o->cap - o->len : 0;
    char *dst = avail ? o->buf + o->len : NULL;

    va_copy(copy, ap);
    n = vsnprintf(dst, avail, fmt, copy);
    va_end(copy);
    if (n > 0)
        o->len += (size_t)n;
}

static void
out_printf(struct out *o, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    out_vprintf(o, fmt, ap);
    va_end(ap);
}

static uint64_t
ptr_value(sd_abi_t abi, uint64_t value)
{
    return abi == SD_ABI_ARM_EABI ? (uint32_t)value : value;
}

static uint64_t
read_addr(sd_abi_t abi, uint64_t value)
{
    value = ptr_value(abi, value);
    /* Strip only the AArch64 top-byte tag for memory inspection. */
    return abi == SD_ABI_ARM64 ? value & UINT64_C(0x00ffffffffffffff) : value;
}

static int
can_read(const sd_decoder_t *d)
{
    return d->opt.dereference && d->reader.read;
}

static ssize_t
read_mem(const sd_decoder_t *d, const sd_event_t *ev, uint64_t addr,
         void *buf, size_t size)
{
    if (!can_read(d) || !addr)
        return -EFAULT;
    return d->reader.read(d->reader.opaque, ev->pid,
                          read_addr(ev->abi, addr), buf, size);
}

static void
print_ptr(struct out *o, sd_abi_t abi, uint64_t value)
{
    value = ptr_value(abi, value);
    if (!value)
        out_printf(o, "NULL");
    else
        out_printf(o, "0x%" PRIx64, value);
}

static void
print_quoted(struct out *o, const unsigned char *p, size_t n, int ellipsis)
{
    size_t i;
    out_printf(o, "\"");
    for (i = 0; i < n; ++i) {
        unsigned c = p[i];
        switch (c) {
        case '\\': out_printf(o, "\\\\"); break;
        case '"': out_printf(o, "\\\""); break;
        case '\n': out_printf(o, "\\n"); break;
        case '\r': out_printf(o, "\\r"); break;
        case '\t': out_printf(o, "\\t"); break;
        default:
            if (c >= 0x20 && c < 0x7f)
                out_printf(o, "%c", c);
            else
                out_printf(o, "\\x%02x", c);
        }
    }
    out_printf(o, "\"");
    if (ellipsis)
        out_printf(o, "...");
}

static void
print_cstring(sd_decoder_t *d, const sd_event_t *ev, struct out *o,
              uint64_t addr)
{
    unsigned char *buf;
    size_t max, used = 0;
    int terminated = 0;

    if (!addr) {
        out_printf(o, "NULL");
        return;
    }
    if (!can_read(d)) {
        print_ptr(o, ev->abi, addr);
        return;
    }
    max = d->opt.max_string ? d->opt.max_string : 1;
    buf = malloc(max);
    if (!buf) {
        print_ptr(o, ev->abi, addr);
        return;
    }
    while (used < max) {
        size_t chunk = max - used > 32 ? 32 : max - used;
        ssize_t got = read_mem(d, ev, addr + used, buf + used, chunk);
        size_t i;
        if (got <= 0)
            break;
        for (i = 0; i < (size_t)got; ++i) {
            if (buf[used + i] == '\0') {
                used += i;
                terminated = 1;
                goto done;
            }
        }
        used += (size_t)got;
        if ((size_t)got < chunk)
            break;
    }
done:
    if (!used && !terminated) {
        print_ptr(o, ev->abi, addr);
        out_printf(o, " /* unreadable */");
    } else {
        print_quoted(o, buf, used, !terminated);
    }
    free(buf);
}

static void
print_buffer(sd_decoder_t *d, const sd_event_t *ev, struct out *o,
             uint64_t addr, uint64_t requested)
{
    unsigned char *buf;
    size_t want, got;

    if (!addr) {
        out_printf(o, "NULL");
        return;
    }
    if (!can_read(d)) {
        print_ptr(o, ev->abi, addr);
        return;
    }
    want = requested > d->opt.max_buffer ? d->opt.max_buffer : (size_t)requested;
    if (!want) {
        out_printf(o, "\"\"");
        return;
    }
    buf = malloc(want);
    if (!buf) {
        print_ptr(o, ev->abi, addr);
        return;
    }
    {
        ssize_t n = read_mem(d, ev, addr, buf, want);
        got = n > 0 ? (size_t)n : 0;
    }
    if (!got) {
        print_ptr(o, ev->abi, addr);
        out_printf(o, " /* unreadable */");
    } else {
        print_quoted(o, buf, got, requested > got);
    }
    free(buf);
}

struct flag_name { uint64_t value; const char *name; };

static const struct flag_name open_flags[] = {
    { O_WRONLY, "O_WRONLY" }, { O_RDWR, "O_RDWR" },
    { O_CREAT, "O_CREAT" }, { O_EXCL, "O_EXCL" },
    { O_TRUNC, "O_TRUNC" }, { O_APPEND, "O_APPEND" },
    { O_NONBLOCK, "O_NONBLOCK" }, { O_CLOEXEC, "O_CLOEXEC" },
#ifdef O_DIRECTORY
    { O_DIRECTORY, "O_DIRECTORY" },
#endif
#ifdef O_NOFOLLOW
    { O_NOFOLLOW, "O_NOFOLLOW" },
#endif
#ifdef O_PATH
    { O_PATH, "O_PATH" },
#endif
};

static const struct flag_name prot_flags[] = {
    { PROT_READ, "PROT_READ" }, { PROT_WRITE, "PROT_WRITE" },
    { PROT_EXEC, "PROT_EXEC" },
#ifdef PROT_GROWSDOWN
    { PROT_GROWSDOWN, "PROT_GROWSDOWN" },
#endif
};

static const struct flag_name map_flags[] = {
    { MAP_SHARED, "MAP_SHARED" }, { MAP_PRIVATE, "MAP_PRIVATE" },
#ifdef MAP_FIXED
    { MAP_FIXED, "MAP_FIXED" },
#endif
#ifdef MAP_ANONYMOUS
    { MAP_ANONYMOUS, "MAP_ANONYMOUS" },
#endif
#ifdef MAP_POPULATE
    { MAP_POPULATE, "MAP_POPULATE" },
#endif
#ifdef MAP_STACK
    { MAP_STACK, "MAP_STACK" },
#endif
};

static void
print_flags(struct out *o, uint64_t value, const struct flag_name *table,
            size_t count, int symbolic, const char *zero)
{
    size_t i;
    uint64_t rest = value;
    int any = 0;
    if (!symbolic) {
        out_printf(o, "0x%" PRIx64, value);
        return;
    }
    if (!value && zero) {
        out_printf(o, "%s", zero);
        return;
    }
    for (i = 0; i < count; ++i) {
        if (table[i].value && (rest & table[i].value) == table[i].value) {
            out_printf(o, "%s%s", any ? "|" : "", table[i].name);
            rest &= ~table[i].value;
            any = 1;
        }
    }
    if (rest || !any)
        out_printf(o, "%s0x%" PRIx64, any ? "|" : "", rest);
}

static void
print_open_flags(struct out *o, uint64_t value, int symbolic)
{
    unsigned access = (unsigned)value & O_ACCMODE;
    const char *access_name = access == O_RDONLY ? "O_RDONLY" :
                              access == O_WRONLY ? "O_WRONLY" :
                              access == O_RDWR ? "O_RDWR" : NULL;
    uint64_t rest = value & ~(uint64_t)O_ACCMODE;
    size_t i;
    if (!symbolic) {
        out_printf(o, "0x%" PRIx64, value);
        return;
    }
    if (access_name)
        out_printf(o, "%s", access_name);
    else
        out_printf(o, "0x%x", access);
    for (i = 0; i < sizeof(open_flags) / sizeof(open_flags[0]); ++i) {
        if ((open_flags[i].value & O_ACCMODE) || !open_flags[i].value)
            continue;
        if ((rest & open_flags[i].value) == open_flags[i].value) {
            out_printf(o, "|%s", open_flags[i].name);
            rest &= ~open_flags[i].value;
        }
    }
    if (rest)
        out_printf(o, "|0x%" PRIx64, rest);
}

static const char *
signal_name(unsigned sig)
{
    switch (sig) {
    case SIGHUP: return "SIGHUP"; case SIGINT: return "SIGINT";
    case SIGQUIT: return "SIGQUIT"; case SIGILL: return "SIGILL";
    case SIGABRT: return "SIGABRT"; case SIGFPE: return "SIGFPE";
    case SIGKILL: return "SIGKILL"; case SIGSEGV: return "SIGSEGV";
    case SIGPIPE: return "SIGPIPE"; case SIGALRM: return "SIGALRM";
    case SIGTERM: return "SIGTERM"; case SIGCHLD: return "SIGCHLD";
    case SIGCONT: return "SIGCONT"; case SIGSTOP: return "SIGSTOP";
    case SIGTSTP: return "SIGTSTP"; case SIGTTIN: return "SIGTTIN";
    case SIGTTOU: return "SIGTTOU"; default: return NULL;
    }
}

static void
print_signal(struct out *o, uint64_t value, int symbolic)
{
    const char *name = signal_name((unsigned)value);
    if (symbolic && name)
        out_printf(o, "%s", name);
    else
        out_printf(o, "%" PRIu64, value);
}

static void
print_sockaddr(sd_decoder_t *d, const sd_event_t *ev, struct out *o,
               uint64_t addr, size_t supplied_len)
{
    unsigned char raw[sizeof(struct sockaddr_storage)];
    size_t want = supplied_len < sizeof(raw) ? supplied_len : sizeof(raw);
    ssize_t n;
    uint16_t family;

    if (!addr || !can_read(d) || want < sizeof(family)) {
        print_ptr(o, ev->abi, addr);
        return;
    }
    n = read_mem(d, ev, addr, raw, want);
    if (n < (ssize_t)sizeof(family)) {
        print_ptr(o, ev->abi, addr);
        out_printf(o, " /* unreadable sockaddr */");
        return;
    }
    memcpy(&family, raw, sizeof(family));
    if (family == AF_INET && n >= (ssize_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)raw;
        char ip[INET_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        out_printf(o, "{sa_family=AF_INET, sin_port=htons(%u), sin_addr=\"%s\"}",
                   ntohs(sin->sin_port), ip);
    } else if (family == AF_INET6 && n >= (ssize_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)raw;
        char ip[INET6_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        out_printf(o, "{sa_family=AF_INET6, sin6_port=htons(%u), sin6_addr=\"%s\"}",
                   ntohs(sin6->sin6_port), ip);
    } else if (family == AF_UNIX && n > (ssize_t)offsetof(struct sockaddr_un, sun_path)) {
        const struct sockaddr_un *sun = (const struct sockaddr_un *)raw;
        size_t base = offsetof(struct sockaddr_un, sun_path);
        size_t len = (size_t)n - base;
        while (len && sun->sun_path[len - 1] == '\0') --len;
        out_printf(o, "{sa_family=AF_UNIX, sun_path=");
        if (len && sun->sun_path[0] == '\0') {
            out_printf(o, "@");
            print_quoted(o, (const unsigned char *)sun->sun_path + 1, len - 1, 0);
        } else {
            print_quoted(o, (const unsigned char *)sun->sun_path, len, 0);
        }
        out_printf(o, "}");
    } else {
        out_printf(o, "{sa_family=%u, ...}", family);
    }
}

static void
print_timespec(sd_decoder_t *d, const sd_event_t *ev, struct out *o,
               uint64_t addr, int time64)
{
    if (!addr) { out_printf(o, "NULL"); return; }
    if (ev->abi == SD_ABI_ARM64 || time64) {
        int64_t ts[2];
        if (read_mem(d, ev, addr, ts, sizeof(ts)) == (ssize_t)sizeof(ts))
            out_printf(o, "{tv_sec=%" PRId64 ", tv_nsec=%" PRId64 "}", ts[0], ts[1]);
        else
            print_ptr(o, ev->abi, addr);
    } else {
        int32_t ts[2];
        if (read_mem(d, ev, addr, ts, sizeof(ts)) == (ssize_t)sizeof(ts))
            out_printf(o, "{tv_sec=%" PRId32 ", tv_nsec=%" PRId32 "}", ts[0], ts[1]);
        else
            print_ptr(o, ev->abi, addr);
    }
}

static void
print_strv(sd_decoder_t *d, const sd_event_t *ev, struct out *o, uint64_t addr)
{
    size_t width = ev->abi == SD_ABI_ARM64 ? 8 : 4;
    size_t i;
    if (!addr) { out_printf(o, "NULL"); return; }
    if (!can_read(d)) { print_ptr(o, ev->abi, addr); return; }
    out_printf(o, "[");
    for (i = 0; i < d->opt.max_array; ++i) {
        uint64_t p = 0;
        ssize_t n = read_mem(d, ev, addr + i * width, &p, width);
        if (n != (ssize_t)width) {
            out_printf(o, "%s... /* unreadable */", i ? ", " : "");
            break;
        }
        p = ptr_value(ev->abi, p);
        if (!p)
            break;
        if (i) out_printf(o, ", ");
        print_cstring(d, ev, o, p);
    }
    if (i == d->opt.max_array)
        out_printf(o, ", ...");
    out_printf(o, "]");
}

static void
print_iov(sd_decoder_t *d, const sd_event_t *ev, struct out *o,
          uint64_t addr, size_t count, int show_data, uint64_t total_limit)
{
    size_t i, width = ev->abi == SD_ABI_ARM64 ? 8 : 4;
    size_t item_size = width * 2;
    if (!addr || !can_read(d)) { print_ptr(o, ev->abi, addr); return; }
    out_printf(o, "[");
    if (count > d->opt.max_array) count = d->opt.max_array;
    for (i = 0; i < count; ++i) {
        unsigned char raw[16] = {0};
        uint64_t base = 0, len = 0, shown;
        if (read_mem(d, ev, addr + i * item_size, raw, item_size) != (ssize_t)item_size) {
            out_printf(o, "%s... /* unreadable */", i ? ", " : "");
            break;
        }
        memcpy(&base, raw, width);
        memcpy(&len, raw + width, width);
        base = ptr_value(ev->abi, base); len = ptr_value(ev->abi, len);
        if (i) out_printf(o, ", ");
        out_printf(o, "{iov_base=");
        shown = len < total_limit ? len : total_limit;
        if (show_data) print_buffer(d, ev, o, base, shown); else print_ptr(o, ev->abi, base);
        out_printf(o, ", iov_len=%" PRIu64 "}", len);
        if (total_limit > shown) total_limit -= shown; else total_limit = 0;
    }
    out_printf(o, "]");
}

enum arg_kind {
    A_HEX, A_INT, A_UINT, A_FD, A_PID, A_PTR, A_STR, A_PATH, A_STRV,
    A_SIZE, A_MODE, A_OPEN, A_PROT, A_MAP, A_SIG, A_BUF_IN, A_BUF_OUT,
    A_SOCKADDR, A_TIMESPEC, A_TIME64, A_TIMESPEC_OUT, A_TIME64_OUT,
    A_IOV_IN, A_IOV_OUT
};

struct arg_desc { enum arg_kind kind; int8_t aux; };
struct call_desc { const char *name; uint8_t nargs; struct arg_desc arg[6]; };
#define AD(k) { k, -1 }
#define AL(k, n) { k, n }
#define CALL(n, c, ...) { n, c, { __VA_ARGS__ } }

static const struct call_desc calls[] = {
    CALL("read",3, AD(A_FD),AL(A_BUF_OUT,2),AD(A_SIZE)),
    CALL("write",3,AD(A_FD),AL(A_BUF_IN,2),AD(A_SIZE)),
    CALL("pread64",4,AD(A_FD),AL(A_BUF_OUT,2),AD(A_SIZE),AD(A_HEX)),
    CALL("pwrite64",4,AD(A_FD),AL(A_BUF_IN,2),AD(A_SIZE),AD(A_HEX)),
    CALL("readv",3,AD(A_FD),AL(A_IOV_OUT,2),AD(A_UINT)),
    CALL("writev",3,AD(A_FD),AL(A_IOV_IN,2),AD(A_UINT)),
    CALL("open",3,AD(A_PATH),AD(A_OPEN),AD(A_MODE)),
    CALL("openat",4,AD(A_FD),AD(A_PATH),AD(A_OPEN),AD(A_MODE)),
    CALL("creat",2,AD(A_PATH),AD(A_MODE)),
    CALL("close",1,AD(A_FD)), CALL("dup",1,AD(A_FD)),
    CALL("dup2",2,AD(A_FD),AD(A_FD)), CALL("dup3",3,AD(A_FD),AD(A_FD),AD(A_HEX)),
    CALL("lseek",3,AD(A_FD),AD(A_INT),AD(A_UINT)),
    CALL("access",2,AD(A_PATH),AD(A_HEX)), CALL("faccessat",3,AD(A_FD),AD(A_PATH),AD(A_HEX)),
    CALL("faccessat2",4,AD(A_FD),AD(A_PATH),AD(A_HEX),AD(A_HEX)),
    CALL("chdir",1,AD(A_PATH)), CALL("chroot",1,AD(A_PATH)), CALL("fchdir",1,AD(A_FD)),
    CALL("mkdir",2,AD(A_PATH),AD(A_MODE)), CALL("mkdirat",3,AD(A_FD),AD(A_PATH),AD(A_MODE)),
    CALL("rmdir",1,AD(A_PATH)), CALL("unlink",1,AD(A_PATH)),
    CALL("unlinkat",3,AD(A_FD),AD(A_PATH),AD(A_HEX)),
    CALL("rename",2,AD(A_PATH),AD(A_PATH)),
    CALL("renameat",4,AD(A_FD),AD(A_PATH),AD(A_FD),AD(A_PATH)),
    CALL("renameat2",5,AD(A_FD),AD(A_PATH),AD(A_FD),AD(A_PATH),AD(A_HEX)),
    CALL("link",2,AD(A_PATH),AD(A_PATH)), CALL("symlink",2,AD(A_PATH),AD(A_PATH)),
    CALL("readlink",3,AD(A_PATH),AL(A_BUF_OUT,2),AD(A_SIZE)),
    CALL("readlinkat",4,AD(A_FD),AD(A_PATH),AL(A_BUF_OUT,3),AD(A_SIZE)),
    CALL("chmod",2,AD(A_PATH),AD(A_MODE)), CALL("fchmod",2,AD(A_FD),AD(A_MODE)),
    CALL("fchmodat",3,AD(A_FD),AD(A_PATH),AD(A_MODE)),
    CALL("truncate",2,AD(A_PATH),AD(A_SIZE)), CALL("ftruncate",2,AD(A_FD),AD(A_SIZE)),
    CALL("stat",2,AD(A_PATH),AD(A_PTR)), CALL("lstat",2,AD(A_PATH),AD(A_PTR)),
    CALL("fstat",2,AD(A_FD),AD(A_PTR)), CALL("newfstatat",4,AD(A_FD),AD(A_PATH),AD(A_PTR),AD(A_HEX)),
    CALL("statx",5,AD(A_FD),AD(A_PATH),AD(A_HEX),AD(A_HEX),AD(A_PTR)),
    CALL("getcwd",2,AL(A_BUF_OUT,1),AD(A_SIZE)),
    CALL("execve",3,AD(A_PATH),AD(A_STRV),AD(A_STRV)),
    CALL("execveat",5,AD(A_FD),AD(A_PATH),AD(A_STRV),AD(A_STRV),AD(A_HEX)),
    CALL("exit",1,AD(A_INT)), CALL("exit_group",1,AD(A_INT)),
    CALL("kill",2,AD(A_PID),AD(A_SIG)), CALL("tgkill",3,AD(A_PID),AD(A_PID),AD(A_SIG)),
    CALL("tkill",2,AD(A_PID),AD(A_SIG)), CALL("wait4",4,AD(A_PID),AD(A_PTR),AD(A_HEX),AD(A_PTR)),
    CALL("mmap",6,AD(A_PTR),AD(A_SIZE),AD(A_PROT),AD(A_MAP),AD(A_FD),AD(A_HEX)),
    CALL("mmap2",6,AD(A_PTR),AD(A_SIZE),AD(A_PROT),AD(A_MAP),AD(A_FD),AD(A_HEX)),
    CALL("munmap",2,AD(A_PTR),AD(A_SIZE)), CALL("mprotect",3,AD(A_PTR),AD(A_SIZE),AD(A_PROT)),
    CALL("madvise",3,AD(A_PTR),AD(A_SIZE),AD(A_INT)), CALL("brk",1,AD(A_PTR)),
    CALL("socket",3,AD(A_INT),AD(A_HEX),AD(A_INT)),
    CALL("bind",3,AD(A_FD),AL(A_SOCKADDR,2),AD(A_SIZE)),
    CALL("connect",3,AD(A_FD),AL(A_SOCKADDR,2),AD(A_SIZE)),
    CALL("listen",2,AD(A_FD),AD(A_INT)),
    CALL("accept",3,AD(A_FD),AD(A_PTR),AD(A_PTR)), CALL("accept4",4,AD(A_FD),AD(A_PTR),AD(A_PTR),AD(A_HEX)),
    CALL("sendto",6,AD(A_FD),AL(A_BUF_IN,2),AD(A_SIZE),AD(A_HEX),AL(A_SOCKADDR,5),AD(A_SIZE)),
    CALL("recvfrom",6,AD(A_FD),AL(A_BUF_OUT,2),AD(A_SIZE),AD(A_HEX),AD(A_PTR),AD(A_PTR)),
    CALL("sendmsg",3,AD(A_FD),AD(A_PTR),AD(A_HEX)), CALL("recvmsg",3,AD(A_FD),AD(A_PTR),AD(A_HEX)),
    CALL("shutdown",2,AD(A_FD),AD(A_INT)),
    CALL("getsockname",3,AD(A_FD),AD(A_PTR),AD(A_PTR)), CALL("getpeername",3,AD(A_FD),AD(A_PTR),AD(A_PTR)),
    CALL("setsockopt",5,AD(A_FD),AD(A_INT),AD(A_INT),AD(A_PTR),AD(A_SIZE)),
    CALL("getsockopt",5,AD(A_FD),AD(A_INT),AD(A_INT),AD(A_PTR),AD(A_PTR)),
    CALL("pipe",1,AD(A_PTR)), CALL("pipe2",2,AD(A_PTR),AD(A_HEX)),
    CALL("eventfd2",2,AD(A_UINT),AD(A_HEX)), CALL("epoll_create1",1,AD(A_HEX)),
    CALL("epoll_ctl",4,AD(A_FD),AD(A_INT),AD(A_FD),AD(A_PTR)),
    CALL("nanosleep",2,AD(A_TIMESPEC),AD(A_PTR)),
    CALL("clock_nanosleep",4,AD(A_INT),AD(A_HEX),AD(A_TIMESPEC),AD(A_PTR)),
    CALL("clock_gettime",2,AD(A_INT),AD(A_TIMESPEC_OUT)), CALL("clock_settime",2,AD(A_INT),AD(A_TIMESPEC)),
    CALL("clock_gettime64",2,AD(A_INT),AD(A_TIME64_OUT)), CALL("clock_settime64",2,AD(A_INT),AD(A_TIME64)),
    CALL("getrandom",3,AL(A_BUF_OUT,1),AD(A_SIZE),AD(A_HEX)),
    CALL("memfd_create",2,AD(A_STR),AD(A_HEX)),
    CALL("prctl",5,AD(A_INT),AD(A_HEX),AD(A_HEX),AD(A_HEX),AD(A_HEX)),
    CALL("seccomp",3,AD(A_UINT),AD(A_HEX),AD(A_PTR)),
    CALL("mount",5,AD(A_STR),AD(A_PATH),AD(A_STR),AD(A_HEX),AD(A_PTR)),
    CALL("umount2",2,AD(A_PATH),AD(A_HEX)),
    CALL("setxattr",5,AD(A_PATH),AD(A_STR),AL(A_BUF_IN,3),AD(A_SIZE),AD(A_HEX)),
    CALL("getxattr",4,AD(A_PATH),AD(A_STR),AL(A_BUF_OUT,3),AD(A_SIZE)),
    CALL("listxattr",3,AD(A_PATH),AL(A_BUF_OUT,2),AD(A_SIZE)),
    CALL("removexattr",2,AD(A_PATH),AD(A_STR)),
    CALL("inotify_add_watch",3,AD(A_FD),AD(A_PATH),AD(A_HEX)),
    CALL("inotify_rm_watch",2,AD(A_FD),AD(A_INT)),
};

static const struct call_desc *
find_call(const char *name)
{
    size_t i;
    for (i = 0; i < sizeof(calls) / sizeof(calls[0]); ++i)
        if (!strcmp(calls[i].name, name)) return &calls[i];
    return NULL;
}

static uint64_t
buffer_count(const sd_event_t *ev, int arg_index, int output)
{
    uint64_t requested = arg_index >= 0 ? ev->args[arg_index] : 0;
    if (output  && !sd_is_linux_error(ev->retval)) {
        uint64_t returned = ev->retval > 0 ? (uint64_t)ev->retval : 0;
        return returned < requested ? returned : requested;
    }
    return requested;
}

static void
print_arg(sd_decoder_t *d, const sd_event_t *ev, struct out *o,
          struct arg_desc desc, uint64_t value, const char *call_name)
{
    switch (desc.kind) {
    case A_INT: out_printf(o, "%" PRId64, ev->abi == SD_ABI_ARM_EABI ? (int64_t)(int32_t)value : (int64_t)value); break;
    case A_UINT: case A_SIZE: out_printf(o, "%" PRIu64, sd_normalize_arg(ev->abi, value)); break;
    case A_FD: case A_PID: out_printf(o, "%" PRId64, ev->abi == SD_ABI_ARM_EABI ? (int64_t)(int32_t)value : (int64_t)value); break;
    case A_PTR: print_ptr(o, ev->abi, value); break;
    case A_STR: case A_PATH: print_cstring(d, ev, o, value); break;
    case A_STRV: print_strv(d, ev, o, value); break;
    case A_MODE: out_printf(o, "0%llo", (unsigned long long)(value & 07777)); break;
    case A_OPEN: print_open_flags(o, value, d->opt.symbolic); break;
    case A_PROT: print_flags(o, value, prot_flags, sizeof(prot_flags)/sizeof(prot_flags[0]), d->opt.symbolic, "PROT_NONE"); break;
    case A_MAP: print_flags(o, value, map_flags, sizeof(map_flags)/sizeof(map_flags[0]), d->opt.symbolic, NULL); break;
    case A_SIG: print_signal(o, value, d->opt.symbolic); break;
    case A_BUF_IN: print_buffer(d, ev, o, value, buffer_count(ev, desc.aux, 0)); break;
    case A_BUF_OUT:
        if (!sd_is_linux_error(ev->retval))
            print_buffer(d, ev, o, value, buffer_count(ev, desc.aux, 1));
        else
            print_ptr(o, ev->abi, value);
        break;
    case A_SOCKADDR: print_sockaddr(d, ev, o, value, (size_t)ev->args[desc.aux]); break;
    case A_TIMESPEC: print_timespec(d, ev, o, value, 0); break;
    case A_TIME64: print_timespec(d, ev, o, value, 1); break;
    case A_TIMESPEC_OUT:
        if (!sd_is_linux_error(ev->retval)) print_timespec(d, ev, o, value, 0);
        else print_ptr(o, ev->abi, value);
        break;
    case A_TIME64_OUT:
        if (!sd_is_linux_error(ev->retval)) print_timespec(d, ev, o, value, 1);
        else print_ptr(o, ev->abi, value);
        break;
    case A_IOV_IN: print_iov(d, ev, o, value, (size_t)ev->args[desc.aux], 1, d->opt.max_buffer); break;
    case A_IOV_OUT:
        print_iov(d, ev, o, value, (size_t)ev->args[desc.aux],
                  !sd_is_linux_error(ev->retval),
                  ev->retval > 0 ? (uint64_t)ev->retval : 0);
        break;
    case A_HEX: default: out_printf(o, "0x%" PRIx64, sd_normalize_arg(ev->abi, value)); break;
    }
    (void)call_name;
}

static void
print_ioctl(struct out *o, const sd_event_t *ev)
{
    uint64_t req = sd_normalize_arg(ev->abi, ev->args[1]);
    unsigned nr = req & 0xff, type = (req >> 8) & 0xff;
    unsigned size = (req >> 16) & 0x3fff, dir = (req >> 30) & 3;
    out_printf(o, "%" PRId64 ", _IOC(dir=%u,type=0x%02x,nr=0x%02x,size=%u), ",
               ev->abi == SD_ABI_ARM_EABI ? (int64_t)(int32_t)ev->args[0] : (int64_t)ev->args[0],
               dir, type, nr, size);
    print_ptr(o, ev->abi, ev->args[2]);
}

static const char *
bpf_cmd_name(uint64_t cmd)
{
    static const char *const names[] = {
        "BPF_MAP_CREATE", "BPF_MAP_LOOKUP_ELEM", "BPF_MAP_UPDATE_ELEM",
        "BPF_MAP_DELETE_ELEM", "BPF_MAP_GET_NEXT_KEY", "BPF_PROG_LOAD",
        "BPF_OBJ_PIN", "BPF_OBJ_GET", "BPF_PROG_ATTACH", "BPF_PROG_DETACH",
        "BPF_PROG_TEST_RUN", "BPF_PROG_GET_NEXT_ID", "BPF_MAP_GET_NEXT_ID",
        "BPF_PROG_GET_FD_BY_ID", "BPF_MAP_GET_FD_BY_ID", "BPF_OBJ_GET_INFO_BY_FD"
    };
    return cmd < sizeof(names)/sizeof(names[0]) ? names[cmd] : NULL;
}

static void
print_bpf(struct out *o, const sd_event_t *ev, int symbolic)
{
    uint64_t cmd = sd_normalize_arg(ev->abi, ev->args[0]);
    const char *name = bpf_cmd_name(cmd);
    if (symbolic && name) out_printf(o, "%s, ", name); else out_printf(o, "%" PRIu64 ", ", cmd);
    print_ptr(o, ev->abi, ev->args[1]);
    out_printf(o, ", %" PRIu64, sd_normalize_arg(ev->abi, ev->args[2]));
}

static void
print_openat2(sd_decoder_t *d, const sd_event_t *ev, struct out *o)
{
    uint64_t how[3] = {0};
    size_t user_size = (size_t)sd_normalize_arg(ev->abi, ev->args[3]);
    size_t read_size = user_size < sizeof(how) ? user_size : sizeof(how);
    out_printf(o, "%" PRId64 ", ", ev->abi == SD_ABI_ARM_EABI ?
               (int64_t)(int32_t)ev->args[0] : (int64_t)ev->args[0]);
    print_cstring(d, ev, o, ev->args[1]);
    out_printf(o, ", ");
    if (read_size >= 8 && read_mem(d, ev, ev->args[2], how, read_size) == (ssize_t)read_size) {
        out_printf(o, "{flags=");
        print_open_flags(o, how[0], d->opt.symbolic);
        if (read_size >= 16) out_printf(o, ", mode=0%llo", (unsigned long long)(how[1] & 07777));
        if (read_size >= 24) out_printf(o, ", resolve=0x%" PRIx64, how[2]);
        if (user_size > sizeof(how)) out_printf(o, ", ...");
        out_printf(o, "}");
    } else {
        print_ptr(o, ev->abi, ev->args[2]);
    }
    out_printf(o, ", %zu", user_size);
}

static void
print_clone3(sd_decoder_t *d, const sd_event_t *ev, struct out *o)
{
    uint64_t a[11] = {0};
    size_t user_size = (size_t)sd_normalize_arg(ev->abi, ev->args[1]);
    size_t read_size = user_size < sizeof(a) ? user_size : sizeof(a);
    if (read_size >= 8 && read_mem(d, ev, ev->args[0], a, read_size) == (ssize_t)read_size) {
        out_printf(o, "{flags=0x%" PRIx64, a[0]);
        if (read_size >= 40) out_printf(o, ", exit_signal=%" PRIu64, a[4]);
        if (read_size >= 56) out_printf(o, ", stack=0x%" PRIx64 ", stack_size=%" PRIu64, a[5], a[6]);
        if (read_size >= 64) out_printf(o, ", tls=0x%" PRIx64, a[7]);
        if (read_size >= 80) out_printf(o, ", set_tid=0x%" PRIx64 ", set_tid_size=%" PRIu64, a[8], a[9]);
        if (read_size >= 88) out_printf(o, ", cgroup=%" PRIu64, a[10]);
        if (user_size > sizeof(a)) out_printf(o, ", ...");
        out_printf(o, "}");
    } else {
        print_ptr(o, ev->abi, ev->args[0]);
    }
    out_printf(o, ", %zu", user_size);
}

static const char *
fcntl_cmd_name(int cmd)
{
    switch (cmd) {
    case F_DUPFD: return "F_DUPFD"; case F_GETFD: return "F_GETFD";
    case F_SETFD: return "F_SETFD"; case F_GETFL: return "F_GETFL";
    case F_SETFL: return "F_SETFL"; case F_GETLK: return "F_GETLK";
    case F_SETLK: return "F_SETLK"; case F_SETLKW: return "F_SETLKW";
#ifdef F_DUPFD_CLOEXEC
    case F_DUPFD_CLOEXEC: return "F_DUPFD_CLOEXEC";
#endif
    default: return NULL;
    }
}

static void
print_fcntl(struct out *o, const sd_event_t *ev, int symbolic)
{
    int cmd = (int)(uint32_t)ev->args[1];
    const char *name = fcntl_cmd_name(cmd);
    out_printf(o, "%" PRId32 ", %s", (int32_t)ev->args[0],
               symbolic && name ? name : "UNKNOWN_FCNTL_CMD");
    if (!symbolic || !name) out_printf(o, "(%d)", cmd);
    if (cmd != F_GETFD && cmd != F_GETFL) {
        out_printf(o, ", ");
        if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW)
            print_ptr(o, ev->abi, ev->args[2]);
        else
            out_printf(o, "0x%" PRIx64, sd_normalize_arg(ev->abi, ev->args[2]));
    }
}

static void
print_socketcall(sd_decoder_t *d, const sd_event_t *ev, struct out *o)
{
    static const char *const names[] = { NULL, "socket", "bind", "connect", "listen", "accept",
        "getsockname", "getpeername", "socketpair", "send", "recv", "sendto", "recvfrom",
        "shutdown", "setsockopt", "getsockopt", "sendmsg", "recvmsg", "accept4", "recvmmsg", "sendmmsg" };
    uint32_t call = (uint32_t)ev->args[0], words[6] = {0};
    const char *name = call < sizeof(names)/sizeof(names[0]) ? names[call] : NULL;
    out_printf(o, "%s, ", name ? name : "UNKNOWN_SOCKETCALL");
    if (read_mem(d, ev, ev->args[1], words, sizeof(words)) == (ssize_t)sizeof(words))
        out_printf(o, "[0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x]", words[0], words[1], words[2], words[3], words[4], words[5]);
    else
        print_ptr(o, ev->abi, ev->args[1]);
}

static uint64_t
arm_eabi_u64(uint64_t first, uint64_t second)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((uint64_t)(uint32_t)first << 32) | (uint32_t)second;
#else
    return ((uint64_t)(uint32_t)second << 32) | (uint32_t)first;
#endif
}

static int
print_arm_eabi_aligned64(sd_decoder_t *d, const sd_event_t *ev,
                         struct out *o, const char *name)
{
    uint64_t v;
    if (!strcmp(name, "pread64") || !strcmp(name, "pwrite64")) {
        int is_write = name[0] == 'p' && name[1] == 'w';
        out_printf(o, "%" PRId32 ", ", (int32_t)ev->args[0]);
        if (is_write)
            print_buffer(d, ev, o, ev->args[1], (uint32_t)ev->args[2]);
        else if (!sd_is_linux_error(ev->retval))
            print_buffer(d, ev, o, ev->args[1], buffer_count(ev, 2, 1));
        else
            print_ptr(o, ev->abi, ev->args[1]);
        v = arm_eabi_u64(ev->args[4], ev->args[5]);
        out_printf(o, ", %" PRIu32 ", %" PRIu64, (uint32_t)ev->args[2], v);
        return 1;
    }
    if (!strcmp(name, "readahead")) {
        v = arm_eabi_u64(ev->args[2], ev->args[3]);
        out_printf(o, "%" PRId32 ", %" PRIu64 ", %" PRIu32,
                   (int32_t)ev->args[0], v, (uint32_t)ev->args[4]);
        return 1;
    }
    if (!strcmp(name, "truncate64") || !strcmp(name, "ftruncate64")) {
        if (name[0] == 't') print_cstring(d, ev, o, ev->args[0]);
        else out_printf(o, "%" PRId32, (int32_t)ev->args[0]);
        v = arm_eabi_u64(ev->args[2], ev->args[3]);
        out_printf(o, ", %" PRIu64, v);
        return 1;
    }
    return 0;
}

static const char *
errno_name(unsigned e)
{
    switch (e) {
    case EPERM: return "EPERM"; case ENOENT: return "ENOENT"; case ESRCH: return "ESRCH";
    case EINTR: return "EINTR"; case EIO: return "EIO"; case ENXIO: return "ENXIO";
    case E2BIG: return "E2BIG"; case ENOEXEC: return "ENOEXEC"; case EBADF: return "EBADF";
    case ECHILD: return "ECHILD"; case EAGAIN: return "EAGAIN"; case ENOMEM: return "ENOMEM";
    case EACCES: return "EACCES"; case EFAULT: return "EFAULT"; case EBUSY: return "EBUSY";
    case EEXIST: return "EEXIST"; case EXDEV: return "EXDEV"; case ENODEV: return "ENODEV";
    case ENOTDIR: return "ENOTDIR"; case EISDIR: return "EISDIR"; case EINVAL: return "EINVAL";
    case ENFILE: return "ENFILE"; case EMFILE: return "EMFILE"; case ENOTTY: return "ENOTTY";
    case EFBIG: return "EFBIG"; case ENOSPC: return "ENOSPC"; case ESPIPE: return "ESPIPE";
    case EROFS: return "EROFS"; case EPIPE: return "EPIPE"; case ERANGE: return "ERANGE";
    case ENOSYS: return "ENOSYS"; case EOVERFLOW: return "EOVERFLOW";
    case ETIMEDOUT: return "ETIMEDOUT"; case ECONNREFUSED: return "ECONNREFUSED";
    default: return NULL;
    }
}

static void
print_result(struct out *o, const sd_event_t *ev, const char *name)
{
    if (sd_is_linux_error(ev->retval)) {
        unsigned e = (unsigned)-ev->retval;
        const char *en = errno_name(e);
        out_printf(o, " = -1 %s (%s)", en ? en : "ERRNO", strerror((int)e));
    } else if (!strcmp(name, "mmap") || !strcmp(name, "mmap2") || !strcmp(name, "brk")) {
        out_printf(o, " = 0x%" PRIx64, (uint64_t)ev->retval);
    } else {
        out_printf(o, " = %" PRId64, ev->retval);
    }
}

const syscall_entry_t *
syscall_table_lookup(__s32 syscall_id,
                     const syscall_entry_t table[SYSCALL_TABLE_SIZE])
{
    if (!table || syscall_id < 0 || (unsigned)syscall_id >= SYSCALL_TABLE_SIZE)
        return NULL;
    return table[syscall_id].name ? &table[syscall_id] : NULL;
}

__u64
syscall_normalize_arg(unsigned abi_bits, __u64 raw)
{
    return abi_bits == 32 ? (__u32)raw : raw;
}

__s64
syscall_normalize_retval(unsigned abi_bits, __u64 raw)
{
    return abi_bits == 32 ? (__s64)(__s32)raw : (__s64)raw;
}

int syscall_ret_is_error(__s64 r) { return r < 0 && r >= -4095; }

static uint64_t sd_normalize_arg(sd_abi_t abi, uint64_t raw)
{
    return syscall_normalize_arg(abi == SD_ABI_ARM_EABI ? 32 : 64, raw);
}

static int64_t sd_normalize_retval(sd_abi_t abi, uint64_t raw)
{
    return syscall_normalize_retval(abi == SD_ABI_ARM_EABI ? 32 : 64, raw);
}

static int sd_is_linux_error(int64_t r) { return syscall_ret_is_error(r); }

static unsigned
table_abi_bits(const syscall_entry_t table[SYSCALL_TABLE_SIZE])
{
    return table ? table[0].abi_bits : 0;
}

static int
decode_with_table(sd_decoder_t *d, sd_event_t *ev,
                  const syscall_entry_t table[SYSCALL_TABLE_SIZE],
                  char *dst, size_t dst_size)
{
    const syscall_entry_t *ent;
    const struct call_desc *call;
    struct out o = { dst, dst_size, 0 };
    const char *name;
    unsigned i, nargs;
    char unknown[32];

    if (!d || !ev || !table || (!dst && dst_size) ||
        (ev->abi != SD_ABI_ARM64 && ev->abi != SD_ABI_ARM_EABI))
        return -EINVAL;
    if (dst_size)
        dst[0] = '\0';
    ent = syscall_table_lookup((__s32)ev->nr, table);
    if (ent)
        name = ent->name;
    else {
        snprintf(unknown, sizeof(unknown), "syscall_%u", ev->nr);
        name = unknown;
    }

    out_printf(&o, "[pid %u] ", ev->tid ? ev->tid : ev->pid);
    out_printf(&o, "%s(", name);
    if (ev->abi == SD_ABI_ARM_EABI &&
        print_arm_eabi_aligned64(d, ev, &o, name)) {
        /* Printed as logical C arguments, hiding the EABI alignment hole. */
    } else if (!strcmp(name, "ioctl")) {
        print_ioctl(&o, ev);
    } else if (!strcmp(name, "bpf")) {
        print_bpf(&o, ev, d->opt.symbolic);
    } else if (!strcmp(name, "openat2")) {
        print_openat2(d, ev, &o);
    } else if (!strcmp(name, "clone3")) {
        print_clone3(d, ev, &o);
    } else if (!strcmp(name, "fcntl") || !strcmp(name, "fcntl64")) {
        print_fcntl(&o, ev, d->opt.symbolic);
    } else if (!strcmp(name, "socketcall") && ev->abi == SD_ABI_ARM_EABI) {
        print_socketcall(d, ev, &o);
    } else {
        call = find_call(name);
        nargs = call ? call->nargs : (ent ? ent->nargs : SYSDECODE_MAX_ARGS);
        if (call && !strcmp(name, "open") && !(ev->args[1] & O_CREAT))
            nargs = 2;
        if (call && !strcmp(name, "openat") && !(ev->args[2] & O_CREAT))
            nargs = 3;
        if (nargs > SYSDECODE_MAX_ARGS)
            nargs = SYSDECODE_MAX_ARGS;
        for (i = 0; i < nargs; ++i) {
            if (i)
                out_printf(&o, ", ");
            if (call)
                print_arg(d, ev, &o, call->arg[i], ev->args[i], name);
            else
                out_printf(&o, "0x%" PRIx64, sd_normalize_arg(ev->abi, ev->args[i]));
        }
    }
    out_printf(&o, ")");
    print_result(&o, ev, name);
    out_printf(&o, " <%" PRIu64 ".%06" PRIu64 ">",
                   ev->duration_ns / UINT64_C(1000000000),
                   (ev->duration_ns % UINT64_C(1000000000)) / 1000);

    return o.len > (size_t)INT32_MAX ? INT32_MAX : (int)o.len;
}

ssize_t
syscall_process_vm_reader(void *opaque, __u32 pid, __u64 remote_addr,
                          void *local, size_t len)
{
    struct iovec liov = { local, len };
    struct iovec riov = { (void *)(uintptr_t)remote_addr, len };
    ssize_t n;
    (void)opaque;
    n = process_vm_readv((pid_t)pid, &liov, 1, &riov, 1, 0);
    return n < 0 ? -errno : n;
}

int
syscall_parse_event(syscall_parser_t *parser,
                    struct syscall_event *event,
                    const syscall_entry_t table[SYSCALL_TABLE_SIZE],
                    char *dst, size_t dst_size)
{
    sd_event_t ev;
    unsigned bits = table_abi_bits(table);
    if (!event || event->syscall_id < 0 || (bits != 32 && bits != 64))
        return -EINVAL;

    memset(&ev, 0, sizeof(ev));
    ev.abi = bits == 32 ? SD_ABI_ARM_EABI : SD_ABI_ARM64;
    ev.nr = (__u32)event->syscall_id;
    ev.pid = event->pid;
    ev.tid = event->tid;
    memcpy(ev.args, event->args, sizeof(ev.args));
    ev.retval = sd_normalize_retval(ev.abi, (__u64)event->ret);
    ev.timestamp_ns = event->ts_ns;
    ev.duration_ns = event->duration_ns;
    return decode_with_table(parser, &ev, table, dst, dst_size);
}
