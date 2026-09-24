#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static void test_process_info(void)
{
    printf("=== process info ===\n");
    printf("pid  = %d\n", getpid());
    printf("ppid = %d\n", getppid());
    printf("uid  = %d\n", getuid());
    printf("gid  = %d\n", getgid());
}

static void test_uname(void)
{
    printf("\n=== uname ===\n");

    struct utsname u;
    if (uname(&u) == 0) {
        printf("sysname  : %s\n", u.sysname);
        printf("nodename : %s\n", u.nodename);
        printf("release  : %s\n", u.release);
        printf("version  : %s\n", u.version);
        printf("machine  : %s\n", u.machine);
    } else {
        perror("uname");
    }
}

static void test_file_io(void)
{
    printf("\n=== file io ===\n");

    const char *path = "/data/local/tmp/syscall_demo.txt";

    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return;
    }

    const char *msg = "hello from Android syscall demo\n";

    ssize_t n = write(fd, msg, strlen(msg));
    if (n < 0) {
        perror("write");
        close(fd);
        return;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek");
        close(fd);
        return;
    }

    char buf[128] = {0};

    n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        perror("read");
    } else {
        printf("read: %s", buf);
    }

    struct stat st;
    if (fstat(fd, &st) == 0) {
        printf("file size: %lld\n", (long long)st.st_size);
        printf("inode    : %llu\n",
               (unsigned long long)st.st_ino);
    } else {
        perror("fstat");
    }

    close(fd);
}

static void test_directory(void)
{
    printf("\n=== directory ===\n");

    DIR *dir = opendir("/data/local/tmp");
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL && count < 10) {
        printf("entry: %s\n", entry->d_name);
        count++;
    }

    closedir(dir);
}

static void test_memory(void)
{
    printf("\n=== mmap ===\n");

    size_t size = 4096;

    void *addr = mmap(
        NULL,
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (addr == MAP_FAILED) {
        perror("mmap");
        return;
    }

    strcpy((char *)addr, "hello mmap");

    printf("mapped address: %p\n", addr);
    printf("mapped data   : %s\n", (char *)addr);

    if (mprotect(addr, size, PROT_READ) != 0) {
        perror("mprotect");
    }

    if (munmap(addr, size) != 0) {
        perror("munmap");
    }
}

static void test_time(void)
{
    printf("\n=== time ===\n");

    struct timeval tv;

    if (gettimeofday(&tv, NULL) == 0) {
        printf("seconds      : %lld\n",
               (long long)tv.tv_sec);
        printf("microseconds : %lld\n",
               (long long)tv.tv_usec);
    } else {
        perror("gettimeofday");
    }
    printf("sleep 1 second...\n");
    sleep(1);

}

static void test_pipe(void)
{
    printf("\n=== pipe ===\n");

    int fds[2];

    if (pipe(fds) != 0) {
        perror("pipe");
        return;
    }

    const char *msg = "hello pipe";

    if (write(fds[1], msg, strlen(msg)) < 0) {
        perror("pipe write");
        close(fds[0]);
        close(fds[1]);
        return;
    }

    char buf[64] = {0};

    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    if (n < 0) {
        perror("pipe read");
    } else {
        printf("pipe data: %s\n", buf);
    }

    close(fds[0]);
    close(fds[1]);
}

static void test_socket(void)
{
    printf("\n=== socket ===\n");

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return;
    }

    printf("socket fd: %d\n", fd);

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl F_GETFL");
    } else {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            perror("fcntl F_SETFL");
        } else {
            printf("socket set to non-blocking mode\n");
        }
    }

    close(fd);
}

static void test_dup(void)
{
    printf("\n=== dup ===\n");

    int fd = open(
        "/data/local/tmp/syscall_demo.txt",
        O_RDONLY
    );

    if (fd < 0) {
        perror("open");
        return;
    }

    int fd2 = dup(fd);

    if (fd2 < 0) {
        perror("dup");
    } else {
        printf("fd=%d, duplicated fd=%d\n", fd, fd2);
        close(fd2);
    }

    close(fd);
}

static void test_access(void)
{
    printf("\n=== access ===\n");

    const char *path = "/system/bin/sh";

    if (access(path, F_OK) == 0) {
        printf("%s exists\n", path);
    } else {
        perror("access");
    }
}

static void test_readlink(void)
{
    printf("\n=== readlink ===\n");

    char buf[512] = {0};

    ssize_t n = readlink(
        "/proc/self/exe",
        buf,
        sizeof(buf) - 1
    );

    if (n < 0) {
        perror("readlink");
        return;
    }

    buf[n] = '\0';

    printf("/proc/self/exe -> %s\n", buf);
}

static void test_fork(void)
{
    printf("\n=== fork/waitpid ===\n");

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return;
    }

    if (pid == 0) {
        printf("child pid=%d\n", getpid());
        _exit(0);
    }

    int status = 0;

    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return;
    }

    printf("child %d exited, status=%d\n",
           pid,
           status);
}

int main(void)
{
    printf("Android syscall demo\n");

    test_process_info();
    test_uname();
    test_file_io();
    test_directory();
    test_memory();
    test_time();
    test_pipe();
    test_socket();
    test_dup();
    test_access();
    test_readlink();
    test_fork();

    printf("\nDone.\n");

    return 0;
}
