#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

int main() {
    // 1. 获取进程ID (getpid, getppid)
    printf("--- 1. Process ID Test ---\n");
    pid_t current_pid = getpid();
    pid_t parent_pid = getppid();
    printf("Current PID: %d, Parent PID: %d\n\n", current_pid, parent_pid);

    // 2. 创建子进程 (fork)
    printf("--- 2. Fork & Process Control Test ---\n");
    pid_t pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        exit(1);
    } else if (pid == 0) {
        // 子进程逻辑
        printf("Child Process: PID = %d, Parent PID = %d\n", getpid(), getppid());
        
        // 3. 文件I/O操作 (open, write, close)
        int fd = open("test.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd != -1) {
            const char *msg = "Hello from Linux system calls!\n";
            write(fd, msg, 31);
            close(fd);
            printf("Child successfully wrote to 'test.txt'.\n");
        }
        exit(0);
    } else {
        // 父进程逻辑
        int status;
        wait(&status); // 4. 等待子进程结束 (wait)
        printf("Parent Process: Child (PID: %d) has finished.\n\n", pid);

        // 5. 获取文件元数据 (stat)
        printf("--- 3. File Metadata (stat) Test ---\n");
        struct stat file_info;
        if (stat("test.txt", &file_info) == 0) {
            printf("File 'test.txt' size: %ld bytes\n", file_info.st_size);
            printf("File permissions: %o\n", file_info.st_mode & 0777);
        } else {
            perror("Stat failed");
        }
    }

    return 0;
}
