#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>


int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int prog_fd, map_fd;

    obj = bpf_object__open_file("scap.bpf.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    int err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "add_established_sock");
    if (!prog)
    {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "Failed to get BPF program FD\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "sockmap");
    if (map_fd < 0)
    {
        fprintf(stderr, "Failed to get BPF map FD\n");
        return 1;
    }

    printf("Successfully loaded eBPF program!\n");
    printf("Sockmap FD: %d\n", map_fd);
    printf("Program FD: %d\n", prog_fd);

    // Attach the program to the socket operations
    err = bpf_prog_attach(prog_fd, 0, BPF_PROG_TYPE_SOCK_OPS, 0);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        return 1;
    }

    // Keep the program running to capture events
    while (1)
    {
        sleep(1);
    }

    return 0;
}
