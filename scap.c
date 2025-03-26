#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>

const char *CGROUP_PATH = "/sys/fs/cgroup";

int main(int argc, char **argv)
{
    struct bpf_object *obj;

    // open the BPF object file
    obj = bpf_object__open_file("scap.bpf.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // load the BPF object file into the kernel
    int err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    struct bpf_map *sockmap;

    // find the sockmap in the object file
    sockmap = bpf_object__find_map_by_name(obj, "sockmap");
    if (!sockmap)
    {
        fprintf(stderr, "Failed to find the sockmap\n");
        return -1;
    }

    // get the file descriptor for the map
    int map_fd = bpf_map__fd(sockmap);
    if (map_fd < 0)
    {
        fprintf(stderr, "Failed to get map fd\n");
        return -1;
    }

    struct bpf_program *prog_sockops, *prog_sk_msg;
    int prog_fd_sockops, prog_fd_sk_msg;

    // find the programs in the object file
    prog_sockops = bpf_object__find_program_by_name(obj, "sockops_prog");
    prog_fd_sockops = bpf_program__fd(prog_sockops);

    prog_sk_msg = bpf_object__find_program_by_name(obj, "sk_msg_prog");
    prog_fd_sk_msg = bpf_program__fd(prog_sk_msg);

    // get the file descriptor for the cgroup
    int cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    if (cgroup_fd < 0)
    {
        fprintf(stderr, "Failed to open cgroup: %s\n", strerror(errno));
        return 1;
    }

    // attach sockops_prog to the cgroup
    err = bpf_prog_attach(prog_fd_sockops, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to attach sockops_prog to cgroup: %d\n", err);
        return 1;
    }

    // Attach sk_msg_prog to the sockmap
    err = bpf_prog_attach(prog_fd_sk_msg, map_fd, BPF_SK_MSG_VERDICT, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to attach sk_msg_prog to sockmap: %d\n", err);
        return 1;
    }

    // attach the map to sk_msg_prog
    err = bpf_prog_attach(prog_fd_sk_msg, map_fd, BPF_SK_MSG_VERDICT, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to attach sk_msg_prog to map: %d\n", err);
        return 1;
    }

    printf("Successfully loaded eBPF program!\n");

    // Keep the program running to capture events
    while (1)
    {
        sleep(1);
    }

    return 0;
}
