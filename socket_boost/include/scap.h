
#ifndef SCAP_H
#define SCAP_H

#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include "common.h"
#include "sk_utils.h"

#define CGROUP_PATH "/sys/fs/cgroup"
#define PATH_TO_BPF_OBJ_FILE "build/obj/scap.bpf.o"

typedef struct
{
    struct bpf_object *obj;
    int prog_fd_sockops;
    int prog_fd_sk_msg;
    int intercepted_sk_fd;
    int free_sk_fd;
    int target_ports_fd;
    int socket_association_fd;
    int server_port_fd;
    struct bpf_program *prog_tcp_destroy_sock;
    struct bpf_link *tcp_destroy_link;
    int cgroup_fd;
} bpf_context_t;

int setup_bpf(bpf_context_t *ctx);
int run_bpf(bpf_context_t *ctx);
int cleanup_bpf(bpf_context_t *ctx);
int set_target_ports(bpf_context_t *ctx, __u16 target_p[], int n, __u16 server_port);
int push_sock_to_map(bpf_context_t *ctx, client_sk_t client_sks[], int n);

struct sock_id get_proxy_sk_from_app_sk(bpf_context_t *ctx, struct sock_id app_sk);

#endif // SCAP_H