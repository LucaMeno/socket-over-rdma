
#ifndef SCAP_H
#define SCAP_H

#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>

#include "common.h"
#include "sk_utils.h"
#include "config.h"

#define CGROUP_PATH "/sys/fs/cgroup"
#define PATH_TO_BPF_OBJ_FILE "build/obj/scap.bpf.o"

#define POOL_RB_INTERVAL 100 // milliseconds

typedef struct
{
    void *ctx;
    int (*handle_event)(void *ctx, void *data, size_t len);
} EventHandler;

typedef struct
{
    struct bpf_object *obj;

    // PROGS
    int prog_fd_sockops;
    int prog_fd_sk_msg;
    int cgroup_fd;
    struct bpf_program *prog_tcp_destroy_sock;
    struct bpf_link *tcp_destroy_link;

    // MAPS
    int intercepted_sk_fd;
    int free_sk_fd;
    int target_ports_fd;
    int socket_association_fd;
    int server_port_fd;
    int target_ip_fd;
    int ring_buffer_fd;
    struct ring_buffer *rb;
    int sock_proxyfd_association_fd;

    pthread_t thread_pool_rb;
    int stop_threads;
    EventHandler new_sk_event_handler;
} bpf_context_t;

int bpf_init(bpf_context_t *ctx, EventHandler event_handler);
int bpf_run(bpf_context_t *ctx);
int bpf_destroy(bpf_context_t *ctx);
int bpf_set_target_ports(bpf_context_t *ctx, __u16 target_p[], int n, __u16 server_port);
int bpf_set_target_ip(bpf_context_t *ctx, __u32 target_ip[], int n);
int bpf_push_sock_to_map(bpf_context_t *ctx, client_sk_t client_sks[], int n);

struct sock_id bpf_get_proxy_sk_from_app_sk(bpf_context_t *ctx, struct sock_id app_sk);
struct sock_id bpf_get_app_sk_from_proxy_fd(bpf_context_t *ctx, client_sk_t client_sks[], int target_fd);
struct sock_id bpf_get_app_sk_from_proxy_sk(bpf_context_t *ctx, struct sock_id proxy_sk);
int bpf_get_proxy_fd_from_app_sk(bpf_context_t *ctx, struct sock_id app_sk);
int bpf_add_app_sk_to_proxy_fd(bpf_context_t *ctx, struct sock_id app_sk, int proxy_fd);

#endif // SCAP_H