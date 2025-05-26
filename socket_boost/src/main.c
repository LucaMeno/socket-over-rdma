#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <execinfo.h>
#include "common.h"
#include "scap.h"
#include "sk_utils.h"
#include "rdma_manager.h"
#include "config.h"

#define MAX_NUMBER_OF_RDMA_CONN NUMBER_OF_SOCKETS

// #define BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB 5
// #define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 4

volatile sig_atomic_t STOP = false;

void handle_signal(int signal);
void check_error(int result, const char *msg);
void error_and_exit(const char *msg);

rdma_context_manager_t rdma_ctxm = {0};
sk_context_t sk_ctx = {0};
bpf_context_t bpf_ctx = {0};

int fun(void *ctx, void *data, size_t len)
{
    struct userspace_data_t *user_data = (struct userspace_data_t *)data;
    printf("New : [%u:%u -> %u:%u] <-> [%u:%u -> %u:%u]\n",
           user_data->association.app.sip,
           user_data->association.app.sport,
           user_data->association.app.dip,
           user_data->association.app.dport,
           user_data->association.proxy.sip,
           user_data->association.proxy.sport,
           user_data->association.proxy.dip,
           user_data->association.proxy.dport);

    // start the RDMA connection
    // only the client start the connection
    if (user_data->sockops_op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
    {
        int ret;
        int proxy_fd = sk_get_proxy_fd_from_sockid(&sk_ctx, user_data->association.proxy);

        if (proxy_fd < 0)
        {
            printf("Failed to get proxy fd from sockid\n");
            return -1;
        }

        ret = rdma_manager_connect(&rdma_ctxm, user_data->association.app, proxy_fd);
    }

    return 0;
}

int main()
{
    signal(SIGINT, handle_signal);
    signal(SIGTSTP, handle_signal);

    int err;
    EventHandler handler = {
        .ctx = NULL,
        .handle_event = fun};

    err = bpf_init(&bpf_ctx, handler);

    check_error(err, "");
    printf("eBPF program setup complete\n");

    // TODO: scale this
    __u16 ports_to_set[1] = {TARGET_PORT};
    int nport = sizeof(ports_to_set) / sizeof(ports_to_set[0]);

    // const char *ip_env = getenv("REMOTE_IP");
    const char *ip1 = "192.168.17.86";
    const char *ip2 = "192.168.17.84";
    __u32 ips_to_set[2];

    ips_to_set[0] = inet_addr(ip1);
    ips_to_set[1] = inet_addr(ip2);

    int nip = sizeof(ips_to_set) / sizeof(ips_to_set[0]);

    err = bpf_set_target_ports(&bpf_ctx, ports_to_set, nport, PROXY_PORT);
    check_error(err, "");
    printf("Target ports set\n");

    err = bpf_set_target_ip(&bpf_ctx, ips_to_set, nip);
    check_error(err, "");
    printf("Target IPs set\n");

    err = bpf_run(&bpf_ctx);
    check_error(err, "");
    printf("eBPF program attached to socket\n");

    err = sk_init(&sk_ctx, PROXY_PORT, inet_addr(SERVER_IP));
    check_error(err, "");
    printf("Sockets setup complete\n");

    err = bpf_push_sock_to_map(&bpf_ctx, sk_ctx.client_sk_fd, NUMBER_OF_SOCKETS);
    check_error(err, "");
    printf("Map updated\n");

    // RDMA
    err = rdma_manager_run(&rdma_ctxm, RDMA_PORT, &bpf_ctx, sk_ctx.client_sk_fd);

    printf("Waiting for messages, press Ctrl+C to exit...\n");
    while (!STOP)
    {
        pause(); // wait for signal
    }

    err = sk_destroy(&sk_ctx);
    check_error(err, "");
    printf("Socket closed\n");

    err = bpf_destroy(&bpf_ctx);
    check_error(err, "");
    printf("Successfully detached eBPF program\n");

    err = rdma_manager_destroy(&rdma_ctxm);
    check_error(err, "");
    printf("RDMA manager destroyed\n");

    return 0;
}

void handle_signal(int signal)
{
    STOP = true;
}

void check_error(int result, const char *msg)
{
    if (result != 0)
        error_and_exit(msg);
}

void error_and_exit(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    perror("Error details");
    exit(EXIT_FAILURE);
}
