#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
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

void wait_for_msg(bpf_context_t *bpf_ctx, sk_context_t *sk_ctx, rdma_context_manager_t *rdma_ctx);

rdma_context_manager_t rdma_ctxm = {0};
sk_context_t sk_ctx = {0};
bpf_context_t bpf_ctx = {0};

int fun(void *ctx, void *data, size_t len)
{
    struct userspace_data_t *user_data = (struct userspace_data_t *)data;
    printf("New Association: APP [%u:%u -> %u:%u] <-> PROXY [%u:%u -> %u:%u] - OP: %d\n",
           user_data->association.app.sip,
           user_data->association.app.sport,
           user_data->association.app.dip,
           user_data->association.app.dport,
           user_data->association.proxy.sip,
           user_data->association.proxy.sport,
           user_data->association.proxy.dip,
           user_data->association.proxy.dport,
           user_data->sockops_op);

    // start the RDMA connection
    // only the client start the connection
    if (user_data->sockops_op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
    {
        int ret;
        int proxy_fd = get_proxy_fd_from_sockid(&sk_ctx, user_data->association.proxy);

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

    err = setup_bpf(&bpf_ctx, handler);

    check_error(err, "");
    printf("eBPF program setup complete\n");

    // TODO: scale this
    __u16 ports_to_set[1] = {TARGET_PORT};
    int nport = sizeof(ports_to_set) / sizeof(ports_to_set[0]);

    // const char *ip_env = getenv("REMOTE_IP");
    const char *ip1 = "192.168.100.6";
    const char *ip2 = "192.168.100.5";
    __u32 ips_to_set[2];

    ips_to_set[0] = inet_addr(ip1);
    ips_to_set[1] = inet_addr(ip2);

    int nip = sizeof(ips_to_set) / sizeof(ips_to_set[0]);

    err = set_target_ports(&bpf_ctx, ports_to_set, nport, PROXY_PORT);
    check_error(err, "");
    printf("Target ports set\n");

    err = set_target_ip(&bpf_ctx, ips_to_set, nip);
    check_error(err, "");
    printf("Target IPs set\n");

    err = run_bpf(&bpf_ctx);
    check_error(err, "");
    printf("eBPF program attached to socket\n");

    err = setup_sockets(&sk_ctx, PROXY_PORT, inet_addr(SERVER_IP));
    check_error(err, "");
    printf("Sockets setup complete\n");

    err = push_sock_to_map(&bpf_ctx, sk_ctx.client_sk_fd, NUMBER_OF_SOCKETS);
    check_error(err, "");
    printf("Map updated\n");

    // RDMA
    err = rdma_manager_run(&rdma_ctxm, RDMA_PORT, &bpf_ctx, sk_ctx.client_sk_fd);

    printf("Waiting for messages, press Ctrl+C to exit...\n");
    wait_for_msg(&bpf_ctx, &sk_ctx, &rdma_ctxm);

    err = cleanup_socket(&sk_ctx);
    check_error(err, "");
    printf("Socket closed\n");

    err = cleanup_bpf(&bpf_ctx);
    check_error(err, "");
    printf("Successfully detached eBPF program\n");

    /*err = rdma_manager_destroy(&rdma_ctxm);
    check_error(err, "");
    printf("RDMA manager destroyed\n");*/

    return 0;
}

void wait_for_msg(bpf_context_t *bpf_ctx, sk_context_t *sk_ctx, rdma_context_manager_t *rdma_ctx)
{
    char buffer[MAX_SIZE_SK_MSG];
    fd_set read_fds, temp_fds;
    ssize_t bytes_received;

    // Initialize the file descriptor set
    FD_ZERO(&read_fds);
    FD_SET(sk_ctx->server_sk_fd, &read_fds);

    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        if (sk_ctx->client_sk_fd[i].fd >= 0)
            FD_SET(sk_ctx->client_sk_fd[i].fd, &read_fds);

    // Set the maximum file descriptor
    int max_fd = sk_ctx->server_sk_fd;
    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        if (sk_ctx->client_sk_fd[i].fd > max_fd)
            max_fd = sk_ctx->client_sk_fd[i].fd;

    int k = 1;
    while (!STOP)
    {
        temp_fds = read_fds;

        int activity = select(max_fd + 1, &temp_fds, NULL, NULL, NULL);
        if (activity == -1)
        {
            if (errno == EINTR)
            {
                printf("Select interrupted by signal\n");
                break;
            }
            perror("select error");
            break;
        }

        // Handle data on client sockets
        for (int i = 0; i <= max_fd; i++)
        {
            if (i != sk_ctx->server_sk_fd && FD_ISSET(i, &temp_fds))
            {
                bytes_received = recv(i, buffer, TEST_BUFFER_SIZE, 0); // TODO: ???????????????????
                if (bytes_received <= 0)
                {
                    if (bytes_received == 0)
                        printf("Client %d disconnected\n", i);
                    else
                        perror("recv error");

                    close(i);
                    FD_CLR(i, &read_fds);
                }
                else
                {
#ifdef PROXY_DEBUG
                    buffer[bytes_received] = '\0';
                    printf("-----------------------------------------------------------------------(%d)\n", k);
                    k++;
                    printf("Rx from fd:\t%d\n", i);
                    // printf("Msg text: \t%s\n", buffer);
#endif // PROXY_DEBUG
                    struct sock_id app = get_app_sk_from_proxy_fd(bpf_ctx, sk_ctx->client_sk_fd, i);
                    // Send the message using RDMA
                    rdma_manager_send(rdma_ctx, buffer, bytes_received, app);
                }
            }
        }
    }
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
