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

volatile sig_atomic_t STOP = false;

void handle_signal(int signal);
void check_error(int result, const char *msg);
void error_and_exit(const char *msg);

void wait_for_msg(bpf_context_t *bpf_ctx, sk_context_t *sk_ctx, rdma_context_manager_t *rdma_ctx);

rdma_context_t rdma_ctx[MAX_NUMBER_OF_RDMA_CONN] = {0};

int main()
{
    signal(SIGINT, handle_signal);

    sk_context_t sk_ctx = {0};
    bpf_context_t bpf_ctx = {0};
    rdma_context_manager_t rdma_ctxm = {0};

    int err;

    err = setup_bpf(&bpf_ctx);
    check_error(err, "");
    printf("eBPF program setup complete\n");

    // TODO: scale this to multiple ports
    __u16 ports_to_set[1] = {TARGET_PORT};
    int n = sizeof(ports_to_set) / sizeof(ports_to_set[0]);

    err = set_target_ports(&bpf_ctx, ports_to_set, n, PROXY_PORT);
    check_error(err, "");
    printf("Target ports set\n");

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
    err = rdma_manager_run(&rdma_ctxm, RDMA_PORT);

    printf("Waiting for messages, press Ctrl+C to exit...\n");
    wait_for_msg(&bpf_ctx, &sk_ctx, &rdma_ctxm);

    err = cleanup_socket(&sk_ctx);
    check_error(err, "");
    printf("Socket closed\n");

    err = cleanup_bpf(&bpf_ctx);
    check_error(err, "");
    printf("Successfully detached eBPF program\n");

    return 0;
}

void wait_for_msg(bpf_context_t *bpf_ctx, sk_context_t *sk_ctx, rdma_context_manager_t *rdma_ctx)
{
    char buffer[BUFFER_SIZE];
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
                bytes_received = recv(i, buffer, sizeof(buffer) - 1, 0);
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
                    buffer[bytes_received] = '\0';
                    printf("-----------------------------------------------------------------------(%d)\n", k);
                    k++;
                    printf("Rx from fd:\t%d\n", i);
                    printf("Msg text: \t%s\n", buffer);

                    // get the socket info
                    int j = 0;
                    for (; j < NUMBER_OF_SOCKETS; j++)
                        if (sk_ctx->client_sk_fd[j].fd == i)
                            break;

                    if (j == NUMBER_OF_SOCKETS)
                    {
                        error_and_exit("Socket not found in client_sk_fd");
                    }

                    struct sock_id sk_id_key = sk_ctx->client_sk_fd[j].sk_id;

                    struct association_t sk_assoc_k = {0};
                    struct association_t sk_assoc_v = {0};

                    sk_assoc_k.proxy = sk_id_key;

                    int ret = bpf_map_lookup_elem(bpf_ctx->socket_association_fd, &sk_assoc_k, &sk_assoc_v);
                    check_error(ret, "Failed to lookup socket in socket_association_fd");

                    char src_ip_proxy[INET_ADDRSTRLEN],
                        dst_ip_proxy[INET_ADDRSTRLEN],
                        src_ip_app[INET_ADDRSTRLEN],
                        dst_ip_app[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &sk_assoc_k.proxy.sip, src_ip_proxy, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &sk_assoc_k.proxy.dip, dst_ip_proxy, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &sk_assoc_v.app.sip, src_ip_app, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &sk_assoc_v.app.dip, dst_ip_app, INET_ADDRSTRLEN);

                    printf("Rx Sk info:\t[SRC: %s:%u, DST: %s:%u]\n", src_ip_proxy, sk_assoc_k.proxy.sport, dst_ip_proxy, sk_assoc_k.proxy.dport);

                    printf("Original sk:\t[SRC: %s:%u, DST: %s:%u]\n", src_ip_app, sk_assoc_v.app.sport, dst_ip_app, sk_assoc_v.app.dport);

                    // Send the message using RDMA

                    // sk_send(rdma_ctx, sk_assoc_v.app.dip, sk_assoc_v.app.dport, buffer, bytes_received, i);

                    // respond to the client with the same message
                    /*ssize_t sent_size = send(i, buffer, bytes_received, 0);
                    if (sent_size < 0)
                    {
                        perror("send");
                    }
                    else
                    {
                        printf("Response:\tsent\n");
                    }*/
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
