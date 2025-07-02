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
#include <pthread.h>
#include "common.h"
#include "scap.h"
#include "sk_utils.h"
#include "config.h"

#define MAX_NUMBER_OF_RDMA_CONN NUMBER_OF_SOCKETS

volatile sig_atomic_t STOP = false;

void handle_signal(int signal);
void check_error(int result, const char *msg);
void error_and_exit(const char *msg);

sk_context_t sk_ctx = {0};
bpf_context_t bpf_ctx = {0};

int fun(void *ctx, void *data, size_t len)
{
    printf("Received event from eBPF program\n");
    return 0;
}

struct th_param
{
    int fd1;
    int fd2;
    int wait;
};

void *th_fun(void *arg)
{
    struct th_param *param = (struct th_param *)arg;
    int fd1 = param->fd1;
    int fd2 = param->fd2;
    int wait = param->wait;

    char buf[64000];
    while (!STOP)
    {
        /*if (wait == 1)
        {
            //usleep(500 * 1000); // wait for 500 ms
        }*/
        int len = recv(fd1, buf, sizeof(buf), 0);
        while (len > 0)
        {
            int sent = 0;
            while (sent < len)
            {
                int len2 = send(fd2, buf + sent, len - sent, 0);
                if (len2 <= 0)
                    break;
                sent += len2;
            }
            len -= sent;
        }
    }

    return NULL;
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

    __u16 ports_to_set[1] = {TARGET_PORT};
    int nport = sizeof(ports_to_set) / sizeof(ports_to_set[0]);

    err = bpf_set_target_ports(&bpf_ctx, ports_to_set, nport, PROXY_PORT);
    check_error(err, "");
    printf("Target ports set\n");

    err = bpf_run(&bpf_ctx);
    check_error(err, "");
    printf("eBPF program attached to socket\n");

    err = sk_init(&sk_ctx, PROXY_PORT, inet_addr(SERVER_IP));
    check_error(err, "");
    printf("Sockets setup complete\n");

    err = bpf_push_sock_to_map(&bpf_ctx, sk_ctx.client_sk_fd, NUMBER_OF_SOCKETS);
    check_error(err, "");
    printf("Map updated\n");

    int fd1 = sk_ctx.client_sk_fd[0].fd;
    int fd2 = sk_ctx.client_sk_fd[1].fd;
    int fd3 = sk_ctx.client_sk_fd[2].fd;
    int fd4 = sk_ctx.client_sk_fd[3].fd;

    struct th_param param1 = {
        .fd1 = fd1,
        .fd2 = fd2,
        .wait = 1};
    pthread_t th1;
    pthread_create(&th1, NULL, th_fun, &param1);

    struct th_param param2 = {
        .fd1 = fd2,
        .fd2 = fd1,
        .wait = 1};
    pthread_t th2;
    pthread_create(&th2, NULL, th_fun, &param2);

    struct th_param param3 = {
        .fd1 = fd3,
        .fd2 = fd4,
        .wait = 1};
    pthread_t th3;
    pthread_create(&th3, NULL, th_fun, &param3);

    struct th_param param4 = {
        .fd1 = fd4,
        .fd2 = fd3,
        .wait = 1};
    pthread_t th4;
    pthread_create(&th4, NULL, th_fun, &param4);

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
