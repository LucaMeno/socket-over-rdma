
#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <sys/select.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"
#include "config.h"

/**
 * Structure to hold the socket information related to the proxy sockets
 * It stores the file descriptor and the socket ID used for the socket map
 */
typedef struct
{
    int fd;
    struct sock_id sk_id;
} client_sk_t;

typedef struct
{
    client_sk_t client_sk_fd[NUMBER_OF_SOCKETS];
    int server_sk_fd;
    __u16 server_port;
    __u32 server_ip;
} sk_context_t;

typedef struct
{
    sk_context_t *sk_ctx;
    int client_id;
} client_thread_arg_t;

int sk_init(sk_context_t *sk_ctx, __u16 server_port, __u32 server_ip);
int sk_destroy(sk_context_t *sk_ctx);
int sk_get_proxy_fd_from_sockid(sk_context_t *ctx, struct sock_id sk_id);

#endif // SOCKET_UTILS_H