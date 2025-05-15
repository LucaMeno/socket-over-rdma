
#ifndef RDMA_MANAGER_H
#define RDMA_MANAGER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <pthread.h>
#include <poll.h>
#include <sys/select.h>

#include "rdma_utils.h"

#define N_POLL_PER_CQ 1000
#define N_THREADS_POOL 15
#define N_WRITER_THREADS NUMBER_OF_SOCKETS

typedef struct task task_t;
typedef struct thread_pool thread_pool_t;
typedef struct rdma_context_manager rdma_context_manager_t;
typedef struct thread_pool_arg thread_pool_arg_t;
typedef struct writer_thread_arg writer_thread_arg_t;

struct thread_pool
{
    pthread_mutex_t lock;
    pthread_cond_t cond;
    task_t *head;
    task_t *tail;
    int stop;
    pthread_t *threads;
    int thread_count;
};

struct rdma_context_manager
{
    rdma_context_t *ctxs;
    int ctx_count;                        // number of contexts
    uint16_t rdma_port;                   // port used for RDMA
    thread_pool_t *pool;                  // thread pool for worker threads
    struct rdma_cm_id *listener;          // Listener ID for incoming connections
    struct rdma_event_channel *server_ec; // Event channel
    client_sk_t *client_sks;              // list of client sockets
    bpf_context_t *bpf_ctx;               // BPF context

    pthread_t notification_thread; // thread for the notification
    pthread_t server_thread;       // thread for the server
    pthread_t polling_thread;      // thread for polling the circular buffer
    pthread_t flush_thread;        // thread for flushing the circular buffer

    pthread_t writer_thread[N_WRITER_THREADS]; // thread for writing to the circular buffer

    atomic_uint stop_threads; // flag to stop the threads
};

struct writer_thread_arg
{
    rdma_context_manager_t *ctxm;
    client_sk_t *sk_to_monitor; // socket to monitor
    int n;
};

struct thread_pool_arg
{
    rdma_context_manager_t *ctxm;
    rdma_context_t *ctx;            // context to use
    struct sock_id original_socket; // id of the socket
    char *tx_data;
    int tx_size;
    int fd;
    uint32_t start_read_index;
    uint32_t end_read_index;
};

struct task
{
    void (*function)(void *);
    thread_pool_arg_t *arg;
    struct task *next;
};

int rdma_manager_run(rdma_context_manager_t *ctxm, uint16_t srv_port, bpf_context_t *bpf_ctx, client_sk_t *proxy_sks);

int rdma_manager_destroy(rdma_context_manager_t *ctxm);

int rdma_manager_connect(rdma_context_manager_t *ctxm, struct sock_id original_socket, int proxy_sk_fd);

#endif // RDMA_MANAGER_H
