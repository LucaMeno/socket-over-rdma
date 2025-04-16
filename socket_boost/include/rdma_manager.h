
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

#include "rdma_utils.h"

#define N_POLL_PER_CQ 1000
#define N_THREADS_POOL 5

typedef struct
{
    rdma_context_t *ctx; // context
    int slice_id;        // ID of the slice
} thread_pool_arg_t;

typedef struct task
{
    void (*function)(void *);
    thread_pool_arg_t *arg;
    struct task *next;
} task_t;

typedef struct
{
    pthread_mutex_t lock;
    pthread_cond_t cond;
    task_t *head;
    task_t *tail;
    int stop;
    pthread_t *threads;
    int thread_count;
} thread_pool_t;

typedef struct
{
    rdma_context_t *ctxs;
    int ctx_count;      // number of contexts
    uint16_t rdma_port; // port used for RDMA
    pthread_t notification_thread;
    pthread_t server_thread;
    thread_pool_t *pool;                  // thread pool for worker threads
    int stop_threads;                     // flag to stop the threads
    struct rdma_cm_id *listener;          // Listener ID for incoming connections
    struct rdma_event_channel *server_ec; // Event channel
} rdma_context_manager_t;

rdma_context_slice_t *rdma_manager_get_slice(rdma_context_manager_t *ctxm, uint32_t remote_ip, uint16_t port);
int rdma_manager_get_free_context(rdma_context_manager_t *ctxm);
int rdma_manager_destroy(rdma_context_manager_t *ctxm);
int rdma_manager_init(rdma_context_manager_t *ctxm, uint16_t rdma_port);
int rdma_manager_get_context_by_ip(rdma_context_manager_t *ctxm, uint32_t remote_ip);

int rdma_manager_run_listen_th(rdma_context_manager_t *ctxm);
void *rdma_manager_listen_thread(void *arg);
int rdma_manager_run_server_th(rdma_context_manager_t *ctxm);
void *rdma_manager_server_thread(void *arg);

int sk_send(rdma_context_manager_t *ctxm, uint32_t remote_ip, uint16_t port, char *tx_data, int tx_size, char *rx_data, int *rx_size, int fd);

int rdma_server_setup(rdma_context_manager_t *ctxm);
/** THREAD POOL */

void rdma_recv_notfication_th(void *arg);
void *worker(void *arg);
thread_pool_t *thread_pool_create(int num_threads);
int thread_pool_add(thread_pool_t *pool, void (*function)(void *), void *arg);
void thread_pool_destroy(thread_pool_t *pool);

#endif // RDMA_MANAGER_H
