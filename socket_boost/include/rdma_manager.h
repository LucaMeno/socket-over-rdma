
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

typedef struct task task_t;
typedef struct thread_pool thread_pool_t;
typedef struct rdma_context_manager rdma_context_manager_t;
typedef struct thread_pool_arg thread_pool_arg_t;

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
    int ctx_count;      // number of contexts
    uint16_t rdma_port; // port used for RDMA
    pthread_t notification_thread;
    pthread_t server_thread;
    thread_pool_t *pool;                  // thread pool for worker threads
    int stop_threads;                     // flag to stop the threads
    struct rdma_cm_id *listener;          // Listener ID for incoming connections
    struct rdma_event_channel *server_ec; // Event channel
};

struct thread_pool_arg
{
    rdma_context_manager_t *ctxm;
    uint32_t remote_ip;
    uint16_t client_port;
    char *tx_data;
    int tx_size;
    int fd;
};

struct task
{
    void (*function)(void *);
    thread_pool_arg_t *arg;
    struct task *next;
};

int rdma_manager_run(rdma_context_manager_t *ctxm, uint16_t srv_port);
int rdma_manager_destroy(rdma_context_manager_t *ctxm);

int rdma_manager_send(rdma_context_manager_t *ctxm, uint32_t remote_ip, uint16_t client_port, char *tx_data, int tx_size, int fd);

// REMOVE
int rdma_manager_init(rdma_context_manager_t *ctxm, uint16_t rdma_port);

#endif // RDMA_MANAGER_H
