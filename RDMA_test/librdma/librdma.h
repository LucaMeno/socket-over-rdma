
#ifndef LIB_RDMA_H
#define LIB_RDMA_H

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

#define UNUSED(x) (void)(x)


#define MAX_PAYLOAD_SIZE 512
#define SLICE_BUFFER_SIZE (2 * sizeof(transfer_buffer_t)) // size of the slice in memory. A slice is a double buffer used to exchange data

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t))
#define N_TCP_PER_CONNECTION 5
#define INITIAL_CONTEXT_NUMBER 10
#define N_CONTEXT_REALLOC 5
#define MR_SIZE ((SLICE_BUFFER_SIZE * N_TCP_PER_CONNECTION) + NOTIFICATION_OFFSET_SIZE)

#define POLL_MEM_ATTEMPTS 10000

#define N_POLL_PER_CQ 1000

#define N_THREADS_POOL 5

#define TRUE 1
#define FALSE 0

typedef struct
{
    uintptr_t addr;
    uint32_t rkey;
} rdma_meta_info_t;

/**
 * code that can be notified
 */
typedef enum
{
    RDMA_DATA_READY = 10,
    RDMA_NEW_SLICE = 1,
    RDMA_DELETE_SLICE = 2,
    TEST = 3,
    EXCHANGE_REMOTE_INFO = 4,
    RDMA_CLOSE_CONTEXT = 5
} rdma_communication_code_t;

/**
 * notification structure
 */
typedef struct
{
    rdma_communication_code_t code; // code of the notification
    int slice_id;                   // ID of the slice
} notification_data_t;

typedef struct
{
    notification_data_t from_server; // notification from server
    notification_data_t from_client; // notification from client
} notification_t;

typedef struct
{
    volatile uint32_t data_ready;
} flags_t;

typedef struct
{
    int buffer_size;
    flags_t flags;
    char buffer[MAX_PAYLOAD_SIZE];
} transfer_buffer_t;

/**
 * slice of the context
 * each TCP socket will have its own slice
 * this is used to send and receive data
 */
typedef struct
{
    int slice_id; // ID of the slice
    transfer_buffer_t *server_buffer;
    transfer_buffer_t *client_buffer;
    __u16 src_port;
    int is_polling; // TRUE if polling, FALSE if not
} rdma_context_slice_t;

/**
 * context between two different nodes
 */
typedef struct
{
    // RDMA
    struct rdma_event_channel *ec; // Event channel
    struct rdma_cm_id *listener;   // Listener ID (SERVER only)
    struct rdma_cm_id *conn;       // Connection ID
    struct ibv_pd *pd;             // Protection Domain
    struct ibv_mr *mr;             // Memory Region
    struct ibv_cq *cq;             // Completion Queue
    struct ibv_qp *qp;             // Queue Pair
    char *buffer;                  // Buffer to send
    size_t buffer_size;            // Size of the buffer
    uintptr_t remote_addr;         // Remote address
    uint32_t remote_rkey;          // Remote RKey

    // Context id
    int context_id;  // ID of the context
    __u32 remote_ip; // Remote IP

    // slices
    rdma_context_slice_t slices[N_TCP_PER_CONNECTION]; // Slices for each TCP connection
    int is_id_free[N_TCP_PER_CONNECTION];              // Free IDs for slices: 0 = free, 1 = used
    int is_server;                                     // TRUE if server, FALSE if client
} rdma_context_t;

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
    thread_pool_t *pool; // thread pool for worker threads
    int stop_threads;    // flag to stop the threads
} rdma_context_manager_t;

/** SETUP CONTEXT */

// Server-side functions
int rdma_server_setup(rdma_context_t *sctx, u_int16_t server_port);
int rdma_server_wait_client_connection(rdma_context_t *sctx);

// Client-side functions
int rdma_client_setup(rdma_context_t *cctx, uint32_t ip, u_int16_t port);
int rdma_client_connect(rdma_context_t *cctx);

// cleanup
int rdma_context_close(rdma_context_t *ctx);

/** COMMUNICATION */
// send and receive
int rdma_send_notification(rdma_context_t *ctx, rdma_communication_code_t code, int slice_id);
int rdma_recv_notification(rdma_context_t *ctx);

// write and read
int rdma_write_slice(rdma_context_t *ctx, rdma_context_slice_t *slice);

// polling
int rdma_poll_cq(rdma_context_t *ctx);
int rdma_poll_memory(transfer_buffer_t *buffer_to_read);

/** UTILS */

int rdma_new_slice(rdma_context_t *ctx, u_int16_t port);
int rdma_delete_slice_by_port(rdma_context_t *ctx, u_int16_t port);
int rdma_delete_slice_by_id(rdma_context_t *ctx, int slice_id);
int rdma_slice_id_from_port(rdma_context_t *ctx, uint16_t port);

/** WRAPPER */

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

/** THREAD POOL */

void rdma_recv_notfication_th(void *arg);
void *worker(void *arg);
thread_pool_t *thread_pool_create(int num_threads);
int thread_pool_add(thread_pool_t *pool, void (*function)(void *), void *arg);
void thread_pool_destroy(thread_pool_t *pool);

#endif // LIB_RDMA_H
