
#ifndef RDMA_UTILS_H
#define RDMA_UTILS_H

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
#include <stdatomic.h>

#include "scap.h"
#include "sk_utils.h"
#include "config.h"

#define UNUSED(x) (void)(x)

#define MAX_PAYLOAD_SIZE (1024 * 4) // 8KB
#define MAX_N_MSG_PER_BUFFER 1024

#define RING_BUFFER_SIZE ((sizeof(rdma_msg_t) * MAX_N_MSG_PER_BUFFER) + 1)

#define FLUSH_THRESHOLD_N (400) // number of messages to flush: 40% of the buffer
#define FLUSH_INTERVAL_MS 1000

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t) * 5)
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))

#define INITIAL_CONTEXT_NUMBER 10
#define N_CONTEXT_REALLOC 5

#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

#define N_POLL_PER_CQ 1000

typedef enum rdma_communication_code rdma_communication_code_t;
typedef struct rdma_msg rdma_msg_t;
typedef struct rdma_ringbuffer rdma_ringbuffer_t;
typedef struct rdma_flag rdma_flag_t;
typedef struct rdma_context rdma_context_t;
typedef struct rdma_meta_info rdma_meta_info_t;

struct rdma_meta_info
{
    uintptr_t addr;
    uint32_t rkey;
};

/**
 * code that can be notified
 */
enum rdma_communication_code
{
    RDMA_DATA_READY = 10,
    EXCHANGE_REMOTE_INFO = 4,
    RDMA_CLOSE_CONTEXT = 5,
    NONE = -1
};

/**
 * notification structure
 */
typedef struct
{
    rdma_communication_code_t code; // code of the notification
    int slice_offset;               // offset of the slice in the buffer
    struct sock_id original_sk_id;  // id of the socket
} notification_data_t;

typedef struct
{
    notification_data_t from_server; // notification from server
    notification_data_t from_client; // notification from client
} notification_t;

struct rdma_flag
{
    atomic_uint flags;
};

enum ring_buffer_flags
{
    RING_BUFFER_FULL = 0x01,
    RING_BUFFER_EMPTY = 0x02,
    RING_BUFFER_POLLING = 0x04,
    RING_BUFFER_CAN_POLLING = 0x08,
};

enum msg_flags
{
    DATA_CONT = 0x02,
};

struct rdma_msg
{
    uint32_t msg_flags;            // flags
    struct sock_id original_sk_id; // id of the socket
    uint32_t msg_size;             // size of the message
    char msg[MAX_PAYLOAD_SIZE];    // message
};

struct rdma_ringbuffer
{
    rdma_flag_t flags;
    atomic_uint remote_write_index;
    atomic_uint local_write_index;
    atomic_uint read_index;
    rdma_msg_t data[MAX_N_MSG_PER_BUFFER];
};

struct rdma_context
{
    // RDMA
    struct rdma_event_channel *client_ec; // for client only
    struct rdma_cm_id *conn;              // Connection ID
    struct ibv_pd *pd;                    // Protection Domain
    struct ibv_mr *mr;                    // Memory Region
    struct ibv_qp *qp;                    // Queue Pair
    struct ibv_cq *send_cq;               // send completion queue
    struct ibv_cq *recv_cq;               // recv completion queue
    void *buffer;                         // Buffer to send
    size_t buffer_size;                   // Size of the buffer
    uintptr_t remote_addr;                // Remote address
    uint32_t remote_rkey;                 // Remote RKey

    // Context id
    __u32 remote_ip; // Remote IP

    int is_server; // TRUE if server, FALSE if client
    int is_ready;  // TRUE if the context is ready

    pthread_mutex_t mtx_tx; // to be sure only one thread is using the context at a time
    pthread_cond_t cond_tx; // condition variable for the threads
    int thread_busy_tx;     // flag to indicate if the context is busy

    pthread_mutex_t mtx_rx; // to be sure only one thread is using the context at a time
    pthread_cond_t cond_rx; // condition variable for the threads
    int thread_busy_rx;     // flag to indicate if the context is busy

    pthread_mutex_t mtx_polling; // to be sure only one thread is using the context at a time

    rdma_ringbuffer_t *ringbuffer_server; // Ring buffer for server
    rdma_ringbuffer_t *ringbuffer_client; // Ring buffer for client

    uint64_t last_flush_ns;
    pthread_mutex_t mtx_flush;
};

/** SETUP CONTEXT */

// Server-side functions
int rdma_server_handle_new_client(rdma_context_t *ctx, struct rdma_event_channel *server_ec);

// Client-side functions
int rdma_client_setup(rdma_context_t *cctx, uint32_t ip, uint16_t port);
int rdma_client_connect(rdma_context_t *cctx);

int rdma_context_close(rdma_context_t *ctx);
int rdma_setup_context(rdma_context_t *ctx);

/** COMMUNICATION */

// send and receive

int rdma_write_msg(rdma_context_t *ctx, char *data, int data_size, struct sock_id original_socket);

int rdma_read_msg(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks);

int rdma_flush_buffer(rdma_context_t *ctx, rdma_ringbuffer_t *ringbuffer);

// polling
int rdma_poll_cq_send(rdma_context_t *ctx);
int rdma_poll_memory(volatile uint32_t *flag_to_poll);
int rdma_set_polling_status(rdma_context_t *ctx, uint32_t is_polling);

int rdma_send_data_ready(rdma_context_t *ctx);
const char *get_op_name(rdma_communication_code_t code);
uint64_t get_time_ms();

#endif // RDMA_UTILS_H
