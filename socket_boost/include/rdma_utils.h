
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
#define RING_IDX(i) ((i) & (MAX_MSG_BUFFER - 1))

// THRESHOLDS MANAGEMENT

#define MIN_FLUSH_THRESHOLD 16
#define MID_FLUSH_THRESHOLD 256
#define MAX_FLUSH_THRESHOLD 1024

#define USE_MIN_FT_IF_SMALLER_THAN 64   // if the number of messages is smaller than this, use the minimum flush threshold
#define USE_MID_FT_IF_SMALLER_THAN 512  // if the number of messages is smaller than this, use the mid flush threshold
#define USE_MAX_FT_IF_SMALLER_THAN 2048 // if the number of messages is smaller than this, use the maximum flush threshold

// BUFFER CONFIGURATION
#define MAX_MSG_BUFFER (1024 * 8) // POWER OF 2!!!!!!!!!!!
#define MAX_PAYLOAD_SIZE (1024 * 8)

// READ
#define MSG_TO_READ_PER_THREAD 2048

// SIZE OF STRUCTURES
#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t) * 5)
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))
#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

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
    RDMA_MSG_ERROR = 0x04,
};

struct rdma_msg
{
    uint32_t msg_flags;            // flags
    struct sock_id original_sk_id; // id of the socket
    uint32_t msg_size;             // size of the message
    uint32_t number_of_slots;      // number of slots
    char msg[MAX_PAYLOAD_SIZE];    // message
};

struct rdma_ringbuffer
{
    rdma_flag_t flags;
    atomic_uint remote_write_index;
    atomic_uint remote_read_index;
    atomic_uint local_write_index;
    atomic_uint local_read_index;
    rdma_msg_t data[MAX_MSG_BUFFER];
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

    struct ibv_comp_channel *comp_channel; // Completion channel

    // Context id
    __u32 remote_ip; // Remote IP

    int is_server;        // TRUE if server, FALSE if client
    atomic_uint is_ready; // TRUE if the context is ready

    pthread_mutex_t mtx_tx; // used to wait for the context to be ready
    pthread_cond_t cond_tx; // used to signal the context is ready

    pthread_mutex_t mtx_rx; // to protect the read operations
    pthread_cond_t cond_rx; // used to protect the commit of the read operations (update remote read index)

    uint64_t last_flush_ns;    // last time the buffer was flushed, used to avoid flushing too often
    pthread_mutex_t mtx_flush; // to protect the flush operations

    pthread_mutex_t mtx_test; // mutex for testing purposes DEBUG

    atomic_uint n_msg_sent; // counter for the number of messages sent, used to determinate the threshold for flushing
    atomic_uint flush_threshold;

    uint64_t time_start_polling; // time when the polling started, used to be able to stop the polling thread
    uint32_t loop_with_no_msg;   // number of loops with no messages, used to stop the polling thread if there are no messages for a while

    uint64_t time_last_recv; // time when the last message was sent, used to determine if we should poll
    uint32_t n_recv_msg;     // number of messages recv operations, used to determine if we should poll

    rdma_ringbuffer_t *ringbuffer_server; // Ring buffer for server
    rdma_ringbuffer_t *ringbuffer_client; // Ring buffer for client
};

/** SETUP CONTEXT */

// CLIENT - SERVER
int rdma_server_handle_new_client(rdma_context_t *ctx, struct rdma_event_channel *server_ec);
int rdma_client_setup(rdma_context_t *cctx, uint32_t ip, uint16_t port);
int rdma_client_connect(rdma_context_t *cctx);

// SETUP
int rdma_context_destroy(rdma_context_t *ctx);
int rdma_context_init(rdma_context_t *ctx);

// COMMUNICATION
int rdma_write_msg(rdma_context_t *ctx, int src_fd, struct sock_id original_socket);
int rdma_read_msg(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks, uint32_t start_read_index, uint32_t end_read_index);
int rdma_flush_buffer(rdma_context_t *ctx, rdma_ringbuffer_t *ringbuffer);
int rdma_send_data_ready(rdma_context_t *ctx);

// POLLING
int rdma_set_polling_status(rdma_context_t *ctx, uint32_t is_polling);

// UTILS
const char *get_op_name(rdma_communication_code_t code);
uint64_t get_time_ms();

#endif // RDMA_UTILS_H
