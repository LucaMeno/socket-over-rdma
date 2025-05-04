
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

#include "scap.h"
#include "sk_utils.h"
#include "config.h"

#define UNUSED(x) (void)(x)

#define MAX_PAYLOAD_SIZE 512

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t))
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))
#define RING_BUFFER_HEADER_SIZE (sizeof(rdma_flag_t) + sizeof(uint32_t) + sizeof(uint32_t)) // size of the header of the ring buffer

#define INITIAL_CONTEXT_NUMBER 10
#define N_CONTEXT_REALLOC 5

#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

#define N_POLL_PER_CQ 1000

#define RING_BUFFER_SIZE 1024 * 1024 // 1MB

typedef struct rdma_ringbuffer rdma_ringbuffer_t;
typedef struct rdma_flag rdma_flag_t;
typedef struct rdma_msg rdma_msg_t;
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
typedef enum
{
    RDMA_DATA_READY = 10,
    EXCHANGE_REMOTE_INFO = 4,
    RDMA_CLOSE_CONTEXT = 5,
    NONE = -1
} rdma_communication_code_t;

/**
 * notification structure
 */
typedef struct
{
    rdma_communication_code_t code; // code of the notification
    int slice_offset;               // offset of the slice in the buffer
    // u_int16_t client_port;          // port of the client connected to this slice NOT NEEDED because is inside original_sk_id
    struct sock_id original_sk_id; // id of the socket
} notification_data_t;

typedef struct
{
    notification_data_t from_server; // notification from server
    notification_data_t from_client; // notification from client
} notification_t;

struct rdma_flag
{
    volatile uint32_t is_polling;
};

struct rdma_ringbuffer
{
    rdma_flag_t flags;
    uint32_t write_index;
    uint32_t read_index;
    char data[RING_BUFFER_SIZE];
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
    char *buffer;                         // Buffer to send
    size_t buffer_size;                   // Size of the buffer
    uintptr_t remote_addr;                // Remote address
    uint32_t remote_rkey;                 // Remote RKey

    // Context id
    int context_id;  // ID of the context
    __u32 remote_ip; // Remote IP

    rdma_ringbuffer_t *ringbuffer_server; // Ring buffer for server
    rdma_ringbuffer_t *ringbuffer_client; // Ring buffer for client

    int is_server;       // TRUE if server, FALSE if client
    pthread_mutex_t mtx; // for accssing the ring buffer

    pthread_t polling_thread; // thread for polling the circular buffer
};

struct rdma_msg
{
    struct sock_id original_sk_id; // id of the socket
    uint32_t msg_size;             // size of the message
    char msg[MAX_PAYLOAD_SIZE];    // message
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

int rdma_write_msg(rdma_context_t *ctx, rdma_msg_t *msg);

int rdma_read_msg(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks);

// polling
int rdma_poll_cq_send(rdma_context_t *ctx);
int rdma_poll_memory(volatile uint32_t *flag_to_poll);

int rdma_send_data_ready(rdma_context_t *ctx);
const char *get_op_name(rdma_communication_code_t code);

#endif // RDMA_UTILS_H
