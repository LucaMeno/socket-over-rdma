
#ifndef LIB_RDMA_H
#define LIB_RDMA_H

#include <stdint.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

#define MAX_PAYLOAD_SIZE 512
#define SLICE_BUFFER_SIZE (2 * sizeof(transfer_buffer_t)) // size of the slice in memory. A slice is a double buffer used to exchange data

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t))
#define N_TCP_PER_CONNECTION 5
#define MR_SIZE ((SLICE_BUFFER_SIZE * N_TCP_PER_CONNECTION) + NOTIFICATION_OFFSET_SIZE)

#define POLL_MEM_ATTEMPTS 10000

#define TRUE 1
#define FALSE 0

typedef struct
{
    uintptr_t addr;
    uint32_t rkey;
} rdma_meta_info;

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
} rdma_communication_code;

/**
 * notification structure
 */
typedef struct
{
    rdma_communication_code code; // code of the notification
    int slice_id;                 // ID of the slice
} notification_data;

typedef struct
{
    notification_data from_server; // notification from server
    notification_data from_client; // notification from client
} notification_t;

typedef struct
{
    volatile uint32_t data_ready;
} flags;

typedef struct
{
    int buffer_size;
    flags flags;
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
} rdma_context_slice;

/**
 * context between two different nodes
 */
typedef struct
{
    struct rdma_event_channel *ec;                   // Event channel
    struct rdma_cm_id *listener;                     // Listener ID (SERVER only)
    struct rdma_cm_id *conn;                         // Connection ID
    struct ibv_pd *pd;                               // Protection Domain
    struct ibv_mr *mr;                               // Memory Region
    struct ibv_cq *cq;                               // Completion Queue
    struct ibv_qp *qp;                               // Queue Pair
    char *buffer;                                    // Buffer to send
    size_t buffer_size;                              // Size of the buffer
    uintptr_t remote_addr;                           // Remote address
    uint32_t remote_rkey;                            // Remote RKey
    __u32 remote_ip;                                 // Remote IP
    rdma_context_slice slices[N_TCP_PER_CONNECTION]; // Slices for each TCP connection
    int is_id_free[N_TCP_PER_CONNECTION];            // Free IDs for slices: 0 = free, 1 = used
    int is_server;                                   // TRUE if server, FALSE if client
} rdma_context;

/** SETUP CONTEXT */

// Server-side functions
int rdma_server_setup(rdma_context *sctx, const char *port);
int rdma_server_wait_client_connection(rdma_context *sctx);

// Client-side functions
int rdma_client_setup(rdma_context *cctx, const char *ip, const char *port);
int rdma_client_connect(rdma_context *cctx);

// cleanup
int rdma_context_close(rdma_context *ctx);

/** COMMUNICATION */
// send and receive
int rdma_send_notification(rdma_context *ctx, rdma_communication_code code, int slice_id);
int rdma_recv_notification(rdma_context *ctx);

// write and read
int rdma_write_slice(rdma_context *ctx, rdma_context_slice *slice);

// polling
int rdma_poll_cq(rdma_context *ctx);
int rdma_poll_memory(rdma_context *ctx, rdma_context_slice *slice);

// management
int rdma_new_slice(rdma_context *ctx);
int rdma_delete_slice(rdma_context *ctx, int slice_id);

#endif // LIB_RDMA_H
