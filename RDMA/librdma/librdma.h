
#ifndef LIB_RDMA_H
#define LIB_RDMA_H

#include <stdint.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

#define MAX_PAYLOAD_SIZE 512
#define SLICE_BUFFER_SIZE (2 * sizeof(transfer_buffer_t)) // size of the slice in memory. A slice is a double buffer used to exchange data

#define NOTIFICATION_OFFSET_SIZE (2 * sizeof(notification_t))
#define N_TCP_PER_CONNECTION 5
#define MR_SIZE ((SLICE_BUFFER_SIZE * N_TCP_PER_CONNECTION) + NOTIFICATION_OFFSET_SIZE)

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

typedef enum
{
    RDMA_WRITE_FINISHED = 1,
    RDMA_READ_FINISHED = 2,
} rdma_flags;

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
    char buff[MAX_PAYLOAD_SIZE];
    int buff_size;
} rdma_payload_t;

typedef struct
{
    int buffer_size;
    uint32_t flags;
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
int rdma_setup_server(rdma_context *sctx, const char *port);
int rdma_wait_for_client(rdma_context *sctx);
int set_notification_for_client(rdma_context *sctx, rdma_communication_code code, int slice_id);

// Client-side functions
int rdma_setup_client(rdma_context *cctx, const char *ip, const char *port);
int rdma_connect_server(rdma_context *cctx);
int set_notification_for_server(rdma_context *cctx, rdma_communication_code code, int slice_id);

// cleanup
int rdma_close(rdma_context *ctx);

/** COMMUNICATION */
int rdma_send_notification(rdma_context *ctx);
int rdma_listen_notification(rdma_context *ctx);

int rdma_write(rdma_context *ctx, rdma_context_slice *slice);

int rdma_poll_cq(rdma_context *ctx);
int rdma_is_cq_ready(rdma_context *ctx);

#endif // LIB_RDMA_H
