
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
#include "sk_utils.h"

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
    int slice_offset;               // offset of the slice in the buffer
    u_int16_t client_port;          // port of the client connected to this slice
} notification_data_t;

typedef struct
{
    notification_data_t from_server; // notification from server
    notification_data_t from_client; // notification from client
} notification_t;

typedef struct
{
    volatile uint32_t data_ready;
    volatile uint32_t data_received;
    volatile uint32_t data_written;
} flags_t;

typedef struct
{
    int buffer_size;
    flags_t flags;
    char buffer[MAX_PAYLOAD_SIZE]; // this must be the last field in the struct
} transfer_buffer_t;

/**
 * slice of the context
 * each TCP socket will have its own slice
 * this is used to send and receive data
 */
typedef struct
{
    transfer_buffer_t *server_buffer;
    transfer_buffer_t *client_buffer;
    uint16_t client_port; // port of the client
    int socket_fd;        // socket fd
    int slice_offset;     // offset of the slice in the buffer
} rdma_context_slice_t;

/**
 * context between two different nodes
 */
typedef struct
{
    // RDMA
    struct rdma_event_channel *client_ec; // for client only
    struct rdma_cm_id *conn;              // Connection ID
    struct ibv_pd *pd;                    // Protection Domain
    struct ibv_mr *mr;                    // Memory Region
    struct ibv_cq *cq;                    // Completion Queue
    struct ibv_qp *qp;                    // Queue Pair
    char *buffer;                         // Buffer to send
    size_t buffer_size;                   // Size of the buffer
    uintptr_t remote_addr;                // Remote address
    uint32_t remote_rkey;                 // Remote RKey

    // Context id
    int context_id;  // ID of the context
    __u32 remote_ip; // Remote IP

    // slices
    rdma_context_slice_t slices[N_TCP_PER_CONNECTION]; // Slices for each TCP connection
    int is_id_free[N_TCP_PER_CONNECTION];              // Free IDs for slices: 0 = free, 1 = used // TODO: remove this and use client_port
    int is_server;                                     // TRUE if server, FALSE if client
} rdma_context_t;

/** SETUP CONTEXT */

// Server-side functions
int rdma_server_handle_new_client(rdma_context_t *ctx, struct rdma_event_channel *server_ec);

// Client-side functions
int rdma_client_setup(rdma_context_t *cctx, uint32_t ip, u_int16_t port);
int rdma_client_connect(rdma_context_t *cctx);

// cleanup
int rdma_context_close(rdma_context_t *ctx);
int rdma_setup_context(rdma_context_t *ctx);

/** COMMUNICATION */

// send and receive
int rdma_send_notification(rdma_context_t *ctx, rdma_communication_code_t code, int slice_offset, u_int16_t client_port);
int rdma_recv_notification(rdma_context_t *ctx);

// write and read
int rdma_write_slice(rdma_context_t *ctx, rdma_context_slice_t *slice);

// polling
int rdma_poll_cq(rdma_context_t *ctx);
int rdma_poll_memory(transfer_buffer_t *buffer_to_read);

/** UTILS */

int rdma_new_slice(rdma_context_t *ctx, u_int16_t port, int socket_fd);
int rdma_delete_slice_by_port(rdma_context_t *ctx, u_int16_t client_port);
int rdma_delete_slice_by_offset(rdma_context_t *ctx, int slice_offset);
int rdma_slice_offset_from_port(rdma_context_t *ctx, uint16_t client_port);

#endif // RDMA_UTILS_H
