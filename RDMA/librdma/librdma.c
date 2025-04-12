

#define _POSIX_C_SOURCE 200112L

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

#include "librdma.h"

int ret_err(const char *msg)
{
    perror(msg);
    return -1;
}

int rdma_setup_server(struct rdma_context *sctx, const char *port /*,const char *ib_dev*/)
{
    struct addrinfo *res; // to hold resolved address

    struct addrinfo hints = {
        // hints for getaddrinfo
        .ai_flags = AI_PASSIVE,    // AI_PASSIVE for server
        .ai_family = AF_INET,      // AF_INET for IPv4
        .ai_socktype = SOCK_STREAM // TCP socket
    };

    // 1. Create event channel
    sctx->ec = rdma_create_event_channel();
    if (!sctx->ec)
        return ret_err("rdma_create_event_channel");

    // 2. Create RDMA ID for listener
    if (rdma_create_id(sctx->ec, &sctx->listener, NULL, RDMA_PS_TCP))
        return ret_err("rdma_create_id");

    // 3. Resolve address of server
    if (getaddrinfo(NULL, port, &hints, &res))
        return ret_err("getaddrinfo");

    // 4. Bind address to listener
    if (rdma_bind_addr(sctx->listener, res->ai_addr))
        return ret_err("rdma_bind_addr");

    freeaddrinfo(res);

    // 5. start listening for incoming connections
    if (rdma_listen(sctx->listener, 1))
        return ret_err("rdma_listen");

    // 6. set up the buffer
    sctx->buffer = malloc(MR_SIZE);
    if (!sctx->buffer)
        return ret_err("malloc buffer");

    memset(sctx->buffer, 0, MR_SIZE);

    return 0;
}

int rdma_wait_for_client(struct rdma_context *sctx)
{
    // 1. Wait for RDMA_CM_EVENT_CONNECT_REQUEST
    struct rdma_cm_event *event;
    if (rdma_get_cm_event(sctx->ec, &event))
        return ret_err("rdma_get_cm_event - rdma_wait_for_client");

    // 2. Extract conn ID from event
    sctx->conn = event->id;
    rdma_ack_cm_event(event);

    // 3. Allocate PD and register MR
    sctx->pd = ibv_alloc_pd(sctx->conn->verbs);
    sctx->mr = ibv_reg_mr(sctx->pd, sctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    // 4. Create CQ, QP and PD
    struct ibv_qp_init_attr qp_attr = {
        .cap = {
            .max_send_wr = 1,
            .max_recv_wr = 1,
            .max_send_sge = 1,
            .max_recv_sge = 1},
        .qp_type = IBV_QPT_RC};

    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(sctx->conn->verbs, 2, NULL, NULL, 0);

    sctx->cq = qp_attr.send_cq;

    if (rdma_create_qp(sctx->conn, sctx->pd, &qp_attr))
        return ret_err("rdma_create_qp");

    struct ibv_sge sge = {
        .addr = (uintptr_t)sctx->buffer, // address of the buffer
        .length = MR_SIZE,               // length of the buffer
        .lkey = sctx->mr->lkey           // local key of the registered memory region
    };

    struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};

    struct ibv_recv_wr *bad_wr;

    ibv_post_recv(sctx->conn->qp, &recv_wr, &bad_wr);

    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    // 6. Accept connection using rdma_accept
    if (rdma_accept(sctx->conn, &conn_param))
        ret_err("rdma_accept");

    if (rdma_get_cm_event(sctx->ec, &event))
        return ret_err("rdma_get_cm_event - rdma_wait_for_client");

    // 7. Wait for RDMA_CM_EVENT_ESTABLISHED
    rdma_ack_cm_event(event);

    return 0;
}

int rdma_setup_client(struct rdma_context *cctx, const char *ip, const char *port)
{
    // 1. Create event channel
    cctx->ec = rdma_create_event_channel();

    // 2. Create RDMA ID for connection
    rdma_create_id(cctx->ec, &cctx->conn, NULL, RDMA_PS_TCP);
    if (!cctx->conn)
        return ret_err("rdma_create_id - rdma_setup_client");

    // 3. Resolve address of server
    struct addrinfo *res;
    getaddrinfo(ip, port, NULL, &res);
    rdma_resolve_addr(cctx->conn, NULL, res->ai_addr, 2000);
    freeaddrinfo(res);
    if (!cctx->conn)
        return ret_err("rdma_resolve_addr - rdma_setup_client");

    // 4. Wait for RDMA_CM_EVENT_ADDR_RESOLVED
    struct rdma_cm_event *event = NULL;
    rdma_get_cm_event(cctx->ec, &event);
    rdma_ack_cm_event(event);

    // 5. Resolve route to server
    rdma_resolve_route(cctx->conn, 2000); // Timeout in milliseconds

    rdma_get_cm_event(cctx->ec, &event);

    // 6. Wait for RDMA_CM_EVENT_ROUTE_RESOLVED
    rdma_ack_cm_event(event);

    // 7. Allocate PD
    cctx->pd = ibv_alloc_pd(cctx->conn->verbs);
    if (!cctx->pd)
        return ret_err("ibv_alloc_pd - rdma_setup_client");

    // 8. set up the buffer
    cctx->buffer = malloc(MR_SIZE);
    cctx->mr = ibv_reg_mr(cctx->pd, cctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    // 9. Create CQ
    struct ibv_qp_init_attr qp_attr = {
        .cap.max_send_wr = 1,  // Max outstanding send requests
        .cap.max_recv_wr = 1,  // Max outstanding receive requests
        .cap.max_send_sge = 1, // Max scatter/gather elements for send
        .cap.max_recv_sge = 1, // Max scatter/gather elements for recv
        .qp_type = IBV_QPT_RC  // Reliable connection QP type
    };

    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(cctx->conn->verbs, 2, NULL, NULL, 0);
    if (!qp_attr.send_cq)
        return ret_err("ibv_create_cq - rdma_setup_client");

    // 10. Create QP with ctx->conn and PD
    rdma_create_qp(cctx->conn, cctx->pd, &qp_attr);
    if (!cctx->conn->qp)
        return ret_err("rdma_create_qp - rdma_setup_client");

    return 0;
}

int rdma_connect_server(struct rdma_context *cctx)
{
    // 1. Call rdma_connect
    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    if (rdma_connect(cctx->conn, &conn_param) != 0)
        return ret_err("rdma_connect - rdma_connect_server");

    // 2. Wait for RDMA_CM_EVENT_ESTABLISHED
    struct rdma_cm_event *event = NULL;
    rdma_get_cm_event(cctx->ec, &event); // connection established
    rdma_ack_cm_event(event);

    return 0;
}

int rdma_close(struct rdma_context *ctx)
{
    if (ctx->conn)
    {
        rdma_destroy_qp(ctx->conn);
        rdma_destroy_id(ctx->conn);
    }
    if (ctx->listener)
        rdma_destroy_id(ctx->listener);
    if (ctx->cq)
        ibv_destroy_cq(ctx->cq);
    if (ctx->mr)
        ibv_dereg_mr(ctx->mr);
    if (ctx->pd)
        ibv_dealloc_pd(ctx->pd);
    if (ctx->ec)
        rdma_destroy_event_channel(ctx->ec);
    if (ctx->buffer)
        free(ctx->buffer);

    return 0;
}

/*
int rdma_alloc_and_reg(struct rdma_context *ctx, size_t size, int access)
{
    // 1. Allocate memory with malloc
    // 2. Register memory region with ibv_reg_mr
    // 3. Store buffer and MR in context
    return 0;
}

int rdma_free_and_dereg(struct rdma_context *ctx)
{
    // 1. Deregister memory region
    // 2. Free buffer
    return 0;
}*/

int rdma_send(struct rdma_context *ctx, int len)
{
    // 1. Fill ibv_sge structure
    struct ibv_sge sge = {
        .addr = (uintptr_t)ctx->buffer,
        .length = len,
        .lkey = ctx->mr->lkey // Local key from registered memory region
    };

    // 2. Prepare ibv_send_wr with IBV_WR_SEND
    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,          // Send operation
        .send_flags = IBV_SEND_SIGNALED // Request completion notification
    };

    // 3. Post send with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return ret_err("Failed to post send - rdma_send");

    return 0;
}

int rdma_recv(struct rdma_context *ctx /*, size_t len*/)
{
    // 1. Fill ibv_sge structure
    struct ibv_sge sge = {
        .addr = (uintptr_t)ctx->buffer,
        .length = MR_SIZE,
        .lkey = ctx->mr->lkey};

    // 2. Prepare ibv_recv_wr with IBV_WR_RECV
    struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad_wr;

    // 3. Post receive with ibv_post_recv
    ibv_post_recv(ctx->conn->qp, &recv_wr, &bad_wr);

    return 0;
}

int rdma_poll_cq(struct rdma_context *ctx /*, struct ibv_wc *wc*/)
{
    struct ibv_wc wc;
    int num_completions;

    do
    {
        num_completions = ibv_poll_cq(ctx->cq, 1, &wc);
    } while (num_completions == 0); // poll until we get a completion

    if (num_completions < 0 || wc.status != IBV_WC_SUCCESS)
        return ret_err("Polling CQ failed or status not success - rdma_recv");

    return 0;
}

int rdma_write(struct rdma_context *ctx, void *local_buf, uint64_t remote_addr, uint32_t rkey, size_t len)
{
    // 1. Fill ibv_sge with local buffer
    struct ibv_sge sge = {
        .addr = (uintptr_t)local_buf, // address of the local buffer
        .length = len,                // length of the buffer
        .lkey = ctx->mr->lkey         // local key of the registered memory region
    };

    // 2. Prepare ibv_send_wr with IBV_WR_RDMA_WRITE
    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_RDMA_WRITE,        // RDMA write operation
        .send_flags = IBV_SEND_SIGNALED,    // Request completion notification
        .wr.rdma.remote_addr = remote_addr, // Remote address to write to
        .wr.rdma.rkey = rkey                // Remote key for the memory region
    };

    // 3. Set remote_addr and rkey in WR
    // (already done in the send_wr structure)

    // 4. Post send with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return ret_err("Failed to post send - rdma_write");

    return 0;
}

int rdma_read(struct rdma_context *ctx, void *local_buf, uint64_t remote_addr, uint32_t rkey, size_t len)
{
    // 1. Fill ibv_sge with local buffer
    struct ibv_sge sge = {
        .addr = (uintptr_t)local_buf, // address of the local buffer
        .length = len,                // length of the buffer
        .lkey = ctx->mr->lkey         // local key of the registered memory region
    };

    // 2. Prepare ibv_send_wr with IBV_WR_RDMA_READ
    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_RDMA_READ,         // RDMA read operation
        .send_flags = IBV_SEND_SIGNALED,    // Request completion notification
        .wr.rdma.remote_addr = remote_addr, // Remote address to read from
        .wr.rdma.rkey = rkey                // Remote key for the memory region
    };

    // 3. Set remote_addr and rkey in WR
    // (already done in the send_wr structure)

    // 4. Post send with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return ret_err("Failed to post send - rdma_read");

    return 0;
}
/*
int rdma_notify_write(struct rdma_context *ctx)
{
    // 1. Optionally send a small message with send_with_imm
    // 2. Or perform RDMA write on remote flag
    return 0;
}

int rdma_notify_read(struct rdma_context *ctx)
{
    // 1. Same strategy as notify_write
    return 0;
}

int rdma_wait_for_completion(struct rdma_context *ctx, struct ibv_wc *wc)
{
    // 1. If event-based: wait on CQ event and then poll
    // 2. If polling: loop on ibv_poll_cq until completion
    return 0;
}*/

/*

int setup_server(struct rdma_context *sctx)
{
    struct addrinfo *res;
    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM};

    sctx->ec = rdma_create_event_channel();
    if (!sctx->ec)
        error_and_exit("rdma_create_event_channel");

    if (rdma_create_id(sctx->ec, &sctx->listener, NULL, RDMA_PS_TCP))
        error_and_exit("rdma_create_id");

    if (getaddrinfo(NULL, PORT, &hints, &res))
        error_and_exit("getaddrinfo");

    if (rdma_bind_addr(sctx->listener, res->ai_addr))
        error_and_exit("rdma_bind_addr");
    freeaddrinfo(res);

    if (rdma_listen(sctx->listener, 1))
        error_and_exit("rdma_listen");

    sctx->buffer = malloc(MSG_SIZE);
    if (!sctx->buffer)
        error_and_exit("malloc buffer");
    memset(sctx->buffer, 0, MSG_SIZE);

    return 0;
}

int wait_for_client(struct rdma_context *sctx)
{
    struct rdma_cm_event *event;
    if (rdma_get_cm_event(sctx->ec, &event))
        error_and_exit("rdma_get_cm_event");

    sctx->conn = event->id;
    rdma_ack_cm_event(event);

    sctx->pd = ibv_alloc_pd(sctx->conn->verbs);
    sctx->mr = ibv_reg_mr(sctx->pd, sctx->buffer, MSG_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    struct ibv_qp_init_attr qp_attr = {
        .cap = {
            .max_send_wr = 1,
            .max_recv_wr = 1,
            .max_send_sge = 1,
            .max_recv_sge = 1},
        .qp_type = IBV_QPT_RC};

    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(sctx->conn->verbs, 2, NULL, NULL, 0);

    sctx->cq = qp_attr.send_cq;

    if (rdma_create_qp(sctx->conn, sctx->pd, &qp_attr))
        error_and_exit("rdma_create_qp");

    struct ibv_sge sge = {
        .addr = (uintptr_t)sctx->buffer,
        .length = MSG_SIZE,
        .lkey = sctx->mr->lkey};
    struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad_wr;
    ibv_post_recv(sctx->conn->qp, &recv_wr, &bad_wr);

    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    if (rdma_accept(sctx->conn, &conn_param))
        error_and_exit("rdma_accept");

    if (rdma_get_cm_event(sctx->ec, &event))
        error_and_exit("rdma_get_cm_event (established)");

    rdma_ack_cm_event(event);

    return 0;
}

int wait_for_msg(struct rdma_context *sctx)
{
    while (1)
    {
        // Poll on the completion queue for incoming messages
        struct ibv_wc wc;
        int num_completions;

        do
        {
            num_completions = ibv_poll_cq(sctx->cq, 1, &wc);
        } while (num_completions == 0); // poll until we get a completion

        if (num_completions < 0)
        {
            fprintf(stderr, "Errore durante polling della Completion Queue\n");
            break;
        }

        if (wc.status != IBV_WC_SUCCESS)
        {
            fprintf(stderr, "Errore nella work completion: %s\n", ibv_wc_status_str(wc.status));
            break;
        }
        printf("[Server] Received: %s\n", sctx->buffer);

        // repost the receive work request
        struct ibv_sge sge = {
            .addr = (uintptr_t)sctx->buffer,
            .length = MSG_SIZE,
            .lkey = sctx->mr->lkey};
        struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
        struct ibv_recv_wr *bad_wr;
        ibv_post_recv(sctx->conn->qp, &recv_wr, &bad_wr);
    }

    return 0;
}

int cleanup_server(struct rdma_context *sctx)
{
    if (sctx->conn)
    {
        rdma_destroy_qp(sctx->conn);
        rdma_destroy_id(sctx->conn);
    }
    if (sctx->listener)
        rdma_destroy_id(sctx->listener);
    if (sctx->cq)
        ibv_destroy_cq(sctx->cq);
    if (sctx->mr)
        ibv_dereg_mr(sctx->mr);
    if (sctx->pd)
        ibv_dealloc_pd(sctx->pd);
    if (sctx->ec)
        rdma_destroy_event_channel(sctx->ec);
    if (sctx->buffer)
        free(sctx->buffer);

    return 0;
}

* CLIENT *

int setup_client(struct rdma_context *cctx)
{
    cctx->buffer = malloc(MSG_SIZE); // Allocate buffer for message

    cctx->ec = rdma_create_event_channel(); // Create an RDMA event channel

    // Create an RDMA communication identifier (conn) for TCP
    rdma_create_id(cctx->ec, &cctx->conn, NULL, RDMA_PS_TCP);

    // Resolve the server address
    printf("Resolving server address...\n");
    struct addrinfo *res;
    getaddrinfo(SERVER_IP, PORT, NULL, &res);
    rdma_resolve_addr(cctx->conn, NULL, res->ai_addr, 2000);
    freeaddrinfo(res);

    // Wait for address resolution to complete
    rdma_get_cm_event(cctx->ec, &cctx->event);
    rdma_ack_cm_event(cctx->event);

    // Resolve the route to the server, waiting for the route to be established
    rdma_resolve_route(cctx->conn, 2000); // Timeout in milliseconds
    rdma_get_cm_event(cctx->ec, &cctx->event);
    rdma_ack_cm_event(cctx->event);

    // Allocate protection domain (for memory registration)
    cctx->pd = ibv_alloc_pd(cctx->conn->verbs);

    // Register the buffer with the RDMA device
    cctx->mr = ibv_reg_mr(cctx->pd, cctx->buffer, MSG_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    // Initialize Queue Pair
    struct ibv_qp_init_attr qp_attr = {
        .cap.max_send_wr = 1,  // Max outstanding send requests
        .cap.max_recv_wr = 1,  // Max outstanding receive requests
        .cap.max_send_sge = 1, // Max scatter/gather elements for send
        .cap.max_recv_sge = 1, // Max scatter/gather elements for recv
        .qp_type = IBV_QPT_RC  // Reliable connection QP type
    };

    // Create a Completion Queue and assign it to send/recv
    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(cctx->conn->verbs, 2, NULL, NULL, 0);

    // Create the Queue Pair for the connection
    rdma_create_qp(cctx->conn, cctx->pd, &qp_attr);

    return 0;
}

int connect_to_server(struct rdma_context *cctx)
{
    // Set connection parameters
    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    // Initiate connection to the server
    if (rdma_connect(cctx->conn, &conn_param) != 0)
        error_and_exit("rdma_connect");

    // Wait for connection established event
    rdma_get_cm_event(cctx->ec, &cctx->event); // connection established
    rdma_ack_cm_event(cctx->event);

    return 0;
}

int cleanup_client(struct rdma_context *cctx)
{
    if (cctx->conn)
    {
        rdma_disconnect(cctx->conn);
        rdma_destroy_qp(cctx->conn);
        rdma_destroy_id(cctx->conn);
    }
    if (cctx->cq)
        ibv_destroy_cq(cctx->cq);
    if (cctx->mr)
        ibv_dereg_mr(cctx->mr);
    if (cctx->pd)
        ibv_dealloc_pd(cctx->pd);
    if (cctx->ec)
        rdma_destroy_event_channel(cctx->ec);
    if (cctx->buffer)
        free(cctx->buffer);

    return 0;
}

int send_rdma(struct rdma_context *cctx, char *msg, int msg_size)
{
    strcpy(cctx->buffer, msg); // Copy message to buffer

    // Define scatter/gather entry pointing to our buffer
    struct ibv_sge sge = {
        .addr = (uintptr_t)cctx->buffer,
        .length = msg_size,
        .lkey = cctx->mr->lkey // Local key from registered memory region
    };

    // Define send work request
    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,          // Send operation
        .send_flags = IBV_SEND_SIGNALED // Request completion notification
    };

    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(cctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        error_and_exit("Failed to post send");

    printf("Sent message: %s\n", cctx->buffer);

    return 0;
}
*/