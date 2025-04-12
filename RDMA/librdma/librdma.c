

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

int error_and_exit(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
    return 1;
}

/** SERVER */

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

/** CLIENT */

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
