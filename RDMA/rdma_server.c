#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

#define PORT "7471"
#define MSG_SIZE 1024

struct rdma_server_context
{
    struct rdma_event_channel *ec;
    struct rdma_cm_id *listener;
    struct rdma_cm_id *conn;
    struct ibv_pd *pd;
    struct ibv_mr *mr;
    struct ibv_cq *cq;
    char *buffer;
};

void error_and_exit(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void setup_server(struct rdma_server_context *sctx)
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
}

void wait_for_client(struct rdma_server_context *sctx)
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
        .cap = {.max_send_wr = 1, .max_recv_wr = 1, .max_send_sge = 1, .max_recv_sge = 1},
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
}

void wait_for_msg(struct rdma_server_context *sctx)
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
}

void cleanup_server(struct rdma_server_context *sctx)
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
}

int main()
{
    struct rdma_server_context sctx = {};

    printf("Starting RDMA server...\n");
    setup_server(&sctx);
    printf("Listening for incoming connections...\n");
    wait_for_client(&sctx);
    printf("[Server] Waiting for message...\n");
    wait_for_msg(&sctx);

    cleanup_server(&sctx);
    return 0;
}