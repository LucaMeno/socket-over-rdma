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

int main() {
    struct rdma_event_channel *ec = rdma_create_event_channel();
    struct rdma_cm_id *listener = NULL, *conn = NULL;
    struct rdma_conn_param conn_param = { };
    struct ibv_pd *pd;
    struct ibv_mr *mr;
    char *buffer = malloc(MSG_SIZE);

    memset(buffer, 0, MSG_SIZE);

    rdma_create_id(ec, &listener, NULL, RDMA_PS_TCP);

    struct addrinfo *res;
    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };
    getaddrinfo(NULL, PORT, &hints, &res);
    rdma_bind_addr(listener, res->ai_addr);
    freeaddrinfo(res);
    rdma_listen(listener, 1);

    struct rdma_cm_event *event;
    rdma_get_cm_event(ec, &event);
    conn = event->id;
    rdma_ack_cm_event(event);

    pd = ibv_alloc_pd(conn->verbs);
    mr = ibv_reg_mr(pd, buffer, MSG_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    struct ibv_qp_init_attr qp_attr = {
        .cap.max_send_wr = 1,
        .cap.max_recv_wr = 1,
        .cap.max_send_sge = 1,
        .cap.max_recv_sge = 1,
        .qp_type = IBV_QPT_RC
    };

    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(conn->verbs, 2, NULL, NULL, 0);
    rdma_create_qp(conn, pd, &qp_attr);

    struct ibv_sge sge = {
        .addr = (uintptr_t)buffer,
        .length = MSG_SIZE,
        .lkey = mr->lkey
    };

    struct ibv_recv_wr recv_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1
    };

    struct ibv_recv_wr *bad_recv_wr;
    ibv_post_recv(conn->qp, &recv_wr, &bad_recv_wr);

    conn_param.initiator_depth = conn_param.responder_resources = 1;
    conn_param.rnr_retry_count = 7;

    rdma_accept(conn, &conn_param);

    rdma_get_cm_event(ec, &event); // Wait for established
    rdma_ack_cm_event(event);

    rdma_get_cm_event(ec, &event); // Wait for disconnection
    rdma_ack_cm_event(event);

    printf("Server received: '%s'\n", buffer);

    rdma_destroy_qp(conn);
    ibv_dereg_mr(mr);
    ibv_dealloc_pd(pd);
    rdma_destroy_id(conn);
    rdma_destroy_id(listener);
    rdma_destroy_event_channel(ec);
    free(buffer);
    return 0;
}
