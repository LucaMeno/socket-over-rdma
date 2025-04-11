#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>


#define SERVER_IP "192.168.109.133" // cambia con IP del server
#define PORT "7471"
#define MSG "Hello RDMA Server!"
#define MSG_SIZE 1024

int main() {
    struct rdma_event_channel *ec = rdma_create_event_channel();
    struct rdma_cm_id *conn = NULL;
    struct rdma_conn_param conn_param = { };
    struct ibv_pd *pd;
    struct ibv_mr *mr;
    char *buffer = malloc(MSG_SIZE);

    printf("Client: %s\n", MSG);

    strcpy(buffer, MSG);

    rdma_create_id(ec, &conn, NULL, RDMA_PS_TCP);

    struct addrinfo *res;
    getaddrinfo(SERVER_IP, PORT, NULL, &res);
    rdma_resolve_addr(conn, NULL, res->ai_addr, 2000);
    freeaddrinfo(res);

    struct rdma_cm_event *event;
    rdma_get_cm_event(ec, &event);
    rdma_ack_cm_event(event);

    rdma_resolve_route(conn, 2000);
    rdma_get_cm_event(ec, &event);
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

    conn_param.initiator_depth = conn_param.responder_resources = 1;
    conn_param.rnr_retry_count = 7;

    rdma_connect(conn, &conn_param);

    rdma_get_cm_event(ec, &event); // connection established
    rdma_ack_cm_event(event);

    struct ibv_sge sge = {
        .addr = (uintptr_t)buffer,
        .length = MSG_SIZE,
        .lkey = mr->lkey
    };

    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,
        .send_flags = IBV_SEND_SIGNALED
    };

    struct ibv_send_wr *bad_send_wr;
    ibv_post_send(conn->qp, &send_wr, &bad_send_wr);

    sleep(1); // Attendi che il messaggio venga letto
    rdma_disconnect(conn);

    rdma_destroy_qp(conn);
    ibv_dereg_mr(mr);
    ibv_dealloc_pd(pd);
    rdma_destroy_id(conn);
    rdma_destroy_event_channel(ec);
    free(buffer);
    return 0;
}
