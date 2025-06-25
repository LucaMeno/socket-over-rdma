#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>

#include "rdma_common.h"

#define TCP_PORT "7471"
#define TEST_MSG "Hello-from-server"
#define SIZE 1024

int tcp_server_listen()
{
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo *res;
    getaddrinfo(nullptr, TCP_PORT, &hints, &res);

    int fd = socket(res->ai_family, res->ai_socktype, 0);
    bind(fd, res->ai_addr, res->ai_addrlen);
    listen(fd, 1);
    freeaddrinfo(res);
    return fd;
}

int main()
{
    srand48(getpid());

    ibv_context *ctx = open_device();
    ibv_pd *pd = ibv_alloc_pd(ctx);
    ibv_cq *cq = ibv_create_cq(ctx, 16, nullptr, nullptr, 0);

    void *buf = aligned_alloc(4096, SIZE);
    memset(buf, 0, SIZE);
    strcpy(static_cast<char *>(buf), TEST_MSG);

    ibv_mr *mr = ibv_reg_mr(pd, buf, SIZE,
                            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

    ibv_qp_init_attr qpa = {};
    qpa.send_cq = cq;
    qpa.recv_cq = cq;
    qpa.qp_type = IBV_QPT_RC;
    qpa.cap = {.max_send_wr = 16, .max_recv_wr = 16, .max_send_sge = 1, .max_recv_sge = 1};

    ibv_qp *qp = ibv_create_qp(pd, &qpa);

    ibv_qp_attr attr = {};
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = 1;
    attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;

    if (ibv_modify_qp(qp, &attr,
                      IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
    {
        std::cerr << "Failed to modify QP to INIT state\n";
        exit(EXIT_FAILURE);
    }

    ibv_port_attr pattr;
    ibv_query_port(ctx, 1, &pattr);

    union ibv_gid gid;
    if (ibv_query_gid(ctx, 1, 0, &gid))
    {
        perror("ibv_query_gid");
        exit(EXIT_FAILURE);
    }

    conn_info local = {.lid = pattr.lid, .qp_num = qp->qp_num, .psn = gen_psn(), .rkey = mr->rkey, .addr = reinterpret_cast<uintptr_t>(buf), .gid = gid};

    std::cout << "Local connection info:\n"
              << "LID: " << local.lid << "\n"
              << "QP number: " << local.qp_num << "\n"
              << "PSN: " << local.psn << "\n"
              << "RKEY: " << local.rkey << "\nGID: ";
    for (int i = 0; i < 16; i++)
        std::printf("%02x", local.gid.raw[i]);
    std::printf("\nBuffer address: 0x%lx\n", local.addr);

    int listen_fd = tcp_server_listen();
    int sock = accept(listen_fd, nullptr, nullptr);

    conn_info remote;
    if (write(sock, &local, sizeof(local)) < 0 || read(sock, &remote, sizeof(remote)) < 0)
    {
        perror("TCP exchange");
        close(sock);
        exit(EXIT_FAILURE);
    }
    close(listen_fd);

    ibv_qp_attr rtr = {};
    rtr.qp_state = IBV_QPS_RTR;
    rtr.path_mtu = IBV_MTU_1024;
    rtr.dest_qp_num = remote.qp_num;
    rtr.rq_psn = remote.psn;
    rtr.max_dest_rd_atomic = 1;
    rtr.min_rnr_timer = 12;
    memset(&rtr.ah_attr, 0, sizeof(rtr.ah_attr));
    rtr.ah_attr.is_global = 1;
    rtr.ah_attr.port_num = 1;
    rtr.ah_attr.dlid = 0;
    rtr.ah_attr.grh.dgid = remote.gid;
    rtr.ah_attr.grh.sgid_index = 0;
    rtr.ah_attr.grh.hop_limit = 1;

    ibv_modify_qp(qp, &rtr,
                  IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                      IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                      IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);

    ibv_qp_attr attr2;
    ibv_qp_init_attr iattr;
    ibv_query_qp(qp, &attr2, IBV_QP_STATE, &iattr);
    std::cout << "QP state after RTR = " << attr2.qp_state << std::endl;

    ibv_qp_attr rts = {};
    rts.qp_state = IBV_QPS_RTS;
    rts.sq_psn = local.psn;
    rts.timeout = 14;
    rts.retry_cnt = 7;
    rts.rnr_retry = 7;
    rts.max_rd_atomic = 1;

    ibv_modify_qp(qp, &rts,
                  IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                      IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);

    std::cout << "Server ready. Waiting for RDMA Write...\n";
    sleep(3);
    std::cout << "Buffer now: \"" << static_cast<char *>(buf) << "\"\n";

    ibv_destroy_qp(qp);
    ibv_dereg_mr(mr);
    ibv_destroy_cq(cq);
    ibv_dealloc_pd(pd);
    ibv_close_device(ctx);
    free(buf);
    return 0;
}