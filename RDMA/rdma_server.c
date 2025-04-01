#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <infiniband/verbs.h>

#define MSG_SIZE 64

int main() {
    struct ibv_device **dev_list;
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_mr *mr;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_recv_wr recv_wr, *bad_wr;
    struct ibv_sge sge;
    struct ibv_wc wc;
    
    char *buffer;
    int num_devices, ret;

    // Get RDMA devices
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        perror("Failed to get IB devices list");
        return 1;
    }

    // Open first available device
    ctx = ibv_open_device(dev_list[0]);
    ibv_free_device_list(dev_list);
    if (!ctx) {
        perror("Failed to open device");
        return 1;
    }

    // Allocate protection domain
    pd = ibv_alloc_pd(ctx);
    if (!pd) {
        perror("Failed to allocate PD");
        return 1;
    }

    // Allocate memory
    buffer = malloc(MSG_SIZE);
    memset(buffer, 0, MSG_SIZE);

    // Register memory region
    mr = ibv_reg_mr(pd, buffer, MSG_SIZE, IBV_ACCESS_LOCAL_WRITE);
    if (!mr) {
        perror("Failed to register MR");
        return 1;
    }

    // Create completion queue
    cq = ibv_create_cq(ctx, 1, NULL, NULL, 0);
    if (!cq) {
        perror("Failed to create CQ");
        return 1;
    }

    // Initialize queue pair attributes
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = cq;
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = 1;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;

    // Create queue pair
    qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        perror("Failed to create QP");
        return 1;
    }

    // Prepare receive work request
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)buffer;
    sge.length = MSG_SIZE;
    sge.lkey = mr->lkey;

    memset(&recv_wr, 0, sizeof(recv_wr));
    recv_wr.wr_id = 0;
    recv_wr.sg_list = &sge;
    recv_wr.num_sge = 1;

    // Post receive request
    ret = ibv_post_recv(qp, &recv_wr, &bad_wr);
    if (ret) {
        perror("Failed to post receive WR");
        return 1;
    }

    // Poll for completion
    while (ibv_poll_cq(cq, 1, &wc) == 0);

    if (wc.status == IBV_WC_SUCCESS) {
        printf("Received message: %s\n", buffer);
    } else {
        printf("Receive failed with status %d\n", wc.status);
    }

    // Cleanup
    ibv_destroy_qp(qp);
    ibv_destroy_cq(cq);
    ibv_dereg_mr(mr);
    ibv_dealloc_pd(pd);
    ibv_close_device(ctx);
    free(buffer);

    return 0;
}
