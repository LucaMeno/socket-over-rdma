/* common.h */

#ifndef RDMA_COMMON_H
#define RDMA_COMMON_H

#pragma once
#include <stdint.h>
#include <infiniband/verbs.h>
#include <iostream>

struct conn_info
{
    uint16_t lid;
    uint32_t qp_num;
    uint32_t psn;
    uint32_t rkey;
    uint64_t addr;
    union ibv_gid gid;
} __attribute__((packed));

#define QP_N 4

typedef struct
{
    ibv_context *ctx;
    ibv_pd *pd;
    ibv_cq *send_cq[QP_N];
    ibv_cq *recv_cq;
    ibv_mr *mr;
    ibv_qp *qp;
    char *buffer;
    uintptr_t remote_addr;
    uint32_t remote_rkey;
    ibv_comp_channel *comp_channel;
} rdma_ctx_t;


ibv_context *open_device();
uint32_t gen_psn();


#endif // RDMA_COMMON_H