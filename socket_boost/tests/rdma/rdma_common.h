/* common.h */

#ifndef RDMA_COMMON_H
#define RDMA_COMMON_H

#pragma once
#include <stdint.h>
#include <infiniband/verbs.h>
#include <iostream>

struct conn_info {
    uint16_t lid;
    uint32_t qp_num;
    uint32_t psn;
    uint32_t rkey;
    uint64_t addr;
    union ibv_gid gid;   /* piena di zeri su InfiniBand pure */
} __attribute__((packed));

ibv_context *open_device();
uint32_t gen_psn();


#endif // RDMA_COMMON_H