
#ifndef RDMA_CONNECTION_H
#define RDMA_CONNECTION_H

#pragma once
#include <stdint.h>
#include <infiniband/verbs.h>



struct rdma_connection_info {
    uint32_t qp_num;
    uint16_t lid;
    uint32_t psn;
    uint32_t rkey;
    uint64_t addr;
    union ibv_gid gid;  // for RoCE connections
} __attribute__((packed));


#endif // RDMA_CONNECTION_H
