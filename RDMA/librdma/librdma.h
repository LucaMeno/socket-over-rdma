
#ifndef LIB_RDMA_H
#define LIB_RDMA_H

#include <stdint.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>


#define MR_SIZE 1024

struct rdma_context
{
    struct rdma_event_channel *ec; // Event channel
    struct rdma_cm_id *listener;   // Listener ID (SERVER only)
    struct rdma_cm_id *conn;       // Connection ID
    struct ibv_pd *pd;             // Protection Domain
    struct ibv_mr *mr;             // Memory Region
    struct ibv_cq *cq;             // Completion Queue
    struct ibv_qp *qp;             // Queue Pair
    char *buffer;                  // Buffer to send
    //size_t buffer_size;            // Size of the buffer
    int cq_notify;                 // CQ notifications mode: 0 = polling, 1 = event-based
};

// Server-side functions
int rdma_setup_server(struct rdma_context *sctx, const char * port/*,const char *ib_dev*/);
int rdma_wait_for_client(struct rdma_context *sctx);

// Client-side functions
int rdma_setup_client(struct rdma_context *cctx, const char *ip, const char * port);
int rdma_connect_server(struct rdma_context *cctx);

// Common cleanup
int rdma_close(struct rdma_context *ctx);

// Memory management
//int rdma_alloc_and_reg(struct rdma_context *ctx, size_t size, int access);
//int rdma_free_and_dereg(struct rdma_context *ctx);

// Communication
int rdma_send(struct rdma_context *ctx, int len);
int rdma_recv(struct rdma_context *ctx/*, size_t len*/);
int rdma_write(struct rdma_context *ctx, void *local_buf, uint64_t remote_addr, uint32_t rkey, size_t len);
int rdma_read(struct rdma_context *ctx, void *local_buf, uint64_t remote_addr, uint32_t rkey, size_t len);
//int rdma_notify_write(struct rdma_context *ctx);
//int rdma_notify_read(struct rdma_context *ctx);

// CQ handling
int rdma_poll_cq(struct rdma_context *ctx/*, struct ibv_wc *wc*/);
//int rdma_wait_for_completion(struct rdma_context *ctx, struct ibv_wc *wc);

#endif // LIB_RDMA_H
