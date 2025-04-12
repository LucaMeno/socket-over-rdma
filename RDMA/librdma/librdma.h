
#ifndef LIB_RDMA_H
#define LIB_RDMA_H

#define PORT "7471"
#define MSG_SIZE 1024
#define SERVER_IP "192.168.109.132"
#define MSG "AAAAA"

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
    size_t buffer_size;            // Size of the buffer
    struct rdma_cm_event *event;   // Event for connection management
    int cq_notify;                 // CQ notifications mode: 0 = polling, 1 = event-based
};

/** SERVER */

int setup_server(struct rdma_context *ctx);

int wait_for_client(struct rdma_context *ctx);

int wait_for_msg(struct rdma_context *ctx);

int cleanup_server(struct rdma_context *ctx);


/** CLIENT */

int setup_client(struct rdma_context *ctx);

int connect_to_server(struct rdma_context *ctx);

int send_rdma(struct rdma_context *ctx, char *msg, int msg_size);

int cleanup_client(struct rdma_context *ctx);

#endif // LIB_RDMA_H
