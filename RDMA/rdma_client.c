#define _POSIX_C_SOURCE 200112L

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
#include <errno.h>

#define SERVER_IP "192.168.109.133" // Remote server IP address
#define PORT "7471"                 // Port to connect to
#define MSG "AAAAA"                 // Message to send
#define MSG_SIZE 1024               // Buffer size

void error_and_exit(const char *msg);

struct rdma_client_context
{
    struct rdma_event_channel *ec;
    struct rdma_cm_id *conn;
    struct ibv_pd *pd;           // Protection Domain
    struct ibv_mr *mr;           // Memory Region
    struct ibv_cq *cq;           // Completion Queue
    struct ibv_qp *qp;           // Queue Pair
    char *buffer;                // Buffer to send
    struct rdma_cm_event *event; // Event for connection management
};

void setup_client(struct rdma_client_context *cctx)
{
    cctx->buffer = malloc(MSG_SIZE); // Allocate buffer for message

    cctx->ec = rdma_create_event_channel(); // Create an RDMA event channel

    // Create an RDMA communication identifier (conn) for TCP
    rdma_create_id(cctx->ec, &cctx->conn, NULL, RDMA_PS_TCP);

    // Resolve the server address
    printf("Resolving server address...\n");
    struct addrinfo *res;
    getaddrinfo(SERVER_IP, PORT, NULL, &res);
    rdma_resolve_addr(cctx->conn, NULL, res->ai_addr, 2000);
    freeaddrinfo(res);

    // Wait for address resolution to complete
    rdma_get_cm_event(cctx->ec, &cctx->event);
    rdma_ack_cm_event(cctx->event);

    // Resolve the route to the server, waiting for the route to be established
    rdma_resolve_route(cctx->conn, 2000); // Timeout in milliseconds
    rdma_get_cm_event(cctx->ec, &cctx->event);
    rdma_ack_cm_event(cctx->event);

    // Allocate protection domain (for memory registration)
    cctx->pd = ibv_alloc_pd(cctx->conn->verbs);

    // Register the buffer with the RDMA device
    cctx->mr = ibv_reg_mr(cctx->pd, cctx->buffer, MSG_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    // Initialize Queue Pair
    struct ibv_qp_init_attr qp_attr = {
        .cap.max_send_wr = 1,  // Max outstanding send requests
        .cap.max_recv_wr = 1,  // Max outstanding receive requests
        .cap.max_send_sge = 1, // Max scatter/gather elements for send
        .cap.max_recv_sge = 1, // Max scatter/gather elements for recv
        .qp_type = IBV_QPT_RC  // Reliable connection QP type
    };

    // Create a Completion Queue and assign it to send/recv
    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(cctx->conn->verbs, 2, NULL, NULL, 0);

    // Create the Queue Pair for the connection
    rdma_create_qp(cctx->conn, cctx->pd, &qp_attr);
}

void connect_to_server(struct rdma_client_context *cctx)
{
    // Set connection parameters
    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    // Initiate connection to the server
    if (rdma_connect(cctx->conn, &conn_param) != 0)
        error_and_exit("rdma_connect");

    // Wait for connection established event
    rdma_get_cm_event(cctx->ec, &cctx->event); // connection established
    rdma_ack_cm_event(cctx->event);
}

void cleanup_client(struct rdma_client_context *cctx)
{
    if (cctx->conn)
    {
        rdma_disconnect(cctx->conn);
        rdma_destroy_qp(cctx->conn);
        rdma_destroy_id(cctx->conn);
    }
    if (cctx->cq)
        ibv_destroy_cq(cctx->cq);
    if (cctx->mr)
        ibv_dereg_mr(cctx->mr);
    if (cctx->pd)
        ibv_dealloc_pd(cctx->pd);
    if (cctx->ec)
        rdma_destroy_event_channel(cctx->ec);
    if (cctx->buffer)
        free(cctx->buffer);
}

void send_rdma(struct rdma_client_context *cctx, char *msg, int msg_size)
{
    strcpy(cctx->buffer, msg); // Copy message to buffer

    // Define scatter/gather entry pointing to our buffer
    struct ibv_sge sge = {
        .addr = (uintptr_t)cctx->buffer,
        .length = MSG_SIZE,
        .lkey = cctx->mr->lkey // Local key from registered memory region
    };

    // Define send work request
    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,          // Send operation
        .send_flags = IBV_SEND_SIGNALED // Request completion notification
    };

    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(cctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        error_and_exit("Failed to post send");

    printf("Sent message: %s\n", cctx->buffer);
}

int main()
{
    struct rdma_client_context cctx;

    printf("Starting RDMA client...\n");
    setup_client(&cctx);
    printf("Connecting to server...\n");
    connect_to_server(&cctx);
    printf("Sending messages...\n");

    for (int i = 0; i < 20; i++)
    {
        snprintf(cctx.buffer, MSG_SIZE, "%s %d", MSG, i);
        send_rdma(&cctx, cctx.buffer, MSG_SIZE);
        sleep(1); // wait for the server to process
    }

    // disonnect and cleanup
    printf("Disconnecting...\n");
    cleanup_client(&cctx);

    return 0;
}

void error_and_exit(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    perror("Error details");
    printf("Cleaning up resources...\n");
    exit(EXIT_FAILURE);
}