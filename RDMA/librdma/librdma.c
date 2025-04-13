

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

#include "librdma.h"

int ret_err(const char *msg)
{
    perror(msg);
    return -1;
}

/** SETUP C-S */

int rdma_setup_server(rdma_context *sctx, const char *port)
{
    sctx->slices = (rdma_context_slice **)malloc(N_TCP_PER_CONNECTION * sizeof(rdma_context_slice *));
    for (int i = 0; i < N_TCP_PER_CONNECTION; i++)
    {
        // TODOOOOOOOOOOOOO
        sctx->slices[i] = (rdma_context_slice *)(sizeof(rdma_context_slice));
        sctx->slices[i] = NULL;
        sctx->free_ids[i] = 0;
    }

    struct addrinfo *res; // to hold resolved address

    struct addrinfo hints = {
        // hints for getaddrinfo
        .ai_flags = AI_PASSIVE,    // AI_PASSIVE for server
        .ai_family = AF_INET,      // AF_INET for IPv4
        .ai_socktype = SOCK_STREAM // TCP socket
    };

    // 1. Create event channel
    sctx->ec = rdma_create_event_channel();
    if (!sctx->ec)
        return ret_err("rdma_create_event_channel - rdma_setup_server");

    // 2. Create RDMA ID for listener
    if (rdma_create_id(sctx->ec, &sctx->listener, NULL, RDMA_PS_TCP))
        return ret_err("rdma_create_id");

    // 3. Resolve address of server
    if (getaddrinfo(NULL, port, &hints, &res))
        return ret_err("getaddrinfo");

    // 4. Bind address to listener
    if (rdma_bind_addr(sctx->listener, res->ai_addr))
        return ret_err("rdma_bind_addr");

    freeaddrinfo(res);

    // 5. start listening for incoming connections
    if (rdma_listen(sctx->listener, 1))
        return ret_err("rdma_listen");

    // 6. set up the buffer
    sctx->buffer = malloc(MR_SIZE);
    if (!sctx->buffer)
        return ret_err("malloc buffer - rdma_setup_server");
    // memset(sctx->buffer, 0, MR_SIZE);

    sctx->buffer_size = MR_SIZE;

    return 0;
}

int rdma_wait_for_client(rdma_context *sctx)
{
    // 1. Wait for RDMA_CM_EVENT_CONNECT_REQUEST
    struct rdma_cm_event *event;
    if (rdma_get_cm_event(sctx->ec, &event))
        return ret_err("rdma_get_cm_event - rdma_wait_for_client");

    // 2. Extract conn ID from event and also get the remote IP
    sctx->conn = event->id;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)&event->id->route.addr.src_addr;
    sctx->remote_ip = addr_in->sin_addr.s_addr;
    rdma_ack_cm_event(event);

    // 3. Allocate PD and register MR
    sctx->pd = ibv_alloc_pd(sctx->conn->verbs);

    sctx->mr = ibv_reg_mr(sctx->pd, sctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    sctx->buffer_size = MR_SIZE;

    // 4. Create CQ and QP
    struct ibv_qp_init_attr qp_attr = {
        .cap = {
            .max_send_wr = 10,  // Max outstanding send requests
            .max_recv_wr = 10,  // Max outstanding receive requests
            .max_send_sge = 10, // Max scatter/gather elements for send
            .max_recv_sge = 10  // Max scatter/gather elements for recv
        },
        .qp_type = IBV_QPT_RC // Reliable connection QP type
    };

    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(sctx->conn->verbs, 2, NULL, NULL, 0);
    if (!qp_attr.send_cq)
        return ret_err("ibv_create_cq - rdma_wait_for_client");

    sctx->cq = qp_attr.send_cq;

    if (rdma_create_qp(sctx->conn, sctx->pd, &qp_attr))
        return ret_err("rdma_create_qp");

    // Post a receive work request for receiving the remote address and rkey
    struct ibv_sge sge = {
        .addr = (uintptr_t)sctx->buffer, // address of the buffer
        .length = (sizeof(notification_t) + sizeof(rdma_meta_info)),
        .lkey = sctx->mr->lkey // local key of the registered memory region
    };
    struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad_wr;
    ibv_post_recv(sctx->conn->qp, &recv_wr, &bad_wr);
    if (bad_wr)
        return ret_err("Failed to post recv - rdma_wait_for_client");

    rdma_meta_info info = {
        .addr = (uintptr_t)sctx->buffer,
        .rkey = sctx->mr->rkey};

    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7,
        .private_data = (void *)&info,
        .private_data_len = sizeof(rdma_meta_info)};

    // 6. Accept connection using rdma_accept
    if (rdma_accept(sctx->conn, &conn_param))
        ret_err("rdma_accept");

    if (rdma_get_cm_event(sctx->ec, &event))
        return ret_err("rdma_get_cm_event - rdma_wait_for_client");

    // 7. Wait for RDMA_CM_EVENT_ESTABLISHED
    rdma_ack_cm_event(event);

    return rdma_listen_notification(sctx); // needed to exchange remote info
}

int rdma_setup_client(rdma_context *cctx, const char *ip, const char *port)
{
    cctx->slices = (rdma_context_slice **)malloc(N_TCP_PER_CONNECTION * sizeof(rdma_context_slice *));
    for (int i = 0; i < N_TCP_PER_CONNECTION; i++)
    {
        cctx->slices[i] = (rdma_context_slice *)(sizeof(rdma_context_slice));
        cctx->slices[i] = NULL;
        cctx->free_ids[i] = 0;
    }

    // 1. Create event channel
    cctx->ec = rdma_create_event_channel();

    // 2. Create RDMA ID for connection
    rdma_create_id(cctx->ec, &cctx->conn, NULL, RDMA_PS_TCP);
    if (!cctx->conn)
        return ret_err("rdma_create_id - rdma_setup_client");

    // 3. Resolve address of server
    struct addrinfo *res;
    getaddrinfo(ip, port, NULL, &res);
    rdma_resolve_addr(cctx->conn, NULL, res->ai_addr, 2000);
    freeaddrinfo(res);
    if (!cctx->conn)
        return ret_err("rdma_resolve_addr - rdma_setup_client");

    cctx->remote_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

    // 4. Wait for RDMA_CM_EVENT_ADDR_RESOLVED
    struct rdma_cm_event *event = NULL;
    rdma_get_cm_event(cctx->ec, &event);
    rdma_ack_cm_event(event);

    // 5. Resolve route to server
    rdma_resolve_route(cctx->conn, 2000); // Timeout in milliseconds
    rdma_get_cm_event(cctx->ec, &event);

    // 6. Wait for RDMA_CM_EVENT_ROUTE_RESOLVED
    rdma_ack_cm_event(event);

    // 7. Allocate PD
    cctx->pd = ibv_alloc_pd(cctx->conn->verbs);
    if (!cctx->pd)
        return ret_err("ibv_alloc_pd - rdma_setup_client");

    // 8. set up the buffer
    cctx->buffer = malloc(MR_SIZE);
    if (!cctx->buffer)
        return ret_err("malloc buffer - rdma_setup_client");

    cctx->buffer_size = MR_SIZE;

    cctx->mr = ibv_reg_mr(cctx->pd, cctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    // 9. Create CQ
    struct ibv_qp_init_attr qp_attr = {
        .cap.max_send_wr = 10,  // Max outstanding send requests
        .cap.max_recv_wr = 10,  // Max outstanding receive requests
        .cap.max_send_sge = 10, // Max scatter/gather elements for send
        .cap.max_recv_sge = 10, // Max scatter/gather elements for recv
        .qp_type = IBV_QPT_RC   // Reliable connection QP type
    };

    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(cctx->conn->verbs, 2, NULL, NULL, 0);
    if (!qp_attr.send_cq)
        return ret_err("ibv_create_cq - rdma_setup_client");

    cctx->cq = qp_attr.send_cq; // :-(

    // 10. Create QP with ctx->conn and PD
    rdma_create_qp(cctx->conn, cctx->pd, &qp_attr);
    if (!cctx->conn->qp)
        return ret_err("rdma_create_qp - rdma_setup_client");

    return 0;
}

int rdma_connect_server(rdma_context *cctx)
{
    // 1. Call rdma_connect
    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    if (rdma_connect(cctx->conn, &conn_param) != 0)
        return ret_err("rdma_connect - rdma_connect_server");

    // 2. Wait for RDMA_CM_EVENT_ESTABLISHED
    struct rdma_cm_event *event = NULL;
    rdma_get_cm_event(cctx->ec, &event); // connection established

    // retrieve the remote address and rkey
    rdma_meta_info *info = (rdma_meta_info *)event->param.conn.private_data;
    cctx->remote_addr = info->addr;
    cctx->remote_rkey = info->rkey;

    rdma_ack_cm_event(event);

    printf("C: Remote address: %p, Remote rkey: %u\n", (void *)cctx->remote_addr, cctx->remote_rkey);

    // post a SEND work request to send the remote address and rkey
    notification_t *notification = (notification_t *)cctx->buffer;
    notification->code = EXCHANGE_REMOTE_INFO;
    notification->slice_id = -1; // not used

    rdma_meta_info *remote_info = (rdma_meta_info *)(cctx->buffer + sizeof(notification_t));
    remote_info->addr = (uintptr_t)cctx->buffer;
    remote_info->rkey = cctx->mr->rkey;

    // post
    struct ibv_sge sge = {
        .addr = (uintptr_t)cctx->buffer, // address of the buffer
        .length = (sizeof(notification_t) + sizeof(rdma_meta_info)),
        .lkey = cctx->mr->lkey // Local key from registered memory region
    };

    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,          // Send operation
        .send_flags = IBV_SEND_SIGNALED // Request completion notification
    };

    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(cctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return ret_err("Failed to post send - rdma_connect_server");

    sleep(2);
    return 0;
}

/** COMMUNICATION */

int rdma_close(rdma_context *ctx)
{
    if (ctx->conn)
    {
        rdma_destroy_qp(ctx->conn);
        rdma_destroy_id(ctx->conn);
    }
    if (ctx->listener)
        rdma_destroy_id(ctx->listener);
    if (ctx->cq)
        ibv_destroy_cq(ctx->cq);
    if (ctx->mr)
        ibv_dereg_mr(ctx->mr);
    if (ctx->pd)
        ibv_dealloc_pd(ctx->pd);
    if (ctx->ec)
        rdma_destroy_event_channel(ctx->ec);
    if (ctx->buffer)
        free(ctx->buffer);

    return 0;
}

int rdma_send_notification(rdma_context *ctx)
{
    // 1. Fill ibv_sge structure
    struct ibv_sge sge = {
        .addr = (uintptr_t)ctx->buffer, // address of the buffer
        .length = sizeof(notification_t),
        .lkey = ctx->mr->lkey // Local key from registered memory region
    };

    // 2. Prepare ibv_send_wr with IBV_WR_SEND
    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,          // Send operation
        .send_flags = IBV_SEND_SIGNALED // Request completion notification
    };

    // 3. Post send with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return ret_err("Failed to post send - rdma_send_notification");

    return 0;
}

int rdma_listen_notification(rdma_context *ctx)
{
    // 1. Poll the completion queue
    if (rdma_poll_cq(ctx) != 0)
        return ret_err("Failed to poll CQ - rdma_listen_notification");

    // 3. post a new receive work request
    // post another receive work request
    struct ibv_sge sge = {
        .addr = (uintptr_t)ctx->buffer, // address of the buffer
        .length = sizeof(notification_t),
        .lkey = ctx->mr->lkey};

    // Prepare ibv_recv_wr with IBV_WR_RECV
    struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad_wr;

    // Post receive with ibv_post_recv
    ibv_post_recv(ctx->conn->qp, &recv_wr, &bad_wr);

    if (bad_wr)
        return ret_err("Failed to post recv - rdma_recv");

    // 2. check the notification
    notification_t *notification = (notification_t *)ctx->buffer;

    switch (notification->code)
    {
    case EXCHANGE_REMOTE_INFO:
        printf("Exchange remote info notification received\n");
        rdma_meta_info *remote_info = (rdma_meta_info *)(ctx->buffer + sizeof(notification_t));
        // save the remote address and rkey
        ctx->remote_addr = remote_info->addr;
        ctx->remote_rkey = remote_info->rkey;

        // server
        printf("S: Remote address: %p, Remote rkey: %u\n", (void *)ctx->remote_addr, ctx->remote_rkey);

        break;

    case TEST:
        printf("Test notification received\n");
        break;

    case RDMA_DATA_READY:
        printf("Data ready notification received\n");
        int redy_slice_id = notification->slice_id;
        if (redy_slice_id < 0 || redy_slice_id >= N_TCP_PER_CONNECTION || ctx->free_ids[redy_slice_id] == 0)
            return ret_err("Invalid slice ID - rdma_listen_notification RDMA_DATA_READY");

        printf("Data ready in slice %d\n", redy_slice_id);
        break;

    case RDMA_NEW_SLICE:
        printf("New slice notification received, slice ID: %d\n", notification->slice_id);
        int slice_id = notification->slice_id;

        if (slice_id < 0 || slice_id >= N_TCP_PER_CONNECTION || ctx->free_ids[slice_id] == 1)
            return ret_err("Invalid slice ID - rdma_listen_notification RDMA_NEW_SLICE");

        ctx->free_ids[slice_id] = 1; // Mark the slice as used

        // save the pointer to the slice
        ctx->slices[slice_id] = (rdma_context_slice *)(ctx->buffer + sizeof(notification_t) +
                                                       slice_id * SLICE_SIZE);

        break;

    case RDMA_DELETE_SLICE:
        printf("Delete slice notification received, slice ID: %d\n", notification->slice_id);
        int delete_slice_id = notification->slice_id;

        if (delete_slice_id < 0 || delete_slice_id >= N_TCP_PER_CONNECTION || ctx->free_ids[delete_slice_id] == 0)
            return ret_err("Invalid slice ID - rdma_listen_notification RDMA_DELETE_SLICE");

        ctx->free_ids[delete_slice_id] = 0; // Mark the slice as free

        // free the slice
        ctx->slices[delete_slice_id] = NULL;

        break;
    default:
        printf("Unknown notification code: %d\n", notification->code);
        break;
    }

    return 0;
}

int rdma_write(rdma_context *ctx, rdma_context_slice *slice)
{
    struct ibv_send_wr send_wr = {};
    struct ibv_sge sge;

    // 1. Fill ibv_sge with local buffer
    sge.addr = (uintptr_t)slice->send_buffer; // Local address of the buffer
    sge.length = slice->send_buffer_size;     // Length of the buffer
    sge.lkey = ctx->mr->lkey;

    // 2. Prepare ibv_send_wr with IBV_WR_RDMA_WRITE
    send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.wr.rdma.remote_addr = (uintptr_t)(ctx->remote_addr +
                                              sizeof(notification_t) +
                                              (slice->slice_id * sizeof(rdma_context_slice))); // Remote address where to write
    send_wr.wr.rdma.rkey = ctx->remote_rkey;                                                   // Remote memory key
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;

    // 4. Post send in SQ with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return ret_err("Failed to post send - rdma_write");

    return 0;
}

int rdma_poll_cq(rdma_context *ctx)
{
    if (ctx->cq == NULL)
        return ret_err("CQ is NULL - rdma_poll_cq");

    struct ibv_wc wc;
    int num_completions;
    do
    {
        num_completions = ibv_poll_cq(ctx->cq, 1, &wc);
    } while (num_completions == 0); // poll until we get a completion

    if (num_completions < 0)
        return ret_err("Failed to poll CQ - rdma_poll_cq");
    if (wc.status != IBV_WC_SUCCESS)
    {
        fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
        return ret_err("Failed to poll CQ - rdma_poll_cq");
    }

    return 0;
}

/** OPERATION */
