

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

/** MISC */

int rdma_ret_err(rdma_context_t *rdma_ctx, char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    if (rdma_ctx)
    {
        /*printf("Cleaning up RMDA...\n");
        rdma_context_close(rdma_ctx);*/
    }
    return -1;
}

void *rdma_ret_null(rdma_context_t *rdma_ctx, char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    if (rdma_ctx)
    {
        /*printf("Cleaning up RMDA...\n");
        rdma_context_close(rdma_ctx);*/
    }
    return NULL;
}

const char *get_op_name(rdma_communication_code_t code)
{
    switch (code)
    {
    case RDMA_DATA_READY:
        return "RDMA_DATA_READY";
    case RDMA_NEW_SLICE:
        return "RDMA_NEW_SLICE";
    case RDMA_DELETE_SLICE:
        return "RDMA_DELETE_SLICE";
    case TEST:
        return "TEST";
    case EXCHANGE_REMOTE_INFO:
        return "EXCHANGE_REMOTE_INFO";
    case RDMA_CLOSE_CONTEXT:
        return "RDMA_CLOSE_CONTEXT";
    default:
        return "UNKNOWN";
    }
}

/** SERVER */

int rdma_server_setup(rdma_context_t *sctx, u_int16_t server_port)
{
    sctx->is_server = TRUE;

    for (int i = 0; i < N_TCP_PER_CONNECTION; i++)
    {
        sctx->is_id_free[i] = TRUE;
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
        return rdma_ret_err(sctx, "rdma_create_event_channel - rdma_setup_server");

    // 2. Create RDMA ID for listener
    if (rdma_create_id(sctx->ec, &sctx->listener, NULL, RDMA_PS_TCP))
        return rdma_ret_err(sctx, "rdma_create_id");

    // 3. Resolve address of server
    char port[6];
    snprintf(port, sizeof(port), "%u", server_port);
    if (getaddrinfo(NULL, port, &hints, &res))
        return rdma_ret_err(sctx, "getaddrinfo");

    // 4. Bind address to listener
    if (rdma_bind_addr(sctx->listener, res->ai_addr))
        return rdma_ret_err(sctx, "rdma_bind_addr");

    freeaddrinfo(res);

    // 5. start listening for incoming connections
    if (rdma_listen(sctx->listener, 1))
        return rdma_ret_err(sctx, "rdma_listen");

    // 6. set up the buffer
    sctx->buffer = malloc(MR_SIZE);
    if (!sctx->buffer)
        return rdma_ret_err(sctx, "malloc buffer - rdma_setup_server");
    // memset(sctx->buffer, 0, MR_SIZE);

    sctx->buffer_size = MR_SIZE;

    return 0;
}

int rdma_server_wait_client_connection(rdma_context_t *sctx)
{
    // 1. Wait for RDMA_CM_EVENT_CONNECT_REQUEST
    struct rdma_cm_event *event;
    if (rdma_get_cm_event(sctx->ec, &event))
        return rdma_ret_err(sctx, "rdma_get_cm_event - rdma_wait_for_client");

    // 2. Extract conn ID from event and also get the remote IP
    sctx->conn = event->id;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)&event->id->route.addr.src_addr;
    sctx->remote_ip = addr_in->sin_addr.s_addr;
    rdma_ack_cm_event(event);

    // 3. Allocate PD and register MR
    sctx->pd = ibv_alloc_pd(sctx->conn->verbs);

    sctx->mr = ibv_reg_mr(sctx->pd, sctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

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
        return rdma_ret_err(sctx, "ibv_create_cq - rdma_wait_for_client");

    sctx->cq = qp_attr.send_cq;

    if (rdma_create_qp(sctx->conn, sctx->pd, &qp_attr))
        return rdma_ret_err(sctx, "rdma_create_qp");

    // Post a receive work request for receiving the remote address and rkey
    struct ibv_sge sge = {
        .addr = (uintptr_t)sctx->buffer, // address of the buffer
        .length = (sizeof(notification_t) + sizeof(rdma_meta_info_t)),
        .lkey = sctx->mr->lkey // local key of the registered memory region
    };
    struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad_wr;
    ibv_post_recv(sctx->conn->qp, &recv_wr, &bad_wr);
    if (bad_wr)
        return rdma_ret_err(sctx, "Failed to post recv - rdma_wait_for_client");

    rdma_meta_info_t info = {
        .addr = (uintptr_t)sctx->buffer,
        .rkey = sctx->mr->rkey};

    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7,
        .private_data = (void *)&info,
        .private_data_len = sizeof(rdma_meta_info_t)};

    // 6. Accept connection using rdma_accept
    if (rdma_accept(sctx->conn, &conn_param))
        rdma_ret_err(sctx, "rdma_accept");

    if (rdma_get_cm_event(sctx->ec, &event))
        return rdma_ret_err(sctx, "rdma_get_cm_event - rdma_wait_for_client");

    // 7. Wait for RDMA_CM_EVENT_ESTABLISHED
    rdma_ack_cm_event(event);

    return rdma_recv_notification(sctx); // needed to exchange remote info
}

/** CLIENT */

int rdma_client_setup(rdma_context_t *cctx, uint32_t ip, u_int16_t port)
{
    // IP in HOST

    cctx->is_server = FALSE;

    for (int i = 0; i < N_TCP_PER_CONNECTION; i++)
    {
        cctx->is_id_free[i] = TRUE;
    }

    // 1. Create event channel
    cctx->ec = rdma_create_event_channel();

    // 2. Create RDMA ID for connection
    rdma_create_id(cctx->ec, &cctx->conn, NULL, RDMA_PS_TCP);
    if (!cctx->conn)
        return rdma_ret_err(cctx, "rdma_create_id - rdma_setup_client");

    // 3. Resolve address of server
    char ip_str[INET_ADDRSTRLEN];
    char port_str[6];
    if (inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)) == NULL)
        return rdma_ret_err(cctx, "inet_ntop - rdma_setup_client");
    snprintf(port_str, sizeof(port_str), "%u", port);

    printf("connecting to IP: %s, port: %s\n", ip_str, port_str);

    struct addrinfo *res;
    getaddrinfo(ip_str, port_str, NULL, &res);
    rdma_resolve_addr(cctx->conn, NULL, res->ai_addr, 2000);
    freeaddrinfo(res);
    if (!cctx->conn)
        return rdma_ret_err(cctx, "rdma_resolve_addr - rdma_setup_client");

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
        return rdma_ret_err(cctx, "ibv_alloc_pd - rdma_setup_client");

    // 8. set up the buffer
    cctx->buffer = malloc(MR_SIZE);
    if (!cctx->buffer)
        return rdma_ret_err(cctx, "malloc buffer - rdma_setup_client");

    cctx->buffer_size = MR_SIZE;

    cctx->mr = ibv_reg_mr(cctx->pd, cctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

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
        return rdma_ret_err(cctx, "ibv_create_cq - rdma_setup_client");

    cctx->cq = qp_attr.send_cq; // :-(

    // 10. Create QP with ctx->conn and PD
    rdma_create_qp(cctx->conn, cctx->pd, &qp_attr);
    if (!cctx->conn->qp)
        return rdma_ret_err(cctx, "rdma_create_qp - rdma_setup_client");

    return 0;
}

int rdma_client_connect(rdma_context_t *cctx)
{
    // 1. Call rdma_connect
    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    if (rdma_connect(cctx->conn, &conn_param) != 0)
        return rdma_ret_err(cctx, "rdma_connect - rdma_connect_server");

    // 2. Wait for RDMA_CM_EVENT_ESTABLISHED
    struct rdma_cm_event *event = NULL;
    rdma_get_cm_event(cctx->ec, &event); // connection established

    // retrieve the remote address and rkey
    rdma_meta_info_t *info = (rdma_meta_info_t *)event->param.conn.private_data;
    cctx->remote_addr = info->addr;
    cctx->remote_rkey = info->rkey;

    rdma_ack_cm_event(event);

    printf("C: My address: %p, my rkey: %u\n", (void *)cctx->buffer, cctx->mr->rkey);
    printf("C: Remote address: %p, Remote rkey: %u\n", (void *)cctx->remote_addr, cctx->remote_rkey);

    // post a SEND work request to send the remote address and rkey
    notification_t *notification = (notification_t *)cctx->buffer;
    notification->from_client.code = EXCHANGE_REMOTE_INFO; // code of the notification
    notification->from_client.slice_id = -1;               // ID of the slice (not used here)

    rdma_meta_info_t *remote_info = (rdma_meta_info_t *)(cctx->buffer + sizeof(notification_t));
    remote_info->addr = (uintptr_t)cctx->buffer;
    remote_info->rkey = cctx->mr->rkey;

    // post
    struct ibv_sge sge = {
        .addr = (uintptr_t)cctx->buffer, // address of the buffer
        .length = (sizeof(notification_t) + sizeof(rdma_meta_info_t)),
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
        return rdma_ret_err(cctx, "Failed to post send - rdma_connect_server");

    if (rdma_poll_cq(cctx) != 0) // wait for completion
        return rdma_ret_err(cctx, "Failed to poll CQ - rdma_connect_server");
    sleep(2);
    return 0;
}

/** COMMUNICATION */

int rdma_context_close(rdma_context_t *ctx)
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

int rdma_send_notification(rdma_context_t *ctx, rdma_communication_code_t code, int slice_id)
{

    notification_t *notification = (notification_t *)ctx->buffer;

    if (ctx->is_server == TRUE)
    {
        notification->from_server.code = code;
        notification->from_server.slice_id = slice_id;
    }
    else
    {
        notification->from_client.code = code;
        notification->from_client.slice_id = slice_id;
    }

    // Fill ibv_sge structure
    struct ibv_sge sge = {
        .addr = (uintptr_t)ctx->buffer, // address of the buffer
        .length = sizeof(notification_t),
        .lkey = ctx->mr->lkey // Local key from registered memory region
    };

    // 2. Prepare ibv_send_wr with IBV_WR_SEND
    struct ibv_send_wr send_wr = {0};
    send_wr.wr_id = 0;
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.opcode = IBV_WR_SEND;
    send_wr.send_flags = IBV_SEND_SIGNALED;

    // Post send with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return rdma_ret_err(ctx, "Failed to post send - rdma_send_notification");

    // Poll the completion queue
    if (rdma_poll_cq(ctx) != 0)
        return rdma_ret_err(ctx, "Failed to poll CQ - rdma_send_notification");

    printf("------------------------------------------------------------\n");
    if (ctx->is_server == TRUE)
    {
        printf("S: send: %s (%d), slice_id: %d, ctx_id: %d\n",
               get_op_name(notification->from_server.code), notification->from_server.code, notification->from_server.slice_id, ctx->context_id);
    }
    else
    {
        printf("C: send: %s (%d), slice_id: %d, ctx_id: %d\n",
               get_op_name(notification->from_client.code), notification->from_client.code, notification->from_client.slice_id, ctx->context_id);
    }

    return 0;
}

int rdma_recv_notification(rdma_context_t *ctx)
{

    notification_t *notification = (notification_t *)ctx->buffer;
    int code; // enum rdma_communication_code
    int slice_id = -1;

    printf("------------------------------------------------------------\n");
    if (ctx->is_server == TRUE)
    {
        code = notification->from_client.code;
        slice_id = notification->from_client.slice_id;
        printf("S: Received: %s (%d), slide_id: %d, ctx_id: %d\n", get_op_name(code), code, slice_id, ctx->context_id);
    }
    else // client
    {
        code = notification->from_server.code;
        slice_id = notification->from_server.slice_id;
        printf("C: Received: %s (%d), slide_id: %d, ctx_id: %d\n", get_op_name(code), code, slice_id, ctx->context_id);
    }

    switch (code)
    {
    case EXCHANGE_REMOTE_INFO:
        if (ctx->remote_addr != 0)
        {
            printf("Remote address already set......\n");
            return 0;
        }

        rdma_meta_info_t *remote_info = (rdma_meta_info_t *)(ctx->buffer + sizeof(notification_t));

        // save the remote address and rkey
        ctx->remote_addr = remote_info->addr;
        ctx->remote_rkey = remote_info->rkey;

        // server
        printf("S: My address: %p, my rkey: %u\n", (void *)ctx->buffer, ctx->mr->rkey);
        printf("S: Remote address: %p, Remote rkey: %u\n", (void *)ctx->remote_addr, ctx->remote_rkey);

        break;

    case TEST:
        printf("TEST\n");
        break;

    case RDMA_DATA_READY:
        if (slice_id < 0 || slice_id >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_id] == TRUE)
            return rdma_ret_err(ctx, "Invalid slice ID - rdma_listen_notification RDMA_DATA_READY");

        printf("Data ready in slice %d\n", slice_id);

        transfer_buffer_t *buffer_to_read;

        buffer_to_read = (ctx->is_server == TRUE) ? ctx->slices[slice_id].client_buffer : ctx->slices[slice_id].server_buffer;

        printf("Buffer size: %d\n", buffer_to_read->buffer_size);
        printf("Buffer: %s\n", buffer_to_read->buffer);

        break;

    case RDMA_NEW_SLICE:

        if (slice_id < 0 || slice_id >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_id] == FALSE)
            return rdma_ret_err(ctx, "Invalid slice ID - rdma_listen_notification RDMA_NEW_SLICE");

        ctx->is_id_free[slice_id] = FALSE; // Mark the slice as used

        // set the pointers to the buffers
        ctx->slices[slice_id].slice_id = slice_id;
        ctx->slices[slice_id].server_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                    slice_id * SLICE_BUFFER_SIZE);

        ctx->slices[slice_id].client_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                    slice_id * SLICE_BUFFER_SIZE +
                                                                    sizeof(transfer_buffer_t)); // skip the server buffer

        printf("Added slice %d, server buffer: %p, client buffer: %p\n",
               slice_id, ctx->slices[slice_id].server_buffer, ctx->slices[slice_id].client_buffer);

        break;

    case RDMA_DELETE_SLICE:

        if (slice_id < 0 || slice_id >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_id] == TRUE)
            return rdma_ret_err(ctx, "Invalid slice ID - rdma_listen_notification RDMA_DELETE_SLICE");

        ctx->is_id_free[slice_id] = TRUE; // Mark the slice as free

        // free the buffer
        ctx->slices[slice_id].client_buffer = NULL;
        ctx->slices[slice_id].server_buffer = NULL;

        break;

    case RDMA_CLOSE_CONTEXT:
        // TODO

        break;

    default:
        printf("Unknown notification code\n");
        break;
    }

    return 0;
}

int rdma_write_slice(rdma_context_t *ctx, rdma_context_slice_t *slice)
{
    struct ibv_send_wr send_wr = {};
    struct ibv_sge sge;

    transfer_buffer_t *buffer_to_write;

    if (ctx->is_server)
    {
        // if server, write the server buffer
        buffer_to_write = slice->server_buffer;
    }
    else
    {
        // if client, write the client buffer
        buffer_to_write = slice->client_buffer;
    }

    // calculate the size to write
    int size_to_write = sizeof(buffer_to_write->flags) +
                        sizeof(buffer_to_write->buffer_size) +
                        buffer_to_write->buffer_size;

    // calculate the remote address
    uintptr_t remote_addr = (uintptr_t)ctx->remote_addr;
    remote_addr += NOTIFICATION_OFFSET_SIZE;              // skip the notification header
    remote_addr += (slice->slice_id * SLICE_BUFFER_SIZE); // reach the corresponding slice

    if (ctx->is_server == FALSE)
    {
        remote_addr += sizeof(transfer_buffer_t); // skip the space dedicated to the server buffer
    }
    // else: notthing to do, the server buffer is already in the right place

    // set the flags
    buffer_to_write->flags.data_ready = TRUE;

    // Fill ibv_sge with local buffer
    sge.addr = (uintptr_t)buffer_to_write; // Local address of the buffer
    sge.length = size_to_write;            // Length of the buffer
    sge.lkey = ctx->mr->lkey;

    // Prepare ibv_send_wr with IBV_WR_RDMA_WRITE
    send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.wr.rdma.remote_addr = remote_addr;
    send_wr.wr.rdma.rkey = ctx->remote_rkey;
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    // send_wr.send_flags = IBV_SEND_SIGNALED;

    // 4. Post send in SQ with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return rdma_ret_err(ctx, "Failed to post send - rdma_write");

    if (ctx->is_server)
    {
        printf("S: RDMA_W: local=0x%lx len=%u remote=0x%lx rkey=%u\n",
               sge.addr, sge.length, send_wr.wr.rdma.remote_addr, send_wr.wr.rdma.rkey);
    }
    else
    {
        printf("C: RDMA_W: local=0x%lx len=%u remote=0x%lx rkey=%u\n",
               sge.addr, sge.length, send_wr.wr.rdma.remote_addr, send_wr.wr.rdma.rkey);
    }
    printf("Msg: %s\n", buffer_to_write->buffer);
    printf("Buffer size: %d\n", size_to_write);

    return 0;
}

int rdma_poll_cq(rdma_context_t *ctx)
{
    if (ctx->cq == NULL)
        return rdma_ret_err(ctx, "CQ is NULL - rdma_poll_cq");

    struct ibv_wc wc;
    int num_completions;
    do
    {
        num_completions = ibv_poll_cq(ctx->cq, 1, &wc);
    } while (num_completions == 0); // poll until we get a completion

    if (num_completions < 0)
        return rdma_ret_err(ctx, "Failed to poll CQ (num_completions<0) - rdma_poll_cq");
    if (wc.status != IBV_WC_SUCCESS)
    {
        fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
        return rdma_ret_err(ctx, "Failed to poll CQ - rdma_poll_cq");
    }

    return 0;
}

int rdma_poll_memory(rdma_context_t *ctx, rdma_context_slice_t *slice)
{
    transfer_buffer_t *buffer_to_read = (ctx->is_server == TRUE) ? slice->client_buffer : slice->server_buffer;

    volatile uint32_t *flag_to_poll = (volatile uint32_t *)&buffer_to_read->flags.data_ready;

    int i = 1;
    while (*flag_to_poll == FALSE)
    {
        if (i++ > POLL_MEM_ATTEMPTS)
        {
            printf("Polling timeout\n");
            return -1;
        }
        if (i % 1000 == 0)
        {
            __asm__ __volatile__("pause" ::: "memory");
        }
    }

    // clear the flag
    *flag_to_poll = FALSE;

    return 0;
}

/** UTILS */

int rdma_new_slice(rdma_context_t *ctx, u_int16_t port)
{
    // get the first free slice
    int slice_id = 0;
    for (; slice_id < N_TCP_PER_CONNECTION; slice_id++)
    {
        if (ctx->is_id_free[slice_id] == TRUE)
        {
            ctx->is_id_free[slice_id] = FALSE; // Mark the slice as used
            break;
        }
    }

    if (slice_id == N_TCP_PER_CONNECTION)
        return rdma_ret_err(NULL, "No free slice available - rdma_new_slice");

    // set the pointers to the buffers
    ctx->slices[slice_id].slice_id = slice_id;
    ctx->slices[slice_id].server_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                slice_id * SLICE_BUFFER_SIZE);
    ctx->slices[slice_id].client_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                slice_id * SLICE_BUFFER_SIZE +
                                                                sizeof(transfer_buffer_t)); // skip the server buffer

    ctx->slices[slice_id].src_port = port;

    // notify the other side about the new slice
    if (rdma_send_notification(ctx, RDMA_NEW_SLICE, slice_id) != 0)
        return rdma_ret_err(ctx, "Failed to send notification - rdma_new_slice");

    printf("Added slice %d, server buffer: %p, client buffer: %p\n",
           slice_id, ctx->slices[slice_id].server_buffer, ctx->slices[slice_id].client_buffer);

    return slice_id;
}

int rdma_delete_slice_by_port(rdma_context_t *ctx, u_int16_t port)
{
    int slice_id = rdma_slice_id_from_port(ctx, port);
    return rdma_delete_slice_by_id(ctx, slice_id);
}

int rdma_delete_slice_by_id(rdma_context_t *ctx, int slice_id)
{
    if (slice_id < 0 || slice_id >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_id] == TRUE)
        return rdma_ret_err(ctx, "Slice not found - rdma_delete_slice");

    ctx->is_id_free[slice_id] = TRUE; // Mark the slice as free

    // free the buffer
    ctx->slices[slice_id].client_buffer = NULL;
    ctx->slices[slice_id].server_buffer = NULL;

    // notify the other side about the deletion
    if (rdma_send_notification(ctx, RDMA_DELETE_SLICE, slice_id) != 0)
        return rdma_ret_err(ctx, "Failed to send notification - rdma_delete_slice");

    printf("Deleted slice %d\n", slice_id);

    return 0;
}

int rdma_slice_id_from_port(rdma_context_t *ctx, uint16_t port)
{
    for (int i = 0; i < N_TCP_PER_CONNECTION; i++)
    {
        if (ctx->slices[i].src_port == port)
        {
            return i;
        }
    }
    return -1;
}

/** WRAPPER */

int rdma_manager_init(rdma_context_manager_t *ctxm, uint16_t rdma_port)
{
    ctxm->ctxs = malloc(INITIAL_CONTEXT_NUMBER * sizeof(rdma_context_t));
    for (int i = 0; i < INITIAL_CONTEXT_NUMBER; i++)
    {
        ctxm->ctxs[i].context_id = i;
        ctxm->ctxs[i].is_server = FALSE;
        ctxm->ctxs[i].remote_ip = 0;
        ctxm->ctxs[i].is_id_free[0] = TRUE;
        ctxm->ctxs[i].buffer = NULL;
        ctxm->ctxs[i].buffer_size = 0;
        ctxm->ctxs[i].conn = NULL;
        ctxm->ctxs[i].listener = NULL;
        ctxm->ctxs[i].pd = NULL;
        ctxm->ctxs[i].mr = NULL;
        ctxm->ctxs[i].cq = NULL;
        ctxm->ctxs[i].ec = NULL;
        ctxm->ctxs[i].remote_addr = 0;
        ctxm->ctxs[i].remote_rkey = 0;
        for (int j = 0; j < N_TCP_PER_CONNECTION; j++)
        {
            ctxm->ctxs[i].is_id_free[j] = TRUE;
            ctxm->ctxs[i].slices[j].slice_id = -1;
            ctxm->ctxs[i].slices[j].src_port = 0;
            ctxm->ctxs[i].slices[j].server_buffer = NULL;
            ctxm->ctxs[i].slices[j].client_buffer = NULL;
        }
    }
    ctxm->ctx_count = INITIAL_CONTEXT_NUMBER;
    ctxm->rdma_port = rdma_port;
    ctxm->server_thread = 0;
    ctxm->notification_thread = 0;

    // setup the pool
    ctxm->pool = thread_pool_create(N_THREADS_POOL);

    return 0;
}

int rdma_manager_destroy(rdma_context_manager_t *ctxm)
{
    for (int i = 0; i < ctxm->ctx_count; i++)
        rdma_context_close(&ctxm->ctxs[i]);
    free(ctxm->ctxs);
    ctxm->ctxs = NULL;
    ctxm->ctx_count = 0;
    ctxm->rdma_port = 0;

    // destroy the thread pool
    thread_pool_destroy(ctxm->pool);
    ctxm->pool = NULL;

    // stop the threads
    ctxm->stop_threads = TRUE;

    if (ctxm->notification_thread)
    {
        pthread_join(ctxm->notification_thread, NULL);
        ctxm->notification_thread = 0;
    }

    if (ctxm->server_thread)
    {
        pthread_join(ctxm->server_thread, NULL);
        ctxm->server_thread = 0;
    }

    return 0;
}

int rdma_manager_get_free_context(rdma_context_manager_t *ctxm)
{
    int free_ctx_id = 0;
    for (; free_ctx_id < ctxm->ctx_count; free_ctx_id++)
        if (ctxm->ctxs[free_ctx_id].remote_ip == 0)
            return free_ctx_id;

    // no free context available, reallocate the array
    int new_count = ctxm->ctx_count + N_CONTEXT_REALLOC;

    rdma_context_t *new_ctxs = realloc(ctxm->ctxs, new_count * sizeof(rdma_context_t));
    if (new_ctxs == NULL)
        return rdma_ret_err(NULL, "Failed to realloc context array - rdma_context_manager_get_free_context");

    ctxm->ctxs = new_ctxs;
    ctxm->ctx_count = new_count;

    // init the new contexts
    int i = free_ctx_id;
    for (; i < ctxm->ctx_count; i++)
    {
        ctxm->ctxs[i].context_id = i;
        ctxm->ctxs[i].is_server = FALSE;
        ctxm->ctxs[i].remote_ip = 0;
        ctxm->ctxs[i].is_id_free[0] = TRUE;
    }

    return free_ctx_id;
}

int rdma_manager_get_context_by_ip(rdma_context_manager_t *ctxm, uint32_t remote_ip)
{
    for (int i = 0; i < ctxm->ctx_count; i++)
        if (ctxm->ctxs[i].remote_ip == remote_ip)
            return i;
    return -1;
}

rdma_context_slice_t *rdma_manager_get_slice(rdma_context_manager_t *ctxm, uint32_t remote_ip, uint16_t port)
{
    // search for the context
    int ctx_id = rdma_manager_get_context_by_ip(ctxm, remote_ip);
    if (ctx_id < 0)
    {
        printf("Context not found, creating a new one\n");
        // context not found, create a new one
        ctx_id = rdma_manager_get_free_context(ctxm);
        if (ctx_id < 0)
            return rdma_ret_null(NULL, "Failed to get free context - rdma_get_slice");

        ctxm->ctxs[ctx_id].remote_ip = remote_ip;

        // since the context is new, we need to connect to the corresponding server
        if (rdma_client_setup(&ctxm->ctxs[ctx_id], remote_ip, ctxm->rdma_port) != 0)
            return rdma_ret_null(NULL, "Failed to setup client - rdma_get_slice");

        if (rdma_client_connect(&ctxm->ctxs[ctx_id]) != 0)
            return rdma_ret_null(NULL, "Failed to connect client - rdma_get_slice");
    }

    // search for the slice
    int slice_id = rdma_slice_id_from_port(&ctxm->ctxs[ctx_id], port);

    if (slice_id < 0)
    {
        printf("Slice not found, creating a new one\n");
        // slice not found, create a new one
        slice_id = rdma_new_slice(&ctxm->ctxs[ctx_id], port);
        if (slice_id < 0)
            return rdma_ret_null(NULL, "Failed to create new slice - rdma_get_slice");
    }

    // return the slice
    return &ctxm->ctxs[ctx_id].slices[slice_id];
}

int rdma_manager_run_listen_th(rdma_context_manager_t *ctxm)
{
    // create a thread to listen for notifications
    pthread_t thread;
    if (pthread_create(&thread, NULL, rdma_manager_listen_thread, ctxm) != 0)
        return rdma_ret_err(NULL, "Failed to create thread - rdma_maanger_listen_notification");
    ctxm->notification_thread = thread;
    return 0;
}

void *rdma_manager_listen_thread(void *arg)
{
    rdma_context_manager_t *ctxm = (rdma_context_manager_t *)arg;
    printf("Notification thread running\n");

    while (ctxm->stop_threads == FALSE)
    {
        rdma_context_t *ctx = NULL;
        int j;
        // listen for notifications
        for (int i = 0; i < ctxm->ctx_count; i++)
        {
            ctx = &ctxm->ctxs[i];
            if (ctx->remote_ip == 0 || ctx->conn == NULL)
            {
                continue; // context not connected
            }

            // check the cq
            if (ctx->cq == NULL)
                return rdma_ret_null(ctx, "CQ is NULL - rdma_manager_liste_thread");

            struct ibv_wc wc = {};
            int num_completions = -1;
            j = 0;

            while (j != N_POLL_PER_CQ)
            {
                j++;
                num_completions = ibv_poll_cq(ctx->cq, 1, &wc);
                if (num_completions != 0) // we have something to process
                    break;
            };

            if (num_completions == 0)
                continue; // no completion, go to the next context

            if (num_completions < 0)
                return rdma_ret_null(ctx, "Failed to poll CQ (num_completions<0) - rdma_manager_liste_thread");

            if (wc.status != IBV_WC_SUCCESS)
            {
                fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
                return rdma_ret_null(ctx, "Failed to poll CQ - rdma_manager_liste_thread");
            }

            // post another receive work request
            struct ibv_sge sge = {
                .addr = (uintptr_t)ctx->buffer, // address of the buffer
                .length = sizeof(notification_t),
                .lkey = ctx->mr->lkey};

            // Prepare ibv_recv_wr with IBV_WR_RECV
            struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
            struct ibv_recv_wr *bad_wr;

            // Post receive with ibv_post_recv
            if (ibv_post_recv(ctx->conn->qp, &recv_wr, &bad_wr) != 0 || bad_wr)
                return rdma_ret_null(ctx, "Failed to post recv - rdma_recv");

            // start a new thread to handle the notification
            int err = rdma_recv_notification(ctx);
            if (err != 0)
                return rdma_ret_null(ctx, "Failed to receive notification - rdma_manager_liste_thread");
        }
    }

    return NULL;
}

int rdma_manager_run_server_th(rdma_context_manager_t *ctxm)
{
    // start the server thread
    pthread_t thread;
    if (pthread_create(&thread, NULL, rdma_manager_server_thread, ctxm) != 0)
        return rdma_ret_err(NULL, "Failed to create thread - rdma_manager_start_server");
    ctxm->server_thread = thread;
    return 0;
}

void *rdma_manager_server_thread(void *arg)
{
    rdma_context_manager_t *ctxm = (rdma_context_manager_t *)arg;
    printf("Server thread running\n");
    while (ctxm->stop_threads == FALSE)
    {
        rdma_context_t *ctx = NULL;
        int ctx_id = rdma_manager_get_free_context(ctxm);
        if (ctx_id < 0)
            return rdma_ret_null(NULL, "Failed to get free context - rdma_manager_connection_thread");

        // setup the server
        ctx = &ctxm->ctxs[ctx_id];
        if (rdma_server_setup(ctx, ctxm->rdma_port) != 0)
            return rdma_ret_null(NULL, "Failed to setup server - rdma_manager_connection_thread");

        if (rdma_server_wait_client_connection(ctx) != 0)
            return rdma_ret_null(NULL, "Failed to wait for client connection - rdma_manager_connection_thread");

        // at the first connection, we need to start the notification thread
        if (ctxm->notification_thread == 0)
        {
            if (rdma_manager_run_listen_th(ctxm) != 0)
                return rdma_ret_null(NULL, "Failed to start notification thread - rdma_manager_connection_thread");
            // ctxm->notification_thread = 1;
        }
        break;
    }

    return NULL;
}

/** POOL */

void *worker(void *arg)
{
    thread_pool_t *pool = (thread_pool_t *)arg;
    while (1)
    {
        pthread_mutex_lock(&pool->lock);
        while (pool->head == NULL && !pool->stop)
        {
            pthread_cond_wait(&pool->cond, &pool->lock);
        }
        if (pool->stop && pool->head == NULL)
        {
            pthread_mutex_unlock(&pool->lock);
            break;
        }
        task_t *task = pool->head;
        if (task)
        {
            pool->head = task->next;
            if (pool->head == NULL)
                pool->tail = NULL;
        }
        pthread_mutex_unlock(&pool->lock);
        if (task)
        {
            task->function(task->arg);
            free(task);
        }
    }
    return NULL;
}

thread_pool_t *thread_pool_create(int num_threads)
{
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (!pool)
        return NULL;
    pool->thread_count = num_threads;
    pool->stop = 0;
    pool->head = pool->tail = NULL;
    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->cond, NULL);
    pool->threads = malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads)
    {
        free(pool);
        return NULL;
    }
    for (int i = 0; i < num_threads; ++i)
    {
        pthread_create(&pool->threads[i], NULL, worker, pool);
    }
    return pool;
}

int thread_pool_add(thread_pool_t *pool, void (*function)(void *), void *arg)
{
    task_t *task = malloc(sizeof(task_t));
    if (!task)
        return -1;
    task->function = function;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&pool->lock);
    if (pool->tail)
    {
        pool->tail->next = task;
        pool->tail = task;
    }
    else
    {
        pool->head = pool->tail = task;
    }
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
    return 0;
}

void thread_pool_destroy(thread_pool_t *pool)
{
    pthread_mutex_lock(&pool->lock);
    pool->stop = 1;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->lock);

    for (int i = 0; i < pool->thread_count; ++i)
    {
        pthread_join(pool->threads[i], NULL);
    }

    while (pool->head)
    {
        task_t *tmp = pool->head;
        pool->head = pool->head->next;
        free(tmp);
    }

    free(pool->threads);
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->cond);
    free(pool);
}
