#define _POSIX_C_SOURCE 200112L

#include "rdma_utils.h"

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

int rdma_server_handle_new_client(rdma_context_t *ctx, struct rdma_event_channel *server_ec)
{
    ctx->pd = ibv_alloc_pd(ctx->conn->verbs);
    if (!ctx->pd)
        return rdma_ret_err(ctx, "ibv_alloc_pd");

    ctx->buffer = malloc(MR_SIZE);
    ctx->buffer_size = MR_SIZE;

    ctx->mr = ibv_reg_mr(ctx->pd, ctx->buffer, MR_SIZE,
                         IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

    struct ibv_qp_init_attr qp_attr = {
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 1,
            .max_recv_sge = 1},
        .qp_type = IBV_QPT_RC};

    ctx->cq = ibv_create_cq(ctx->conn->verbs, 2, NULL, NULL, 0);
    if (!ctx->cq)
        return rdma_ret_err(ctx, "ibv_create_cq");

    qp_attr.send_cq = ctx->cq;
    qp_attr.recv_cq = ctx->cq;

    if (rdma_create_qp(ctx->conn, ctx->pd, &qp_attr))
        return rdma_ret_err(ctx, "rdma_create_qp");

    // Post a receive work request to receive the remote address and rkey
    struct ibv_sge sge = {
        .addr = (uintptr_t)ctx->buffer,
        .length = sizeof(notification_t) + sizeof(rdma_meta_info_t),
        .lkey = ctx->mr->lkey};

    struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad_wr;
    ibv_post_recv(ctx->conn->qp, &recv_wr, &bad_wr);

    // Accept the connection and send the remote address and rkey
    rdma_meta_info_t info = {
        .addr = (uintptr_t)ctx->buffer,
        .rkey = ctx->mr->rkey};

    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7,
        .private_data = &info,
        .private_data_len = sizeof(info)};

    if (rdma_accept(ctx->conn, &conn_param))
        return rdma_ret_err(ctx, "rdma_accept");

    struct rdma_cm_event *event;
    if (rdma_get_cm_event(server_ec, &event))
        return rdma_ret_err(ctx, "rdma_get_cm_event");

    if (event->event != RDMA_CM_EVENT_ESTABLISHED)
        return rdma_ret_err(ctx, "rdma_get_cm_event - not established");
    rdma_ack_cm_event(event);

    return 0;
}

/** CLIENT */

int rdma_client_setup(rdma_context_t *cctx, uint32_t ip, uint16_t port)
{
    cctx->is_server = FALSE;

    cctx->conn = NULL;
    cctx->client_ec = rdma_create_event_channel();
    if (!cctx->client_ec)
        return rdma_ret_err(cctx, "rdma_create_event_channel");

    if (rdma_create_id(cctx->client_ec, &cctx->conn, NULL, RDMA_PS_TCP))
        return rdma_ret_err(cctx, "rdma_create_id - rdma_client_setup");

    // Resolve the address
    char ip_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)))
        return rdma_ret_err(cctx, "inet_ntop - rdma_client_setup");

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM};
    struct addrinfo *res;
    if (getaddrinfo(ip_str, port_str, &hints, &res) != 0)
        return rdma_ret_err(cctx, "getaddrinfo - rdma_client_setup");

    if (rdma_resolve_addr(cctx->conn, NULL, res->ai_addr, 2000))
        return rdma_ret_err(cctx, "rdma_resolve_addr");

    cctx->remote_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(res);

    // Wait for the ADDR_RESOLVED event
    struct rdma_cm_event *event = NULL;
    if (rdma_get_cm_event(cctx->client_ec, &event))
        return rdma_ret_err(cctx, "rdma_get_cm_event - addr_resolved");

    if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED)
        return rdma_ret_err(cctx, "unexpected event - not ADDR_RESOLVED");

    rdma_ack_cm_event(event);

    // Resolve the route
    if (rdma_resolve_route(cctx->conn, 2000))
        return rdma_ret_err(cctx, "rdma_resolve_route");

    if (rdma_get_cm_event(cctx->client_ec, &event))
        return rdma_ret_err(cctx, "rdma_get_cm_event - route_resolved");

    if (event->event != RDMA_CM_EVENT_ROUTE_RESOLVED)
        return rdma_ret_err(cctx, "unexpected event - not ROUTE_RESOLVED");

    rdma_ack_cm_event(event);

    // PD, buffer, MR
    cctx->pd = ibv_alloc_pd(cctx->conn->verbs);
    if (!cctx->pd)
        return rdma_ret_err(cctx, "ibv_alloc_pd");

    cctx->buffer = malloc(MR_SIZE);
    if (!cctx->buffer)
        return rdma_ret_err(cctx, "malloc buffer");

    cctx->buffer_size = MR_SIZE;

    cctx->mr = ibv_reg_mr(cctx->pd, cctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

    if (!cctx->mr)
        return rdma_ret_err(cctx, "ibv_reg_mr");

    // CQ + QP
    struct ibv_qp_init_attr qp_attr = {
        .send_cq = NULL,
        .recv_cq = NULL,
        .qp_type = IBV_QPT_RC,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 10,
            .max_recv_sge = 10}};

    qp_attr.send_cq = qp_attr.recv_cq = ibv_create_cq(cctx->conn->verbs, 2, NULL, NULL, 0);
    if (!qp_attr.send_cq)
        return rdma_ret_err(cctx, "ibv_create_cq");

    cctx->cq = qp_attr.send_cq;

    if (rdma_create_qp(cctx->conn, cctx->pd, &qp_attr))
        return rdma_ret_err(cctx, "rdma_create_qp");

    printf("Client connecting to %s:%u\n", ip_str, port);

    return 0;
}

int rdma_client_connect(rdma_context_t *cctx)
{
    struct rdma_conn_param conn_param = {
        .initiator_depth = 1,
        .responder_resources = 1,
        .rnr_retry_count = 7};

    if (rdma_connect(cctx->conn, &conn_param))
        return rdma_ret_err(cctx, "rdma_connect");

    struct rdma_cm_event *event = NULL;
    if (rdma_get_cm_event(cctx->client_ec, &event))
        return rdma_ret_err(cctx, "rdma_get_cm_event - connect");

    if (event->event != RDMA_CM_EVENT_ESTABLISHED)
        return rdma_ret_err(cctx, "unexpected event - not ESTABLISHED");

    rdma_meta_info_t *info = (rdma_meta_info_t *)event->param.conn.private_data;
    cctx->remote_addr = info->addr;
    cctx->remote_rkey = info->rkey;

    rdma_ack_cm_event(event);

    // send the remote address and rkey to the server
    notification_t *notification = (notification_t *)cctx->buffer;
    notification->from_client.code = EXCHANGE_REMOTE_INFO;

    rdma_meta_info_t *remote_info = (rdma_meta_info_t *)(cctx->buffer + sizeof(notification_t));
    remote_info->addr = (uintptr_t)cctx->buffer;
    remote_info->rkey = cctx->mr->rkey;

    struct ibv_sge sge = {
        .addr = (uintptr_t)cctx->buffer,
        .length = sizeof(notification_t) + sizeof(rdma_meta_info_t),
        .lkey = cctx->mr->lkey};

    struct ibv_send_wr send_wr = {
        .wr_id = 0,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,
        .send_flags = IBV_SEND_SIGNALED};

    struct ibv_send_wr *bad_wr;
    if (ibv_post_send(cctx->conn->qp, &send_wr, &bad_wr))
        return rdma_ret_err(cctx, "ibv_post_send");

    if (rdma_poll_cq(cctx))
        return rdma_ret_err(cctx, "rdma_poll_cq");

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
    if (ctx->cq)
        ibv_destroy_cq(ctx->cq);
    if (ctx->mr)
        ibv_dereg_mr(ctx->mr);
    if (ctx->pd)
        ibv_dealloc_pd(ctx->pd);
    if (ctx->buffer)
        free(ctx->buffer);
    if (ctx->client_ec)
        rdma_destroy_event_channel(ctx->client_ec);
    ctx->conn = NULL;
    ctx->pd = NULL;
    ctx->mr = NULL;
    ctx->remote_ip = 0;
    ctx->remote_addr = 0;
    ctx->remote_rkey = 0;
    ctx->buffer = NULL;
    ctx->buffer_size = 0;

    return 0;
}

int rdma_setup_context(rdma_context_t *ctx)
{
    // Initialize the slices
    for (int i = 0; i < N_TCP_PER_CONNECTION; i++)
    {
        ctx->slices[i].slice_offset = -1;
        ctx->slices[i].server_buffer = NULL;
        ctx->slices[i].client_buffer = NULL;
        ctx->is_id_free[i] = TRUE;
        ctx->slices[i].client_port = 0;
        ctx->slices[i].socket_fd = -1;
    }
    ctx->buffer = NULL;
    ctx->buffer_size = 0;
    ctx->conn = NULL;
    ctx->pd = NULL;
    ctx->mr = NULL;
    ctx->cq = NULL;
    ctx->remote_ip = 0;
    ctx->remote_rkey = 0;
    // ctx->context_id = -1;

    ctx->remote_addr = 0;

    return 0;
}

int rdma_send_notification(rdma_context_t *ctx, rdma_communication_code_t code, int slice_offset, u_int16_t client_port)
{
    notification_t *notification = (notification_t *)ctx->buffer;

    if (ctx->is_server == TRUE)
    {
        notification->from_server.code = code;
        notification->from_server.slice_offset = slice_offset;
        notification->from_server.client_port = client_port;
    }
    else
    {
        notification->from_client.code = code;
        notification->from_client.slice_offset = slice_offset;
        notification->from_client.client_port = client_port;
    }

    // Fill ibv_sge structure
    struct ibv_sge sge = {
        .addr = (uintptr_t)ctx->buffer, // address of the buffer
        .length = sizeof(notification_t),
        .lkey = ctx->mr->lkey // Local key from registered memory region
    };

    // Prepare ibv_send_wr with IBV_WR_SEND
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
        printf("S: send: %s (%d), slice_offset: %d, client_port: %u, ctx_id: %d\n",
               get_op_name(notification->from_server.code), notification->from_server.code, notification->from_server.slice_offset, client_port, ctx->context_id);
    }
    else
    {
        printf("C: send: %s (%d), slice_offset: %d, client_port: %u, ctx_id: %d\n",
               get_op_name(notification->from_client.code), notification->from_client.code, notification->from_client.slice_offset, client_port, ctx->context_id);
    }

    return 0;
}

int rdma_recv_notification(rdma_context_t *ctx)
{
    notification_t *notification = (notification_t *)ctx->buffer;
    int code; // enum rdma_communication_code
    u_int16_t client_port = 0;
    int slice_offset = 0;

    printf("------------------------------------------------------------\n");
    if (ctx->is_server == TRUE)
    {
        code = notification->from_client.code;
        client_port = notification->from_client.client_port;
        slice_offset = notification->from_client.slice_offset;
        printf("S: Received: %s (%d), slice_offset: %d, client_port: %u, ctx_id: %d\n",
               get_op_name(code), code, slice_offset, client_port, ctx->context_id);
    }
    else // client
    {
        code = notification->from_server.code;
        slice_offset = notification->from_server.slice_offset;
        client_port = notification->from_server.client_port;
        printf("C: Received: %s (%d), slice_offset: %d, client_port: %u, ctx_id: %d\n",
               get_op_name(code), code, slice_offset, client_port, ctx->context_id);
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
        if (slice_offset < 0 || slice_offset >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_offset] == TRUE)
            return rdma_ret_err(ctx, "Invalid slice ID - rdma_listen_notification RDMA_DATA_READY");

        printf("Data ready in slice %d\n", slice_offset);

        transfer_buffer_t *buffer_to_read;

        buffer_to_read = (ctx->is_server == TRUE) ? ctx->slices[slice_offset].client_buffer : ctx->slices[slice_offset].server_buffer;

        printf("Buffer size: %d\n", buffer_to_read->buffer_size);
        printf("Buffer: %s\n", buffer_to_read->buffer);

        break;

    case RDMA_NEW_SLICE:

        if (slice_offset < 0 || slice_offset >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_offset] == FALSE)
            return rdma_ret_err(ctx, "Invalid slice ID - rdma_listen_notification RDMA_NEW_SLICE");

        ctx->is_id_free[slice_offset] = FALSE; // Mark the slice as used

        // set the pointers to the buffers
        ctx->slices[slice_offset].slice_offset = slice_offset;
        ctx->slices[slice_offset].client_port = client_port;
        ctx->slices[slice_offset].server_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                        slice_offset * SLICE_BUFFER_SIZE);

        ctx->slices[slice_offset].client_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                        slice_offset * SLICE_BUFFER_SIZE +
                                                                        sizeof(transfer_buffer_t)); // skip the server buffer

        printf("Added slice_off %d, server buffer: %p, client buffer: %p, client_port: %u\n",
               slice_offset, ctx->slices[slice_offset].server_buffer, ctx->slices[slice_offset].client_buffer, client_port);

        break;

    case RDMA_DELETE_SLICE:

        if (slice_offset < 0 || slice_offset >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_offset] == TRUE)
            return rdma_ret_err(ctx, "Invalid slice ID - rdma_listen_notification RDMA_DELETE_SLICE");

        ctx->is_id_free[slice_offset] = TRUE; // Mark the slice as free

        // free the buffer
        ctx->slices[slice_offset].client_buffer = NULL;
        ctx->slices[slice_offset].server_buffer = NULL;

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
    remote_addr += NOTIFICATION_OFFSET_SIZE;                  // skip the notification header
    remote_addr += (slice->slice_offset * SLICE_BUFFER_SIZE); // reach the corresponding slice

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

int rdma_poll_memory(transfer_buffer_t *buffer_to_read)
{
    flags_t *flag_to_poll = &buffer_to_read->flags;

    volatile uint32_t *data_ready = (uint32_t *)&flag_to_poll->data_ready;

    int i = 1;
    while (*data_ready == FALSE)
    {
        // TODO: add a timeout in some way
        if (i % 1000 == 0)
        {
            __asm__ __volatile__("pause" ::: "memory");
        }
    }

    // clear the flag
    *data_ready = FALSE;

    return 0;
}

/** UTILS */

int rdma_new_slice(rdma_context_t *ctx, u_int16_t client_port, int fd)
{
    // get the first free slice
    int slice_offset = 0;
    for (; slice_offset < N_TCP_PER_CONNECTION; slice_offset++)
    {
        if (ctx->is_id_free[slice_offset] == TRUE)
        {
            ctx->is_id_free[slice_offset] = FALSE; // Mark the slice as used
            break;
        }
    }

    if (slice_offset == N_TCP_PER_CONNECTION)
        return rdma_ret_err(NULL, "No free slice available - rdma_new_slice");

    // set the pointers to the buffers
    ctx->slices[slice_offset].slice_offset = slice_offset;
    ctx->slices[slice_offset].server_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                    slice_offset * SLICE_BUFFER_SIZE);
    ctx->slices[slice_offset].client_buffer = (transfer_buffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE +
                                                                    slice_offset * SLICE_BUFFER_SIZE +
                                                                    sizeof(transfer_buffer_t)); // skip the server buffer

    ctx->slices[slice_offset].client_port = client_port;
    ctx->slices[slice_offset].socket_fd = fd;

    // set the flags
    ctx->slices[slice_offset].server_buffer->flags.data_ready = FALSE;
    // TODO: set the other flags to FALSE

    // notify the other side about the new slice
    if (rdma_send_notification(ctx, RDMA_NEW_SLICE, slice_offset, client_port) != 0)
        return rdma_ret_err(ctx, "Failed to send notification - rdma_new_slice");

    printf("Added slice %d, server buffer: %p, client buffer: %p\n",
           slice_offset, ctx->slices[slice_offset].server_buffer, ctx->slices[slice_offset].client_buffer);

    return slice_offset;
}

int rdma_delete_slice_by_port(rdma_context_t *ctx, u_int16_t client_port)
{
    int slice_offset = rdma_slice_offset_from_port(ctx, client_port);
    return rdma_delete_slice_by_offset(ctx, slice_offset);
}

int rdma_delete_slice_by_offset(rdma_context_t *ctx, int slice_offset)
{
    if (slice_offset < 0 || slice_offset >= N_TCP_PER_CONNECTION || ctx->is_id_free[slice_offset] == TRUE)
        return rdma_ret_err(ctx, "Slice not found - rdma_delete_slice");

    ctx->is_id_free[slice_offset] = TRUE; // Mark the slice as free

    // free the buffer
    ctx->slices[slice_offset].client_buffer = NULL;
    ctx->slices[slice_offset].server_buffer = NULL;

    // notify the other side about the deletion
    if (rdma_send_notification(ctx, RDMA_DELETE_SLICE, slice_offset, 0) != 0)
        return rdma_ret_err(ctx, "Failed to send notification - rdma_delete_slice");

    printf("Deleted slice_offset %d\n", slice_offset);

    return 0;
}

int rdma_slice_offset_from_port(rdma_context_t *ctx, uint16_t client_port)
{
    for (int i = 0; i < N_TCP_PER_CONNECTION; i++)
    {
        if (ctx->slices[i].client_port == client_port)
        {
            return i;
        }
    }
    return -1;
}
