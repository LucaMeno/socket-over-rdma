#define _POSIX_C_SOURCE 200112L

#include "rdma_utils.h"

// PRIVATE FUNCTIONS
int rdma_send_notification(rdma_context_t *ctx, rdma_communication_code_t code);

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
    case EXCHANGE_REMOTE_INFO:
        return "EXCHANGE_REMOTE_INFO";
    case RDMA_CLOSE_CONTEXT:
        return "RDMA_CLOSE_CONTEXT";
    case NONE:
        return "NONE";
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
    if (!ctx->buffer)
        return rdma_ret_err(ctx, "malloc buffer");

    ctx->buffer_size = MR_SIZE;

    ctx->mr = ibv_reg_mr(ctx->pd, ctx->buffer, MR_SIZE,
                         IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

    ctx->send_cq = ibv_create_cq(ctx->conn->verbs, 10, NULL, NULL, 0);
    if (!ctx->send_cq)
        return rdma_ret_err(ctx, "ibv_create_cq (send)");

    ctx->recv_cq = ibv_create_cq(ctx->conn->verbs, 10, NULL, NULL, 0);
    if (!ctx->recv_cq)
    {
        ibv_destroy_cq(ctx->send_cq); // cleanup in caso di errore
        return rdma_ret_err(ctx, "ibv_create_cq (recv)");
    }

    struct ibv_qp_init_attr qp_attr = {
        .send_cq = ctx->send_cq,
        .recv_cq = ctx->recv_cq,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 1,
            .max_recv_sge = 1},
        .qp_type = IBV_QPT_RC};

    if (rdma_create_qp(ctx->conn, ctx->pd, &qp_attr))
    {
        ibv_destroy_cq(ctx->send_cq);
        ibv_destroy_cq(ctx->recv_cq);
        return rdma_ret_err(ctx, "rdma_create_qp");
    }

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
    struct ibv_cq *send_cq = ibv_create_cq(cctx->conn->verbs, 10, NULL, NULL, 0);
    if (!send_cq)
        return rdma_ret_err(cctx, "ibv_create_cq (send)");

    struct ibv_cq *recv_cq = ibv_create_cq(cctx->conn->verbs, 10, NULL, NULL, 0);
    if (!recv_cq)
    {
        ibv_destroy_cq(send_cq); // cleanup in caso di errore
        return rdma_ret_err(cctx, "ibv_create_cq (recv)");
    }

    cctx->send_cq = send_cq;
    cctx->recv_cq = recv_cq;

    struct ibv_qp_init_attr qp_attr = {
        .send_cq = send_cq,
        .recv_cq = recv_cq,
        .qp_type = IBV_QPT_RC,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 10,
            .max_recv_sge = 10}};

    if (rdma_create_qp(cctx->conn, cctx->pd, &qp_attr))
    {
        ibv_destroy_cq(send_cq);
        ibv_destroy_cq(recv_cq);
        return rdma_ret_err(cctx, "rdma_create_qp");
    }

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

    if (rdma_poll_cq_send(cctx))
        return rdma_ret_err(cctx, "rdma_poll_cq_send");

    // post a receive work request to receive the notification
    struct ibv_sge sge2 = {
        .addr = (uintptr_t)cctx->buffer,
        .length = sizeof(notification_t),
        .lkey = cctx->mr->lkey};

    struct ibv_recv_wr recv_wr = {
        .wr_id = 0,
        .sg_list = &sge2,
        .num_sge = 1};
    struct ibv_recv_wr *bad_wr2 = NULL;

    if (ibv_post_recv(cctx->conn->qp, &recv_wr, &bad_wr2) != 0 || bad_wr2)
    {
        fprintf(stderr, "Failed to post initial recv\n");
    }

    cctx->ringbuffer_server = (rdma_ringbuffer_t *)(cctx->buffer +
                                                    NOTIFICATION_OFFSET_SIZE);
    atomic_store(&cctx->ringbuffer_server->read_index, 0);
    atomic_store(&cctx->ringbuffer_server->remote_write_index, 0);
    atomic_store(&cctx->ringbuffer_server->local_write_index, 0);
    atomic_store(&cctx->ringbuffer_server->flags.flags, 0);

    cctx->ringbuffer_client = (rdma_ringbuffer_t *)(cctx->buffer +
                                                    NOTIFICATION_OFFSET_SIZE +
                                                    RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
    atomic_store(&cctx->ringbuffer_client->remote_write_index, 0);
    atomic_store(&cctx->ringbuffer_client->read_index, 0);
    atomic_store(&cctx->ringbuffer_client->local_write_index, 0);
    atomic_store(&cctx->ringbuffer_client->flags.flags, 0);

    // sleep(1);
    pthread_mutex_lock(&cctx->mtx_tx);
    cctx->is_ready = TRUE;
    pthread_cond_signal(&cctx->cond_tx);
    pthread_mutex_unlock(&cctx->mtx_tx);
    return 0;
}

/** SETUP */

int rdma_context_close(rdma_context_t *ctx)
{
    if (ctx->conn)
    {
        rdma_destroy_qp(ctx->conn);
        rdma_destroy_id(ctx->conn);
    }
    if (ctx->send_cq)
        ibv_destroy_cq(ctx->send_cq);
    if (ctx->recv_cq)
        ibv_destroy_cq(ctx->recv_cq);
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

    pthread_mutex_destroy(&ctx->mtx_tx);
    pthread_cond_destroy(&ctx->cond_tx);

    pthread_mutex_destroy(&ctx->mtx_rx);
    pthread_cond_destroy(&ctx->cond_rx);

    pthread_mutex_destroy(&ctx->mtx_polling);

    pthread_mutex_destroy(&ctx->mtx_flush);

    return 0;
}

int rdma_setup_context(rdma_context_t *ctx)
{
    // Initialize the slices
    ctx->is_ready = FALSE;
    ctx->buffer = NULL;
    ctx->buffer_size = 0;
    ctx->conn = NULL;
    ctx->pd = NULL;
    ctx->mr = NULL;
    ctx->recv_cq = NULL;
    ctx->send_cq = NULL;
    ctx->remote_ip = 0;
    ctx->remote_rkey = 0;
    ctx->remote_addr = 0;

    pthread_mutex_init(&ctx->mtx_tx, NULL);
    pthread_cond_init(&ctx->cond_tx, NULL);
    ctx->thread_busy_tx = FALSE;

    pthread_mutex_init(&ctx->mtx_rx, NULL);
    pthread_cond_init(&ctx->cond_rx, NULL);
    ctx->thread_busy_rx = FALSE;

    pthread_mutex_init(&ctx->mtx_polling, NULL);

    ctx->ringbuffer_client = NULL;
    ctx->ringbuffer_server = NULL;

    ctx->last_flush_ns = 0;
    pthread_mutex_init(&ctx->mtx_flush, NULL);

    return 0;
}

/** NOTIFICATION */

int rdma_send_notification(rdma_context_t *ctx, rdma_communication_code_t code)
{
    notification_t *notification = (notification_t *)ctx->buffer;

    if (ctx->is_server == TRUE)
        notification->from_server.code = code;
    else
        notification->from_client.code = code;

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
    send_wr.next = NULL;

    // Post send with ibv_post_send
    struct ibv_send_wr *bad_send_wr;
    if (ibv_post_send(ctx->conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
        return rdma_ret_err(ctx, "Failed to post send - rdma_send_notification");

    // Poll the completion queue
    if (rdma_poll_cq_send(ctx) != 0)
        return rdma_ret_err(ctx, "Failed to poll CQ - rdma_send_notification");

#ifdef RDMA_DEBUG_SR
    if (ctx->is_server == TRUE)
    {
        printf("S: send: %s (%d)\n",
               get_op_name(notification->from_server.code), notification->from_server.code);
    }
    else // client
    {
        printf("C: send: %s (%d)\n",
               get_op_name(notification->from_client.code), notification->from_client.code);
    }
#endif // RDMA_DEBUG_SR
    return 0;
}

/** COMMUNICATION */

int rdma_post_write_(rdma_context_t *ctx, uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, int signaled)
{
    struct ibv_send_wr send_wr_data = {};
    struct ibv_sge sge_data;

    // Fill ibv_sge with local buffer
    sge_data.addr = local_addr;      // Local address of the buffer
    sge_data.length = size_to_write; // Length of the buffer
    sge_data.lkey = ctx->mr->lkey;

    // Prepare ibv_send_wr with IBV_WR_RDMA_WRITE
    send_wr_data.opcode = IBV_WR_RDMA_WRITE;
    send_wr_data.wr.rdma.remote_addr = remote_addr;
    send_wr_data.wr.rdma.rkey = ctx->remote_rkey;
    send_wr_data.sg_list = &sge_data;
    send_wr_data.num_sge = 1;

    // Post send in SQ with ibv_post_send
    struct ibv_send_wr *bad_send_wr_data;
    int ret = ibv_post_send(ctx->conn->qp, &send_wr_data, &bad_send_wr_data);
    if (ret != 0) // Post the send work request
    {
        printf("CODE: %d\n", ret);
        return rdma_ret_err(ctx, "Failed to post send - rdma_post_write");
    }

    if (0)
    {
        // Poll the completion queue
        if (rdma_poll_cq_send(ctx) != 0)
            return rdma_ret_err(ctx, "Failed to poll CQ - rdma_post_write");
    }

    // NOT poll the CQ since the write is not signaled

#ifdef RDMA_DEBUG_WRITE
    if (ctx->is_server)
    {
        printf("S: RDMA_W: local=0x%lx len=%u remote=0x%lx rkey=%u\n",
               sge_data.addr, sge_data.length, send_wr_data.wr.rdma.remote_addr, send_wr_data.wr.rdma.rkey);
    }
    else
    {
        printf("C: RDMA_W: local=0x%lx len=%u remote=0x%lx rkey=%u\n",
               sge_data.addr, sge_data.length, send_wr_data.wr.rdma.remote_addr, send_wr_data.wr.rdma.rkey);
    }
#endif // RDMA_DEBUG_WR
    return 0;
}

int rdma_flush_buffer(rdma_context_t *ctx, rdma_ringbuffer_t *ringbuffer)
{
    if (pthread_mutex_trylock(&ctx->mtx_flush) != 0)
    {
        // Flush is already in progress
        return 0;
    }

    if (atomic_load(&ringbuffer->read_index) == atomic_load(&ringbuffer->local_write_index))
    {
        pthread_mutex_unlock(&ctx->mtx_flush);
        return 0; // nothing to flush
    }

    // flush the buffer

    if (!ctx || !ringbuffer)
        return rdma_ret_err(ctx, "Context or rb is NULL - rdma_flush_buffer");

    // update the remote write index
    atomic_store(&ringbuffer->remote_write_index, atomic_load(&ringbuffer->local_write_index));

    u_int32_t ri = atomic_load(&ringbuffer->read_index) % MAX_N_MSG_PER_BUFFER;
    u_int32_t wi = atomic_load(&ringbuffer->remote_write_index) % MAX_N_MSG_PER_BUFFER;

#ifdef RDMA_DEBUG_W_FLUSH
    printf("FLUSHING n: %d, wi: %d, ri: %d\n",
           (wi + MAX_N_MSG_PER_BUFFER - ri) % MAX_N_MSG_PER_BUFFER, wi, ri);
#endif // RDMA_DEBUG_W_FLUSH

    // manage the wrap around
    if (ri > wi)
    {
        //  first write: from ri to the end of the buffer
        uintptr_t batch_start = (uintptr_t)&ringbuffer->data[ri];
        size_t batch_size = (MAX_N_MSG_PER_BUFFER - ri) * sizeof(rdma_msg_t);

        uintptr_t remote_addr = ctx->remote_addr + ((uintptr_t)batch_start - (uintptr_t)ctx->buffer);

        if (rdma_post_write_(ctx, remote_addr, batch_start, batch_size, FALSE) != 0)
        {
            pthread_mutex_unlock(&ctx->mtx_flush);
            return rdma_ret_err(ctx, "Failed to post data batch - first write");
        }

        // second write: from the beginning of the buffer to wi
        batch_start = (uintptr_t)&ringbuffer->data[0];
        batch_size = (wi) * sizeof(rdma_msg_t);

        remote_addr = ctx->remote_addr + ((uintptr_t)batch_start - (uintptr_t)ctx->buffer);

        if (rdma_post_write_(ctx, remote_addr, batch_start, batch_size, FALSE) != 0)
        {
            pthread_mutex_unlock(&ctx->mtx_flush);
            return rdma_ret_err(ctx, "Failed to post data batch - second write");
        }
    }
    else
    {
        // normal case
        uintptr_t batch_start = (uintptr_t)&ringbuffer->data[ri];
        size_t batch_size = ((wi + MAX_N_MSG_PER_BUFFER - ri) % MAX_N_MSG_PER_BUFFER) * sizeof(rdma_msg_t);

        uintptr_t remote_addr = ctx->remote_addr + ((uintptr_t)batch_start - (uintptr_t)ctx->buffer);

        if (rdma_post_write_(ctx, remote_addr, batch_start, batch_size, FALSE) != 0)
        {
            pthread_mutex_unlock(&ctx->mtx_flush);
            return rdma_ret_err(ctx, "Failed to post data batch");
        }
    }

    // Update the read index on the remote side
    size_t write_index_offset = (size_t)((char *)ringbuffer - (char *)ctx->buffer) + sizeof(rdma_flag_t);
    uintptr_t remote_addr_write_index = ctx->remote_addr + write_index_offset;

    if (rdma_post_write_(ctx, remote_addr_write_index,
                         (uintptr_t)(ctx->buffer + write_index_offset),
                         sizeof(ringbuffer->remote_write_index), TRUE) != 0)
    {
        pthread_mutex_unlock(&ctx->mtx_flush);
        return rdma_ret_err(ctx, "Failed to post write index");
    }

    printf("Updating REMOTE write index: %u\n",
           (unsigned int)ringbuffer->remote_write_index);

    rdma_ringbuffer_t *peer_rb = (ctx->is_server == TRUE) ? ctx->ringbuffer_client : ctx->ringbuffer_server;

    if (!(atomic_load(&peer_rb->flags.flags) & RING_BUFFER_POLLING))
        rdma_send_data_ready(ctx);

    // update the read index on the local side
    // prevent the flush from being called again (could be improved?)
    atomic_store(&ringbuffer->read_index, atomic_load(&ringbuffer->remote_write_index));

    // set the last flush time
    uint64_t now = get_time_ms();
    ctx->last_flush_ns = now;

    pthread_mutex_unlock(&ctx->mtx_flush);
    return 0;
}

int rdma_write_msg(rdma_context_t *ctx, char *data, int data_size, struct sock_id original_socket)
{
#ifdef RDMA_DEBUG_WRITE_IN_MSG
    printf("-------------------------------------------\n");
    printf("Msg size: %u\n", data_size);
    printf("Msg original sk: %u:%u -> %u:%u\n",
           original_socket.sip, original_socket.sport,
           original_socket.dip, original_socket.dport);
#endif // RDMA_DEBUG_WRITE_IN_MSG

    if (!ctx)
        return rdma_ret_err(ctx, "Context is NULL - rdma_write_msg");

    rdma_ringbuffer_t *ringbuffer = (ctx->is_server == TRUE) ? ctx->ringbuffer_server : ctx->ringbuffer_client;

    if (!ringbuffer)
        return rdma_ret_err(ctx, "Ringbuffer is NULL - rdma_write_msg");

    uint32_t number_of_msg = (data_size + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;

    if (number_of_msg > MAX_N_MSG_PER_BUFFER)
        return rdma_ret_err(ctx, "Message too big - rdma_write_msg");

    int wi = atomic_load(&ringbuffer->local_write_index) % MAX_N_MSG_PER_BUFFER;
    int ri = atomic_load(&ringbuffer->read_index) % MAX_N_MSG_PER_BUFFER;

    int available_space = (ri + MAX_N_MSG_PER_BUFFER - wi - 1) % MAX_N_MSG_PER_BUFFER;

    if (available_space < number_of_msg)
    {
        // Buffer is full
        return rdma_ret_err(ctx, "Buffer is full - rdma_write_msg");
    }

    if (number_of_msg == 1)
    {
        rdma_msg_t *msg = &ringbuffer->data[wi];
        msg->msg_flags = 0;
        msg->original_sk_id = original_socket;
        msg->msg_size = data_size;
        memcpy(msg->msg, data, data_size);
    }
    else
    {
        return rdma_ret_err(ctx, "Multi-message support not implemented");
    }

    atomic_fetch_add(&ringbuffer->local_write_index, number_of_msg);

    if ((wi + MAX_N_MSG_PER_BUFFER - ri) % MAX_N_MSG_PER_BUFFER >= FLUSH_THRESHOLD_N)
    {
        // flush the buffer
        if (rdma_flush_buffer(ctx, ringbuffer) != 0)
            return rdma_ret_err(ctx, "Failed to flush buffer - rdma_write_msg");
    }

    return 0;
}

int rdma_parse_msg(bpf_context_t *bpf_ctx, client_sk_t *client_sks, rdma_msg_t *msg)
{
    // loockup the original socket
    // swap the ip and port
    msg->original_sk_id.dip ^= msg->original_sk_id.sip;
    msg->original_sk_id.sip ^= msg->original_sk_id.dip;
    msg->original_sk_id.dip ^= msg->original_sk_id.sip;
    msg->original_sk_id.dport ^= msg->original_sk_id.sport;
    msg->original_sk_id.sport ^= msg->original_sk_id.dport;
    msg->original_sk_id.dport ^= msg->original_sk_id.sport;

    // find the corresponding proxy socket
    struct sock_id proxy_sk_id = get_proxy_sk_from_app_sk(bpf_ctx, msg->original_sk_id);

    /* struct sock_id original_sk_id;
     original_sk_id.sip = msg->original_sk_id.dip;
     original_sk_id.sport = msg->original_sk_id.dport;
     original_sk_id.dip = msg->original_sk_id.sip;
     original_sk_id.dport = msg->original_sk_id.sport;

     struct sock_id proxy_sk_id = get_proxy_sk_from_app_sk(bpf_ctx, original_sk_id);*/

#ifdef RDMA_DEBUG_PARSE_MSG
    printf("O [%u:%u -> %u:%u] <-> P [%u:%u -> %u:%u]\n",
           msg->original_sk_id.sip, msg->original_sk_id.sport,
           msg->original_sk_id.dip, msg->original_sk_id.dport,
           proxy_sk_id.sip, proxy_sk_id.sport,
           proxy_sk_id.dip, proxy_sk_id.dport);
#endif // RDMA_DEBUG_PARSE_MSG

    // find the original socket in the list
    int i = 0;
    for (; i < NUMBER_OF_SOCKETS; i++)
    {
        if (client_sks[i].sk_id.dip == proxy_sk_id.dip &&
            client_sks[i].sk_id.sport == proxy_sk_id.sport &&
            client_sks[i].sk_id.sip == proxy_sk_id.sip &&
            client_sks[i].sk_id.dport == proxy_sk_id.dport)
        {
            // found the socket
            write(client_sks[i].fd, msg->msg, msg->msg_size);
            return 0;
        }
    }

    if (i == NUMBER_OF_SOCKETS)
    {
        // socket not found
        printf("Socket not found in the list: %u:%u -> %u:%u\n",
               msg->original_sk_id.sip, msg->original_sk_id.sport,
               msg->original_sk_id.dip, msg->original_sk_id.dport);
    }

    return 0;
}

int rdma_read_msg(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks)
{
    if (!ctx)
        return rdma_ret_err(ctx, "Context is NULL - rdma_read_msg");

    rdma_ringbuffer_t *rb_local = ctx->is_server ? ctx->ringbuffer_server : ctx->ringbuffer_client;
    rdma_ringbuffer_t *ringbuffer = ctx->is_server ? ctx->ringbuffer_client : ctx->ringbuffer_server;

    if (!ringbuffer)
        return rdma_ret_err(ctx, "Ringbuffer is NULL - rdma_read_msg");

    int ri = atomic_load(&ringbuffer->read_index);
    int wi = atomic_load(&ringbuffer->remote_write_index);

    if (wi == ri)
    {
        // nothing to read
        return 0;
    }

    int number_of_msg = wi - ri;

    wi %= MAX_N_MSG_PER_BUFFER;
    ri %= MAX_N_MSG_PER_BUFFER;

#ifdef RDMA_DEBUG_READ
    printf("READING: ri: %d, wi: %d, number_of_msg: %d, write_index: %d, read_index: %d\n",
           ri, wi, number_of_msg, ringbuffer->remote_write_index, ringbuffer->read_index);
#endif // RDMA_DEBUG_READ

    // manage the wrap around
    if (ri > wi)
    {
        //  read from ri to the end of the buffer
        for (int i = 0; i < MAX_N_MSG_PER_BUFFER - ri; i++)
        {
            int idx = (ri + i);
            rdma_msg_t *msg = &ringbuffer->data[idx];
            rdma_parse_msg(bpf_ctx, client_sks, msg);
        }

        // read from the beginning of the buffer to wi
        ri = 0;
        for (int i = 0; i < wi; i++)
        {
            int idx = (ri + i);
            rdma_msg_t *msg = &ringbuffer->data[idx];
            rdma_parse_msg(bpf_ctx, client_sks, msg);
        }
    }
    else
    {
        // normal case
        for (int i = 0; i < number_of_msg; i++)
        {
            int idx = (ri + i);
            rdma_msg_t *msg = &ringbuffer->data[idx];
            rdma_parse_msg(bpf_ctx, client_sks, msg);
        }
    }

    // ringbuffer->read_index += number_of_msg;
    atomic_fetch_add(&ringbuffer->read_index, number_of_msg);

    // update the read index on the remote side
    size_t read_index_offset = (size_t)((char *)ringbuffer - (char *)ctx->buffer) +
                               sizeof(rdma_flag_t) +
                               sizeof(ringbuffer->remote_write_index) +
                               sizeof(ringbuffer->local_write_index);

    uintptr_t remote_addr_read_index = ctx->remote_addr + read_index_offset;

    if (rdma_post_write_(ctx, remote_addr_read_index,
                         (uintptr_t)(ctx->buffer + read_index_offset),
                         sizeof(uint32_t), FALSE) != 0)
        return rdma_ret_err(ctx, "Failed to post read index update");

    printf("Updating REMOTE read index: %u\n",
           (unsigned int)ringbuffer->read_index);

    // allow polling again
    atomic_fetch_or(&rb_local->flags.flags, RING_BUFFER_CAN_POLLING);

    return 0;
}

int rdma_poll_cq_send(rdma_context_t *ctx)
{
    if (ctx->send_cq == NULL)
        return rdma_ret_err(ctx, "CQ is NULL - rdma_poll_cq_send");

    struct ibv_wc wc;
    int num_completions;
    do
    {
        num_completions = ibv_poll_cq(ctx->send_cq, 1, &wc);
    } while (num_completions == 0); // poll until we get a completion

    if (num_completions < 0)
        return rdma_ret_err(ctx, "Failed to poll CQ (num_completions<0) - rdma_poll_cq_send");

    if (wc.status != IBV_WC_SUCCESS)
    {
        fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
        return rdma_ret_err(ctx, "Failed to poll CQ - rdma_poll_cq_send");
    }

    return 0;
}

int rdma_poll_memory(volatile uint32_t *flag_to_poll)
{
    int i = 1;
    while (*flag_to_poll == FALSE)
    {
        // TODO: add a timeout in some way
        if (i % 1000 == 0)
        {
            __asm__ __volatile__("pause" ::: "memory");
        }
    }

    // consume the flag
    *flag_to_poll = FALSE;

    return 0;
}

int rdma_set_polling_status(rdma_context_t *ctx, uint32_t is_polling)
{
    rdma_ringbuffer_t *ringbuffer = (ctx->is_server == TRUE) ? ctx->ringbuffer_server : ctx->ringbuffer_client;
    unsigned int f = atomic_load(&ringbuffer->flags.flags);

    // is polling?
    if (((f & RING_BUFFER_POLLING) != 0) == is_polling)
        return 0;

    unsigned int expected = f;
    unsigned int desired;

    // CAS loop to set the polling status (Compare And Swap)
    do
    {
        desired = expected ^ RING_BUFFER_POLLING; // toggle bit
        desired |= RING_BUFFER_CAN_POLLING;       // set CAN_POLLING
    } while (!atomic_compare_exchange_weak(&ringbuffer->flags.flags, &expected, desired));

    // update the polling status on the remote side
    size_t offset = (size_t)((char *)ringbuffer - (char *)ctx->buffer);
    uintptr_t remote_addr = ctx->remote_addr + offset;

    if (rdma_post_write_(ctx, remote_addr, (uintptr_t)(ctx->buffer + offset), sizeof(ringbuffer->flags.flags), FALSE) != 0)
        return rdma_ret_err(ctx, "Failed to post write - rdma_set_polling_status");

    printf("Updating REMOTE polling status: %u\n",
           (unsigned int)ringbuffer->flags.flags);

    return 0;
}

int rdma_send_data_ready(rdma_context_t *ctx)
{
    // TODO: count the number of notification sent to notice the disconnection
    printf("Sending data ready notification\n");
    if (rdma_send_notification(ctx, RDMA_DATA_READY) != 0)
        return rdma_ret_err(ctx, "Failed to send notification - rdma_send_data_ready");

    return 0;
}

uint64_t get_time_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
}