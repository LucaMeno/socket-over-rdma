#define _POSIX_C_SOURCE 200112L

#include "rdma_utils.h"

uint32_t COUNT = 0;    // for debugging
uint32_t TX_COUNT = 0; // for debugging
uint32_t TX_SIZE = 0;
uint32_t TX_N_FLUSH = 0; // for debugging

atomic_uint RX_COUNT = 0; // for debugging
atomic_uint RX_SIZE = 0;  // for debugging
uint32_t RX_N_RECV = 0;   // for debugging

// PRIVATE FUNCTIONS

// UTILS
int rdma_send_notification(rdma_context_t *ctx, rdma_communication_code_t code);
int rdma_poll_cq_send(rdma_context_t *ctx);

// ERROR HANDLING
int rdma_err_int(rdma_context_t *rdma_ctx, char *msg);
void rdma_on_error(rdma_context_t *rdma_ctx, char *msg);

// COMMUNICATION
int rdma_parse_msg(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks, rdma_msg_t *msg);

/** CLIENT - SERVER */

int rdma_server_handle_new_client(rdma_context_t *ctx, struct rdma_event_channel *server_ec)
{
    ctx->pd = ibv_alloc_pd(ctx->conn->verbs);
    if (!ctx->pd)
        return rdma_err_int(ctx, "ibv_alloc_pd");

    ctx->buffer = malloc(MR_SIZE);
    if (!ctx->buffer)
        return rdma_err_int(ctx, "malloc buffer");

    ctx->buffer_size = MR_SIZE;

    ctx->mr = ibv_reg_mr(ctx->pd, ctx->buffer, MR_SIZE,
                         IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

    if (!ctx->mr)
        return rdma_err_int(ctx, "ibv_reg_mr");

    // create the completion channel to be able to use select()
    ctx->comp_channel = ibv_create_comp_channel(ctx->conn->verbs);
    if (!ctx->comp_channel)
        return rdma_err_int(ctx, "ibv_create_comp_channel");

    ctx->send_cq = ibv_create_cq(ctx->conn->verbs, 10, NULL, NULL, 0);
    if (!ctx->send_cq)
    {
        ibv_destroy_cq(ctx->send_cq);
        return rdma_err_int(ctx, "ibv_create_cq (send)");
    }

    ctx->recv_cq = ibv_create_cq(ctx->conn->verbs, 10, NULL, ctx->comp_channel, 0);
    if (!ctx->recv_cq)
    {
        ibv_destroy_cq(ctx->send_cq);
        return rdma_err_int(ctx, "ibv_create_cq (recv)");
    }

    // set the recv cq in event mode
    if (ibv_req_notify_cq(ctx->recv_cq, 0))
    {
        ibv_destroy_cq(ctx->recv_cq);
        return rdma_err_int(ctx, "ibv_req_notify_cq");
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
        return rdma_err_int(ctx, "rdma_create_qp");
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
        return rdma_err_int(ctx, "rdma_accept");

    struct rdma_cm_event *event;
    if (rdma_get_cm_event(server_ec, &event))
        return rdma_err_int(ctx, "rdma_get_cm_event");

    if (event->event != RDMA_CM_EVENT_ESTABLISHED)
        return rdma_err_int(ctx, "rdma_get_cm_event - not established");
    rdma_ack_cm_event(event);

    return 0;
}

int rdma_client_setup(rdma_context_t *cctx, uint32_t ip, uint16_t port)
{
    cctx->is_server = FALSE;

    cctx->conn = NULL;
    cctx->client_ec = rdma_create_event_channel();
    if (!cctx->client_ec)
        return rdma_err_int(cctx, "rdma_create_event_channel");

    if (rdma_create_id(cctx->client_ec, &cctx->conn, NULL, RDMA_PS_TCP))
        return rdma_err_int(cctx, "rdma_create_id - rdma_client_setup");

    // Resolve the address
    char ip_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)))
        return rdma_err_int(cctx, "inet_ntop - rdma_client_setup");

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM};
    struct addrinfo *res;
    if (getaddrinfo(ip_str, port_str, &hints, &res) != 0)
        return rdma_err_int(cctx, "getaddrinfo - rdma_client_setup");

    if (rdma_resolve_addr(cctx->conn, NULL, res->ai_addr, 2000))
        return rdma_err_int(cctx, "rdma_resolve_addr");

    cctx->remote_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(res);

    // Wait for the ADDR_RESOLVED event
    struct rdma_cm_event *event = NULL;
    if (rdma_get_cm_event(cctx->client_ec, &event))
        return rdma_err_int(cctx, "rdma_get_cm_event - addr_resolved");

    if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED)
        return rdma_err_int(cctx, "unexpected event - not ADDR_RESOLVED");

    rdma_ack_cm_event(event);

    // Resolve the route
    if (rdma_resolve_route(cctx->conn, 2000))
        return rdma_err_int(cctx, "rdma_resolve_route");

    if (rdma_get_cm_event(cctx->client_ec, &event))
        return rdma_err_int(cctx, "rdma_get_cm_event - route_resolved");

    if (event->event != RDMA_CM_EVENT_ROUTE_RESOLVED)
        return rdma_err_int(cctx, "unexpected event - not ROUTE_RESOLVED");

    rdma_ack_cm_event(event);

    // PD, buffer, MR
    cctx->pd = ibv_alloc_pd(cctx->conn->verbs);
    if (!cctx->pd)
        return rdma_err_int(cctx, "ibv_alloc_pd");

    cctx->buffer = malloc(MR_SIZE);
    if (!cctx->buffer)
        return rdma_err_int(cctx, "malloc buffer");

    cctx->buffer_size = MR_SIZE;

    cctx->mr = ibv_reg_mr(cctx->pd, cctx->buffer, MR_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

    if (!cctx->mr)
        return rdma_err_int(cctx, "ibv_reg_mr");

    // CQ + QP
    cctx->comp_channel = ibv_create_comp_channel(cctx->conn->verbs);
    if (!cctx->comp_channel)
        return rdma_err_int(cctx, "ibv_create_comp_channel");

    printf("Creating send and receive completion queues\n");

    cctx->send_cq = ibv_create_cq(cctx->conn->verbs, 10, NULL, NULL, 0);
    if (!cctx->send_cq)
    {
        ibv_destroy_cq(cctx->recv_cq);
        return rdma_err_int(cctx, "ibv_create_cq (send)");
    }

    cctx->recv_cq = ibv_create_cq(cctx->conn->verbs, 10, NULL, cctx->comp_channel, 0);
    if (!cctx->recv_cq)
    {
        ibv_destroy_cq(cctx->send_cq);
        return rdma_err_int(cctx, "ibv_create_cq (recv)");
    }

    if (ibv_req_notify_cq(cctx->recv_cq, 0))
        return rdma_err_int(cctx, "ibv_req_notify_cq");

    struct ibv_qp_init_attr qp_attr = {
        .send_cq = cctx->send_cq,
        .recv_cq = cctx->recv_cq,
        .qp_type = IBV_QPT_RC,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 10,
            .max_recv_sge = 10}};

    if (rdma_create_qp(cctx->conn, cctx->pd, &qp_attr))
    {
        ibv_destroy_cq(cctx->send_cq);
        ibv_destroy_cq(cctx->recv_cq);
        return rdma_err_int(cctx, "rdma_create_qp");
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
        return rdma_err_int(cctx, "rdma_connect");

    struct rdma_cm_event *event = NULL;
    if (rdma_get_cm_event(cctx->client_ec, &event))
        return rdma_err_int(cctx, "rdma_get_cm_event - connect");

    if (event->event != RDMA_CM_EVENT_ESTABLISHED)
        return rdma_err_int(cctx, "unexpected event - not ESTABLISHED");

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
        return rdma_err_int(cctx, "ibv_post_send");

    if (rdma_poll_cq_send(cctx))
        return rdma_err_int(cctx, "rdma_poll_cq_send");

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
    atomic_store(&cctx->ringbuffer_server->local_read_index, 0);
    atomic_store(&cctx->ringbuffer_server->remote_read_index, 0);
    atomic_store(&cctx->ringbuffer_server->remote_write_index, 0);
    atomic_store(&cctx->ringbuffer_server->local_write_index, 0);
    atomic_store(&cctx->ringbuffer_server->flags.flags, 0);

    cctx->ringbuffer_client = (rdma_ringbuffer_t *)(cctx->buffer +
                                                    NOTIFICATION_OFFSET_SIZE +
                                                    RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
    atomic_store(&cctx->ringbuffer_client->remote_write_index, 0);
    atomic_store(&cctx->ringbuffer_client->local_read_index, 0);
    atomic_store(&cctx->ringbuffer_client->remote_read_index, 0);
    atomic_store(&cctx->ringbuffer_client->local_write_index, 0);
    atomic_store(&cctx->ringbuffer_client->flags.flags, 0);

    // sleep(1);
    pthread_mutex_lock(&cctx->mtx_tx);
    atomic_store(&cctx->is_ready, TRUE);
    pthread_cond_signal(&cctx->cond_tx);
    pthread_mutex_unlock(&cctx->mtx_tx);
    return 0;
}

/** SETUP */

int rdma_context_destroy(rdma_context_t *ctx)
{
    if (ctx == NULL)
        return 0; // nothing to destroy

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
    if (ctx->comp_channel)
        ibv_destroy_comp_channel(ctx->comp_channel);

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

    pthread_mutex_destroy(&ctx->mtx_flush);

    pthread_mutex_destroy(&ctx->mtx_test);

    return 0;
}

int rdma_context_init(rdma_context_t *ctx)
{
    atomic_store(&ctx->is_ready, FALSE);
    ctx->remote_ip = 0;
    ctx->buffer = NULL;
    ctx->buffer_size = 0;
    ctx->conn = NULL;
    ctx->pd = NULL;
    ctx->mr = NULL;
    ctx->recv_cq = NULL;
    ctx->send_cq = NULL;
    ctx->remote_rkey = 0;
    ctx->remote_addr = 0;
    ctx->client_ec = NULL;
    ctx->comp_channel = NULL;

    ctx->ringbuffer_client = NULL;
    ctx->ringbuffer_server = NULL;

    pthread_mutex_init(&ctx->mtx_tx, NULL);
    pthread_cond_init(&ctx->cond_tx, NULL);

    pthread_mutex_init(&ctx->mtx_rx, NULL);
    pthread_cond_init(&ctx->cond_rx, NULL);

    ctx->last_flush_ns = 0;
    pthread_mutex_init(&ctx->mtx_flush, NULL);

#ifdef AUTOSCALE_FLUSH_THRESHOLD
    atomic_store(&ctx->flush_threshold, MIN_FLUSH_THRESHOLD);
#else
    atomic_store(&ctx->flush_threshold, THRESHOLD_NOT_AUTOSCALER);
#endif // AUTOSCALE_FLUSH_THRESHOLD

    atomic_store(&ctx->n_msg_sent, 0);
    ctx->flush_threshold_set_time = 0;

    pthread_mutex_init(&ctx->mtx_test, NULL);

    ctx->time_last_recv = 0;
    ctx->n_recv_msg = 0;

    ctx->hash_fs_sk_1 = NULL;
    ctx->hash_fd_sk_2 = &ctx->hash_fs_sk_1;

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
        return rdma_err_int(ctx, "Failed to post send - rdma_send_notification");

    // Poll the completion queue
    if (rdma_poll_cq_send(ctx) != 0)
        return rdma_err_int(ctx, "Failed to poll CQ - rdma_send_notification");

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

int rdma_send_data_ready(rdma_context_t *ctx)
{
    return rdma_send_notification(ctx, RDMA_DATA_READY);
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
    if (signaled == TRUE)
        send_wr_data.send_flags = IBV_SEND_SIGNALED;

    // Post send in SQ with ibv_post_send
    struct ibv_send_wr *bad_send_wr_data;
    int ret = ibv_post_send(ctx->conn->qp, &send_wr_data, &bad_send_wr_data);
    if (ret != 0) // Post the send work request
    {
        printf("CODE: %d\n", ret);
        return rdma_err_int(ctx, "Failed to post send - rdma_post_write");
    }

    // Poll the completion queue
    if (signaled == TRUE)
        if (rdma_poll_cq_send(ctx) != 0)
            return rdma_err_int(ctx, "Failed to poll CQ - rdma_post_write");

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
    if (!ctx || !ringbuffer)
        return rdma_err_int(ctx, "Context or rb is NULL - rdma_flush_buffer");

    uint32_t actual_w = atomic_load(&ringbuffer->local_write_index);
    uint32_t actual_r = atomic_load(&ringbuffer->local_read_index);
    uint32_t remote_r = atomic_load(&ringbuffer->remote_read_index);

    uint32_t w_idx = RING_IDX(actual_w);
    uint32_t r_idx = RING_IDX(remote_r);

    if (r_idx > w_idx)
    {
        // wrap-around
        uintptr_t batch_start = (uintptr_t)&ringbuffer->data[r_idx];
        size_t batch_size = (MAX_MSG_BUFFER - r_idx) * sizeof(rdma_msg_t);

        uintptr_t remote_addr = ctx->remote_addr + ((uintptr_t)batch_start - (uintptr_t)ctx->buffer);

        if (rdma_post_write_(ctx, remote_addr, batch_start, batch_size, FALSE) != 0)
        {
            return rdma_err_int(ctx, "Failed to post data batch - first write");
        }

        batch_start = (uintptr_t)&ringbuffer->data[0];
        batch_size = w_idx * sizeof(rdma_msg_t);

        remote_addr = ctx->remote_addr + ((uintptr_t)batch_start - (uintptr_t)ctx->buffer);

        if (rdma_post_write_(ctx, remote_addr, batch_start, batch_size, FALSE) != 0)
        {
            return rdma_err_int(ctx, "Failed to post data batch - second write");
        }
    }
    else
    {
        // normal case
        uintptr_t batch_start = (uintptr_t)&ringbuffer->data[r_idx];
        size_t batch_size = (w_idx - r_idx) * sizeof(rdma_msg_t);

        uintptr_t remote_addr = ctx->remote_addr + ((uintptr_t)batch_start - (uintptr_t)ctx->buffer);

        if (rdma_post_write_(ctx, remote_addr, batch_start, batch_size, FALSE) != 0)
        {
            return rdma_err_int(ctx, "Failed to post data batch");
        }
    }

    // Update the write index
    atomic_store(&ringbuffer->remote_write_index, actual_w);

    size_t write_index_offset = (size_t)((char *)ringbuffer - (char *)ctx->buffer) +
                                offsetof(rdma_ringbuffer_t, remote_write_index);

    uintptr_t remote_addr_write_index = ctx->remote_addr + write_index_offset;

    if (rdma_post_write_(ctx, remote_addr_write_index,
                         (uintptr_t)(ctx->buffer + write_index_offset),
                         sizeof(ringbuffer->remote_write_index), TRUE) != 0)
    {
        return rdma_err_int(ctx, "Failed to post write index");
    }

    rdma_ringbuffer_t *peer_rb = (ctx->is_server == TRUE) ? ctx->ringbuffer_client : ctx->ringbuffer_server;

    if (!(atomic_load(&peer_rb->flags.flags) & RING_BUFFER_POLLING))
        rdma_send_data_ready(ctx);

    // update the local read index
    atomic_store(&ringbuffer->local_read_index, actual_w);

    ctx->last_flush_ns = get_time_ms();

#ifdef RDMA_DEBUG_FLUSH
    uint32_t msg_to_flush = RING_IDX(actual_w - actual_r);
    TX_COUNT += msg_to_flush;
    TX_N_FLUSH += 1;
    if (TX_N_FLUSH % RDMA_DEBUG_INTERVAL == 0)
    {
        printf("TX_COUNT: %u (+%d), TX_SIZE: %u Thrsh: %u\n",
               TX_COUNT,
               msg_to_flush,
               TX_SIZE,
               atomic_load(&ctx->flush_threshold));
    }
#endif // RDMA_DEBUG_FLUSH

    return 0;
}

int rdma_write_msg(rdma_context_t *ctx, int src_fd, struct sock_id original_socket)
{
    if (!ctx)
        return rdma_err_int(ctx, "Context is NULL - rdma_write_msg");

    rdma_ringbuffer_t *ringbuffer = (ctx->is_server == TRUE) ? ctx->ringbuffer_server : ctx->ringbuffer_client;

    if (!ringbuffer)
        return rdma_err_int(ctx, "Ringbuffer is NULL - rdma_write_msg");

    uint32_t start_w_index, end_w_index, available_space;

    while (1)
    { // wait until there is enough space in the ringbuffer
        while (1)
        {
            start_w_index = atomic_load(&ringbuffer->local_write_index);
            end_w_index = atomic_load(&ringbuffer->remote_read_index);

            uint32_t used = start_w_index - end_w_index; // wrap-around safe
            available_space = MAX_MSG_BUFFER - used - 1;

            if (available_space >= 1)
                break;

            sched_yield();
            COUNT++;
            if (COUNT % 1000000 == 0)
            {
                printf("STUCK %u - local_w: %u, remote_r: %u av_space: %u\n",
                       COUNT, start_w_index, end_w_index, available_space);
            }
        }

        // modulo the indexes
        start_w_index = RING_IDX(start_w_index);
        end_w_index = RING_IDX(end_w_index);

        rdma_msg_t *msg = &ringbuffer->data[start_w_index];

        msg->msg_size = recv(src_fd, msg->msg, MAX_PAYLOAD_SIZE, 0);
        if ((int)msg->msg_size <= 0)
        {
            return msg->msg_size;
        }

#ifdef RDMA_DEBUG_FLUSH
        TX_SIZE += msg->msg_size;
#endif // RDMA_DEBUG_FLUSH

        msg->msg_flags = 0;
        msg->original_sk_id = original_socket;
        msg->number_of_slots = 1;

        atomic_fetch_add(&ctx->n_msg_sent, 1);
        // atomic_fetch_add(&ringbuffer->local_write_index, 1);

        ringbuffer->local_write_index++;
    }

    return 1;
}

int rdma_parse_msg(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks, rdma_msg_t *msg)
{
    // retrive the proxy_fd
    int fd = hash_get_fd_from_sk(ctx->hash_fs_sk_1, msg->original_sk_id);
    if (fd > 0)
    {
        send(fd, msg->msg, msg->msg_size, 0);
        return 0;
    }
    else
    {
        // loockup the original socket
        // swap the ip and port
        struct sock_id swapped;
        swapped.dip = msg->original_sk_id.sip;
        swapped.sip = msg->original_sk_id.dip;
        swapped.dport = msg->original_sk_id.sport;
        swapped.sport = msg->original_sk_id.dport;

        // find the corresponding proxy socket
        struct sock_id proxy_sk_id = bpf_get_proxy_sk_from_app_sk(bpf_ctx, swapped);

#ifdef RDMA_DEBUG_PARSE_MSG
        printf("O [%u:%u -> %u:%u] <-> P [%u:%u -> %u:%u]\n",
               swapped.sip, swapped.sport,
               swapped.dip, swapped.dport,
               proxy_sk_id.sip, proxy_sk_id.sport,
               proxy_sk_id.dip, proxy_sk_id.dport);
#endif // RDMA_DEBUG_PARSE_MSG

        // find the original socket in the lists
        int i = 0;
        for (; i < NUMBER_OF_SOCKETS; i++)
        {
            if (client_sks[i].sk_id.dip == proxy_sk_id.dip &&
                client_sks[i].sk_id.sport == proxy_sk_id.sport &&
                client_sks[i].sk_id.sip == proxy_sk_id.sip &&
                client_sks[i].sk_id.dport == proxy_sk_id.dport)
            {
                // update the map with the new socket
                // bpf_add_app_sk_to_proxy_fd(bpf_ctx, msg->original_sk_id, client_sks[i].fd);
                printf("New entry: %u:%u - %u:%u -> %d\n",
                       msg->original_sk_id.sip, msg->original_sk_id.sport,
                       msg->original_sk_id.dip, msg->original_sk_id.dport,
                       client_sks[i].fd);
                hash_add_update_sk_to_fd(ctx->hash_fd_sk_2, msg->original_sk_id, client_sks[i].fd);

                // found the socket
                send(client_sks[i].fd, msg->msg, msg->msg_size, 0);

                return 0;
            }
        }

        if (i == NUMBER_OF_SOCKETS)
        {
            printf("Socket not found in the list: %u:%u -> %u:%u\n",
                   msg->original_sk_id.sip, msg->original_sk_id.sport,
                   msg->original_sk_id.dip, msg->original_sk_id.dport);
        }
    }

    return 0;
}

int rdma_update_remote_read_idx(rdma_context_t *ctx, rdma_ringbuffer_t *ringbuffer, uint32_t r_idx)
{
    // COMMIT the read index
    atomic_store(&ringbuffer->remote_read_index, r_idx);

    size_t read_index_offset = (size_t)((char *)ringbuffer - (char *)ctx->buffer) +
                               offsetof(rdma_ringbuffer_t, remote_read_index);

    uintptr_t remote_addr_read_index = ctx->remote_addr + read_index_offset;

    if (rdma_post_write_(ctx,
                         remote_addr_read_index,
                         (uintptr_t)(ctx->buffer + read_index_offset),
                         sizeof(ringbuffer->remote_read_index),
                         TRUE) != 0)
    {
        return rdma_err_int(ctx, "Failed to post read index update");
    }

    return 0;
}

int rdma_read_msg(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks, uint32_t start_read_index, uint32_t end_read_index)
{
    if (!ctx)
        return rdma_err_int(ctx, "Context is NULL - rdma_read_msg");

    rdma_ringbuffer_t *ringbuffer = ctx->is_server ? ctx->ringbuffer_client : ctx->ringbuffer_server;

    if (!ringbuffer)
        return rdma_err_int(ctx, "Ringbuffer is NULL - rdma_read_msg");

    if (start_read_index == end_read_index)
    {
        // nothing to read
        return 0;
    }

    uint32_t number_of_msg = (end_read_index + MAX_MSG_BUFFER - start_read_index) % MAX_MSG_BUFFER;

    start_read_index = RING_IDX(start_read_index);
    end_read_index = RING_IDX(end_read_index);

    u_int32_t n = 0;
    for (int i = 0; i < number_of_msg;)
    {
        int idx = RING_IDX(start_read_index + i);
        rdma_msg_t *msg = &ringbuffer->data[idx];
        rdma_parse_msg(ctx, bpf_ctx, client_sks, msg);
        i += msg->number_of_slots;

#ifdef RDMA_DEBUG_READ
        RX_COUNT += msg->number_of_slots;
        RX_SIZE += msg->msg_size;
        n += msg->msg_size;
#endif // RDMA_DEBUG_READ
    }

#ifdef RDMA_DEBUG_READ
    RX_N_RECV++;

    if (RX_N_RECV % RDMA_DEBUG_INTERVAL == 0)
    {
        printf("RX_COUNT: %d (+%d), RX_SIZE: %u (+%u) rem_r_idx: %u\n",
               atomic_load(&RX_COUNT),
               number_of_msg,
               atomic_load(&RX_SIZE),
               n,
               (unsigned int)atomic_load(&ringbuffer->remote_read_index));
    }

#endif // RDMA_DEBUG_READ
    return 0;
}

/** POLLING */

int rdma_poll_cq_send(rdma_context_t *ctx)
{
    if (ctx->send_cq == NULL)
        return rdma_err_int(ctx, "CQ is NULL - rdma_poll_cq_send");

    struct ibv_wc wc;
    int num_completions;
    do
    {
        num_completions = ibv_poll_cq(ctx->send_cq, 1, &wc);
    } while (num_completions == 0); // poll until we get a completion

    if (num_completions < 0)
        return rdma_err_int(ctx, "Failed to poll CQ (num_completions<0) - rdma_poll_cq_send");

    if (wc.status != IBV_WC_SUCCESS)
    {
        fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
        return rdma_err_int(ctx, "Failed to poll CQ - rdma_poll_cq_send");
    }

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

    if (rdma_post_write_(ctx, remote_addr,
                         (uintptr_t)(ctx->buffer + offset),
                         sizeof(ringbuffer->flags.flags),
                         FALSE) != 0)
        return rdma_err_int(ctx, "Failed to post write - rdma_set_polling_status");

    printf("Updating REMOTE polling status: %u\n",
           (unsigned int)ringbuffer->flags.flags);

    return 0;
}

/** MISC */

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

uint64_t get_time_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
}

/** ERRORS */

int rdma_err_int(rdma_context_t *rdma_ctx, char *msg)
{
    rdma_on_error(rdma_ctx, msg);
    return -1;
}

void rdma_on_error(rdma_context_t *rdma_ctx, char *msg)
{
    if (rdma_ctx)
    {
        rdma_context_destroy(rdma_ctx);
    }
    log_error("RDMA ERROR: %s", msg);
}