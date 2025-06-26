
#include <RdmaContext.h>

using namespace std;

namespace rdma
{
    int COUNT = 0; // for debugging

    // CLIENT - SERVER

    void RdmaContext::rdma_server_handle_new_client(struct rdma_event_channel *server_ec)
    {
        pd = ibv_alloc_pd(conn->verbs);
        if (!pd)
            throw runtime_error("ibv_alloc_pd failed");

        buffer = malloc(MR_SIZE);
        if (!buffer)
            throw runtime_error("malloc buffer failed");

        buffer_size = MR_SIZE;

        mr = ibv_reg_mr(pd, buffer, MR_SIZE,
                        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

        if (!mr)
            throw runtime_error("ibv_reg_mr failed");

        // create the completion channel to be able to use select()
        comp_channel = ibv_create_comp_channel(conn->verbs);
        if (!comp_channel)
            throw runtime_error("ibv_create_comp_channel failed");

        send_cq = ibv_create_cq(conn->verbs, 10, NULL, NULL, 0);
        if (!send_cq)
        {
            ibv_destroy_cq(send_cq);
            throw runtime_error("ibv_create_cq (send) failed");
        }

        recv_cq = ibv_create_cq(conn->verbs, 10, NULL, comp_channel, 0);
        if (!recv_cq)
        {
            ibv_destroy_cq(send_cq);
            throw runtime_error("ibv_create_cq (recv) failed");
        }

        // set the recv cq in event mode
        if (ibv_req_notify_cq(recv_cq, 0))
        {
            ibv_destroy_cq(recv_cq);
            ibv_destroy_cq(send_cq);
            throw runtime_error("ibv_req_notify_cq failed");
        }

        struct ibv_qp_init_attr qp_attr = {
            .send_cq = send_cq,
            .recv_cq = recv_cq,
            .cap = {
                .max_send_wr = 128,
                .max_recv_wr = 10,
                .max_send_sge = 1,
                .max_recv_sge = 1},
            .qp_type = IBV_QPT_RC};

        if (rdma_create_qp(conn, pd, &qp_attr))
        {
            ibv_destroy_cq(send_cq);
            ibv_destroy_cq(recv_cq);
            throw runtime_error("rdma_create_qp failed");
        }

        // Post a receive work request to receive the remote address and rkey
        struct ibv_sge sge = {
            .addr = (uintptr_t)buffer,
            .length = sizeof(notification_t) + sizeof(rdma_meta_info_t),
            .lkey = mr->lkey};

        struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
        struct ibv_recv_wr *bad_wr;
        ibv_post_recv(conn->qp, &recv_wr, &bad_wr);

        // Accept the connection and send the remote address and rkey
        rdma_meta_info_t info = {
            .addr = (uintptr_t)buffer,
            .rkey = mr->rkey};

        struct rdma_conn_param conn_param = {
            .initiator_depth = 1,
            .responder_resources = 1,
            .rnr_retry_count = 7,
            .private_data = &info,
            .private_data_len = sizeof(info)};

        if (rdma_accept(conn, &conn_param))
            throw runtime_error("rdma_accept failed");

        struct rdma_cm_event *event;
        if (rdma_get_cm_event(server_ec, &event))
            throw runtime_error("rdma_get_cm_event failed");

        if (event->event != RDMA_CM_EVENT_ESTABLISHED)
            throw runtime_error("unexpected event - not ESTABLISHED");

        rdma_ack_cm_event(event);
    }

    void RdmaContext::rdma_client_setup(uint32_t ip, uint16_t port)
    {
        is_server = FALSE;

        conn = NULL;
        client_ec = rdma_create_event_channel();
        if (!client_ec)
            throw runtime_error("rdma_create_event_channel failed");

        if (rdma_create_id(client_ec, &conn, NULL, RDMA_PS_TCP))
            throw runtime_error("rdma_create_id failed");

        // Resolve the address
        char ip_str[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)))
            throw runtime_error("inet_ntop failed");

        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%u", port);

        struct addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM};

        struct addrinfo *res;

        if (getaddrinfo(ip_str, port_str, &hints, &res) != 0)
            throw runtime_error("getaddrinfo failed");

        if (rdma_resolve_addr(conn, NULL, res->ai_addr, 2000))
            throw runtime_error("rdma_resolve_addr failed");

        remote_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

        freeaddrinfo(res);

        // Wait for the ADDR_RESOLVED event
        struct rdma_cm_event *event = NULL;
        if (rdma_get_cm_event(client_ec, &event))
            throw runtime_error("rdma_get_cm_event - addr_resolved failed");

        if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED)
            throw runtime_error("unexpected event - not ADDR_RESOLVED");

        rdma_ack_cm_event(event);

        // Resolve the route
        if (rdma_resolve_route(conn, 2000))
            throw runtime_error("rdma_resolve_route failed");

        if (rdma_get_cm_event(client_ec, &event))
            throw runtime_error("rdma_get_cm_event - route_resolved failed");

        if (event->event != RDMA_CM_EVENT_ROUTE_RESOLVED)
            throw runtime_error("unexpected event - not ROUTE_RESOLVED");

        rdma_ack_cm_event(event);

        // PD, buffer, MR
        pd = ibv_alloc_pd(conn->verbs);
        if (!pd)
            throw runtime_error("ibv_alloc_pd failed");

        buffer = malloc(MR_SIZE);
        if (!buffer)
            throw runtime_error("malloc buffer failed");

        buffer_size = MR_SIZE;

        mr = ibv_reg_mr(pd, buffer, MR_SIZE,
                        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

        if (!mr)
            throw runtime_error("ibv_reg_mr failed");

        // CQ + QP
        comp_channel = ibv_create_comp_channel(conn->verbs);
        if (!comp_channel)
            throw runtime_error("ibv_create_comp_channel failed");

        cout << "Creating send and receive completion queues..." << endl;

        send_cq = ibv_create_cq(conn->verbs, 10, NULL, NULL, 0);
        if (!send_cq)
        {
            ibv_destroy_cq(recv_cq);
            throw runtime_error("ibv_create_cq (send) failed");
        }

        recv_cq = ibv_create_cq(conn->verbs, 10, NULL, comp_channel, 0);
        if (!recv_cq)
        {
            ibv_destroy_cq(send_cq);
            throw runtime_error("ibv_create_cq (recv) failed");
        }

        if (ibv_req_notify_cq(recv_cq, 0))
            throw runtime_error("ibv_req_notify_cq failed");

        struct ibv_qp_init_attr qp_attr = {
            .send_cq = send_cq,
            .recv_cq = recv_cq,
            .qp_type = IBV_QPT_RC,
            .cap = {
                .max_send_wr = 128,
                .max_recv_wr = 10,
                .max_send_sge = 10,
                .max_recv_sge = 10}};

        if (rdma_create_qp(conn, pd, &qp_attr))
        {
            ibv_destroy_cq(send_cq);
            ibv_destroy_cq(recv_cq);
            throw runtime_error("rdma_create_qp failed");
        }

        cout << "Client connected to server at " << ip_str << ":" << port_str << endl;
    }

    void RdmaContext::rdma_client_connect()
    {
        struct rdma_conn_param conn_param = {
            .initiator_depth = 1,
            .responder_resources = 1,
            .rnr_retry_count = 7};

        if (rdma_connect(conn, &conn_param))
            throw runtime_error("rdma_connect failed");

        struct rdma_cm_event *event = NULL;
        if (rdma_get_cm_event(client_ec, &event))
            throw runtime_error("rdma_get_cm_event failed");

        if (event->event != RDMA_CM_EVENT_ESTABLISHED)
            throw runtime_error("unexpected event - not ESTABLISHED");

        rdma_meta_info_t *info = (rdma_meta_info_t *)event->param.conn.private_data;
        remote_addr = info->addr;
        remote_rkey = info->rkey;

        rdma_ack_cm_event(event);

        // send the remote address and rkey to the server
        notification_t *notification = (notification_t *)buffer;
        notification->from_client.code = CommunicationCode::EXCHANGE_REMOTE_INFO;

        rdma_meta_info_t *remote_info = (rdma_meta_info_t *)(buffer + sizeof(notification_t));
        remote_info->addr = (uintptr_t)buffer;
        remote_info->rkey = mr->rkey;

        struct ibv_sge sge = {
            .addr = (uintptr_t)buffer,
            .length = sizeof(notification_t) + sizeof(rdma_meta_info_t),
            .lkey = mr->lkey};

        struct ibv_send_wr send_wr = {
            .wr_id = 0,
            .sg_list = &sge,
            .num_sge = 1,
            .opcode = IBV_WR_SEND,
            .send_flags = IBV_SEND_SIGNALED};

        struct ibv_send_wr *bad_wr;
        if (ibv_post_send(conn->qp, &send_wr, &bad_wr))
            throw runtime_error("Failed to post send - rdma_send_notification");

        rdma_poll_cq_send();

        // post a receive work request to receive the notification
        struct ibv_sge sge2 = {
            .addr = (uintptr_t)buffer,
            .length = sizeof(notification_t),
            .lkey = mr->lkey};

        struct ibv_recv_wr recv_wr = {
            .wr_id = 0,
            .sg_list = &sge2,
            .num_sge = 1};
        struct ibv_recv_wr *bad_wr2 = NULL;

        if (ibv_post_recv(conn->qp, &recv_wr, &bad_wr2) != 0 || bad_wr2)
            throw runtime_error("Failed to post recv - rdma_send_notification");

        ringbuffer_server = (rdma_ringbuffer_t *)(buffer +
                                                  NOTIFICATION_OFFSET_SIZE);
        atomic_store(&ringbuffer_server->local_read_index, 0);
        atomic_store(&ringbuffer_server->remote_read_index, 0);
        atomic_store(&ringbuffer_server->remote_write_index, 0);
        atomic_store(&ringbuffer_server->local_write_index, 0);
        atomic_store(&ringbuffer_server->flags.flags, 0);

        ringbuffer_client = (rdma_ringbuffer_t *)(buffer +
                                                  NOTIFICATION_OFFSET_SIZE +
                                                  RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
        atomic_store(&ringbuffer_client->remote_write_index, 0);
        atomic_store(&ringbuffer_client->local_read_index, 0);
        atomic_store(&ringbuffer_client->remote_read_index, 0);
        atomic_store(&ringbuffer_client->local_write_index, 0);
        atomic_store(&ringbuffer_client->flags.flags, 0);

        // sleep(1);
        unique_lock<mutex> lock(mtx_tx);
        is_ready = TRUE;
        cond_tx.notify_all(); // Notify the waiting threads that the context is ready
    }

    // SETUP

    void RdmaContext::init()
    {
        atomic_store(&is_ready, FALSE);
        remote_ip = 0;
        buffer = NULL;
        buffer_size = 0;
        conn = NULL;
        pd = NULL;
        mr = NULL;
        recv_cq = NULL;
        send_cq = NULL;
        remote_rkey = 0;
        remote_addr = 0;
        client_ec = NULL;
        comp_channel = NULL;

        ringbuffer_client = NULL;
        ringbuffer_server = NULL;

        last_flush_ms = 0;
        is_flushing = FALSE;

#ifdef AUTOSCALE_FLUSH_THRESHOLD
        atomic_store(&flush_threshold, MIN_FLUSH_THRESHOLD);
#else
        atomic_store(&flush_threshold, THRESHOLD_NOT_AUTOSCALER);
#endif // AUTOSCALE_FLUSH_THRESHOLD

        atomic_store(&n_msg_sent, 0);
        flush_threshold_set_time = 0;

        time_last_recv = 0;
        n_recv_msg = 0;

        fulsh_index ^= fulsh_index; // reset the flush index

        atomic_store(&is_flush_thread_running, FALSE);
    }

    void RdmaContext::destroy()
    {
        if (conn)
        {
            rdma_destroy_qp(conn);
            rdma_destroy_id(conn);
        }
        if (send_cq)
            ibv_destroy_cq(send_cq);
        if (recv_cq)
            ibv_destroy_cq(recv_cq);
        if (mr)
            ibv_dereg_mr(mr);
        if (pd)
            ibv_dealloc_pd(pd);
        if (buffer)
            free(buffer);
        if (client_ec)
            rdma_destroy_event_channel(client_ec);
        if (comp_channel)
            ibv_destroy_comp_channel(comp_channel);

        conn = NULL;
        pd = NULL;
        mr = NULL;
        remote_ip = 0;
        remote_addr = 0;
        remote_rkey = 0;
        buffer = NULL;
        buffer_size = 0;
    }

    // NOTIFICATIONS

    void RdmaContext::rdma_send_notification(CommunicationCode code)
    {
        notification_t *notification = (notification_t *)buffer;

        if (is_server == TRUE)
            notification->from_server.code = code;
        else
            notification->from_client.code = code;

        // Fill ibv_sge structure
        struct ibv_sge sge = {
            .addr = (uintptr_t)buffer, // address of the buffer
            .length = sizeof(notification_t),
            .lkey = mr->lkey // Local key from registered memory region
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
        if (ibv_post_send(conn->qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
            throw runtime_error("Failed to post send - rdma_send_notification");

        // Poll the completion queue
        rdma_poll_cq_send();

#ifdef RDMA_DEBUG_SR
        if (is_server == TRUE)
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
    }

    void RdmaContext::rdma_send_data_ready()
    {
        rdma_send_notification(CommunicationCode::RDMA_DATA_READY);
    }

    // WRITE

    void RdmaContext::rdma_post_write_(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, int signaled)
    {
        struct ibv_send_wr send_wr_data = {};
        struct ibv_sge sge_data;

        // Fill ibv_sge with local buffer
        sge_data.addr = local_addr;      // Local address of the buffer
        sge_data.length = size_to_write; // Length of the buffer
        sge_data.lkey = mr->lkey;

        // Prepare ibv_send_wr with IBV_WR_RDMA_WRITE
        send_wr_data.opcode = IBV_WR_RDMA_WRITE;
        send_wr_data.wr.rdma.remote_addr = remote_addr;
        send_wr_data.wr.rdma.rkey = remote_rkey;
        send_wr_data.sg_list = &sge_data;
        send_wr_data.num_sge = 1;
        if (signaled == TRUE)
            send_wr_data.send_flags = IBV_SEND_SIGNALED;

        // Post send in SQ with ibv_post_send
        struct ibv_send_wr *bad_send_wr_data;
        int ret = ibv_post_send(conn->qp, &send_wr_data, &bad_send_wr_data);
        if (ret != 0) // Post the send work request
        {
            cerr << "Failed to post write - rdma_post_write: " << strerror(errno) << endl;
            cerr << "Error code: " << ret << endl;
            throw runtime_error("Failed to post write - rdma_post_write");
        }

        // Poll the completion queue
        if (signaled == TRUE)
            rdma_poll_cq_send();
    }

    void RdmaContext::rdma_flush_buffer(rdma_ringbuffer_t *ringbuffer, uint32_t start_idx, uint32_t end_idx)
    {
        if (!ringbuffer)
            throw runtime_error("ringbuffer is NULL - rdma_flush_buffer");

        uint32_t w_idx = RING_IDX(end_idx);   // local write index
        uint32_t r_idx = RING_IDX(start_idx); // remote read index

        if (r_idx > w_idx)
        {
            // wrap-around
            uintptr_t batch_start = (uintptr_t)&ringbuffer->data[r_idx];
            size_t batch_size = (MAX_MSG_BUFFER - r_idx) * sizeof(rdma_msg_t);

            uintptr_t remote_addr = remote_addr + ((uintptr_t)batch_start - (uintptr_t)buffer);

            rdma_post_write_(remote_addr, batch_start, batch_size, TRUE);

            batch_start = (uintptr_t)&ringbuffer->data[0];
            batch_size = w_idx * sizeof(rdma_msg_t);

            remote_addr = remote_addr + ((uintptr_t)batch_start - (uintptr_t)buffer);

            rdma_post_write_(remote_addr, batch_start, batch_size, TRUE);
        }
        else
        {
            // normal case
            uintptr_t batch_start = (uintptr_t)&ringbuffer->data[r_idx];
            size_t batch_size = (w_idx - r_idx) * sizeof(rdma_msg_t);

            uintptr_t remote_addr = remote_addr + ((uintptr_t)batch_start - (uintptr_t)buffer);

            rdma_post_write_(remote_addr, batch_start, batch_size, TRUE);
        }

        // calculate the offset
        size_t write_index_offset = (size_t)((char *)ringbuffer - (char *)buffer) +
                                    offsetof(rdma_ringbuffer_t, remote_write_index);

        uintptr_t remote_addr_write_index = remote_addr + write_index_offset;

        rdma_ringbuffer_t *peer_rb = (is_server == TRUE) ? ringbuffer_client : ringbuffer_server;

        // Critical region to update the write index using C++ std::mutex and std::condition_variable
        std::unique_lock<std::mutex> lock(mtx_commit_flush);
        // Wait until the previous flush is committed
        cond_commit_flush.wait(lock, [&]()
                               { return atomic_load(&ringbuffer->remote_write_index) == start_idx; });

        // Update the write index
        atomic_store(&ringbuffer->remote_write_index, end_idx);

        rdma_post_write_(remote_addr_write_index,
                         (uintptr_t)(buffer + write_index_offset),
                         sizeof(ringbuffer->remote_write_index), TRUE);

        auto flags = peer_rb->flags.flags.load(std::memory_order_acquire);

        if ((flags & static_cast<unsigned int>(RingBufferFlag::RING_BUFFER_POLLING)) == 0)
            rdma_send_data_ready();

        cond_commit_flush.notify_all();
        // std::unique_lock will automatically unlock mtx_commit_flush when it goes out of scope
    }

    int RdmaContext::rdma_write_msg(int src_fd, struct sock_id original_socket)
    {
        rdma_ringbuffer_t *ringbuffer = (is_server == TRUE) ? ringbuffer_server : ringbuffer_client;

        if (!ringbuffer)
            throw runtime_error("ringbuffer is NULL - rdma_write_msg");

        uint32_t start_w_index, end_w_index, available_space;

        while (1)
        { // wait until there is enough space in the ringbuffer
            int c = 0;
            while (1)
            {
                start_w_index = atomic_load(&ringbuffer->local_write_index);
                end_w_index = atomic_load(&ringbuffer->remote_read_index);

                uint32_t used = start_w_index - end_w_index; // wrap-around safe
                available_space = MAX_MSG_BUFFER - used - 1;

                if (available_space >= 1)
                    break;

                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = (TIME_TO_WAIT_IF_NO_SPACE_MS) * 1000000; // ms -> ns
                nanosleep(&ts, NULL);
                COUNT++;

                if (COUNT % 100 == 0)
                {
                    printf("No space in the ringbuffer, waiting... %d - %d\n", COUNT, c);
                    c++;
                }
            }

            // modulo the indexes
            start_w_index = RING_IDX(start_w_index);
            end_w_index = RING_IDX(end_w_index);

            rdma_msg_t *msg = &ringbuffer->data[start_w_index];

            msg->msg_size = recv(src_fd, msg->msg, MAX_PAYLOAD_SIZE, 0);
            if ((int)msg->msg_size <= 0)
                return msg->msg_size;

            msg->msg_flags = 0;
            msg->original_sk_id = original_socket;
            msg->number_of_slots = 1;

            atomic_fetch_add(&n_msg_sent, 1);
            atomic_fetch_add(&ringbuffer->local_write_index, 1);
        }

        return 1;
    }

    void RdmaContext::rdma_parse_msg(bpf::BpfMng *bpf_ctx, sk::client_sk_t *client_sks, rdma_msg_t *msg)
    {
        // retrive the proxy_fd
        int fd;
        try
        {
            int fd = sockid_to_fd_map.at(msg->original_sk_id);
        }
        catch (const std::exception &e)
        {
            // loockup the original socket
            // swap the ip and port
            struct sock_id swapped;
            swapped.dip = msg->original_sk_id.sip;
            swapped.sip = msg->original_sk_id.dip;
            swapped.dport = msg->original_sk_id.sport;
            swapped.sport = msg->original_sk_id.dport;

            // find the corresponding proxy socket
            struct sock_id proxy_sk_id = bpf_ctx->get_proxy_sk_from_app_sk(swapped);

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
                    // update the map with the new socket
                    sockid_to_fd_map[msg->original_sk_id] = client_sks[i].fd;
                    fd = client_sks[i].fd;
                    break;
                }
            }

            if (i == NUMBER_OF_SOCKETS)
            {
                printf("Socket not found in the list: %u:%u -> %u:%u\n",
                       msg->original_sk_id.sip, msg->original_sk_id.sport,
                       msg->original_sk_id.dip, msg->original_sk_id.dport);
            }
        }

        send(fd, msg->msg, msg->msg_size, 0);
    }

    void RdmaContext::rdma_update_remote_read_idx(rdma_ringbuffer_t *ringbuffer, uint32_t r_idx)
    {
        // COMMIT the read index
        atomic_store(&ringbuffer->remote_read_index, r_idx);

        size_t read_index_offset = (size_t)((char *)ringbuffer - (char *)buffer) +
                                   offsetof(rdma_ringbuffer_t, remote_read_index);

        uintptr_t remote_addr_read_index = remote_addr + read_index_offset;

        rdma_post_write_(remote_addr_read_index,
                         (uintptr_t)(buffer + read_index_offset),
                         sizeof(ringbuffer->remote_read_index),
                         TRUE);
    }

    void RdmaContext::rdma_read_msg(bpf::BpfMng *bpf_ctx, sk::client_sk_t *client_sks, uint32_t start_read_index, uint32_t end_read_index)
    {
        rdma_ringbuffer_t *ringbuffer = is_server ? ringbuffer_client : ringbuffer_server;

        if (!ringbuffer)
            throw runtime_error("ringbuffer is NULL - rdma_read_msg");

        if (start_read_index == end_read_index)
        {
            // nothing to read
            return;
        }

        uint32_t number_of_msg = (end_read_index + MAX_MSG_BUFFER - start_read_index) % MAX_MSG_BUFFER;

        start_read_index = RING_IDX(start_read_index);
        end_read_index = RING_IDX(end_read_index);

        u_int32_t n = 0;
        for (int i = 0; i < number_of_msg;)
        {
            int idx = RING_IDX(start_read_index + i);
            rdma_msg_t *msg = &ringbuffer->data[idx];
            rdma_parse_msg(bpf_ctx, client_sks, msg);
            i += msg->number_of_slots;
        }
    }

    // UTILS

    void RdmaContext::rdma_set_polling_status(uint32_t is_polling)
    {
        rdma_ringbuffer_t *ringbuffer = (is_server == TRUE) ? ringbuffer_server : ringbuffer_client;
        unsigned int f = atomic_load(&ringbuffer->flags.flags);

        // is polling?
        if (f & static_cast<unsigned int>(RingBufferFlag::RING_BUFFER_POLLING) == is_polling)
            return;

        unsigned int expected = f;
        unsigned int desired;

        uint32_t expected = ringbuffer->flags.flags.load(std::memory_order_relaxed);
        uint32_t desired;

        do
        {
            desired = expected ^ static_cast<uint32_t>(RingBufferFlag::RING_BUFFER_POLLING); // toggle bit
            desired |= static_cast<uint32_t>(RingBufferFlag::RING_BUFFER_CAN_POLLING);       // set bit
        } while (!ringbuffer->flags.flags.compare_exchange_weak(
            expected,                  // -- on success this becomes the old value
            desired,                   // -- the new value you want to write
            std::memory_order_acq_rel, // success order
            std::memory_order_relaxed)); // failure order

        // update the polling status on the remote side
        size_t offset = (size_t)((char *)ringbuffer - (char *)buffer);
        uintptr_t remote_addr = remote_addr + offset;

        rdma_post_write_(remote_addr,
                         (uintptr_t)(buffer + offset),
                         sizeof(ringbuffer->flags.flags),
                         TRUE);

        cout << "Polling status updated: " << (is_polling ? "ON" : "OFF") << endl;
    }

    void RdmaContext::rdma_poll_cq_send()
    {
        if (send_cq == NULL)
            throw runtime_error("send_cq is NULL - rdma_poll_cq_send");

        struct ibv_wc wc;
        int num_completions;
        do
        {
            num_completions = ibv_poll_cq(send_cq, 1, &wc);
        } while (num_completions == 0); // poll until we get a completion

        if (num_completions < 0)
        {
            fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
            throw runtime_error("Failed to poll CQ - rdma_poll_cq_send");
        }

        if (wc.status != IBV_WC_SUCCESS)
        {
            fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
            throw runtime_error("Failed to poll CQ - rdma_poll_cq_send");
        }
    }

    const string get_op_name(CommunicationCode code)
    {
        switch (code)
        {
        case CommunicationCode::RDMA_DATA_READY:
            return "RDMA_DATA_READY";
        case CommunicationCode::EXCHANGE_REMOTE_INFO:
            return "EXCHANGE_REMOTE_INFO";
        case CommunicationCode::RDMA_CLOSE_CONTEXT:
            return "RDMA_CLOSE_CONTEXT";
        case CommunicationCode::NONE:
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

}