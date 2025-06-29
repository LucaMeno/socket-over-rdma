
#include <RdmaContext.h>

using namespace std;

namespace rdma
{
    int COUNT = 0; // for debugging

    // CLIENT - SERVER

    conn_info RdmaContext::rdmaSetupPreHs()
    {
        srand48(getpid());

        ctx = open_device();
        if (!ctx)
            throw runtime_error("Failed to open RDMA device: " + string(strerror(errno)));

        pd = ibv_alloc_pd(ctx);
        if (!pd)
            throw runtime_error("Failed to allocate protection domain");

        send_cq = ibv_create_cq(ctx, 16, nullptr, nullptr, 0);
        if (!send_cq)
            throw runtime_error("Failed to create send CQ");

        recv_cq = ibv_create_cq(ctx, 16, nullptr, nullptr, 0);
        if (!recv_cq)
            throw runtime_error("Failed to create receive CQ");

        buffer = (char *)aligned_alloc(4096, MR_SIZE);
        if (!buffer)
            throw runtime_error("Failed to allocate buffer");

        memset(buffer, 0, MR_SIZE);

        mr = ibv_reg_mr(pd, buffer, MR_SIZE,
                        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
        if (!mr)
            throw runtime_error("Failed to register memory region");

        ibv_qp_init_attr qpa = {};
        qpa.send_cq = send_cq;
        qpa.recv_cq = recv_cq;
        qpa.qp_type = IBV_QPT_RC;
        qpa.cap = {
            .max_send_wr = 16,
            .max_recv_wr = 16,
            .max_send_sge = 1,
            .max_recv_sge = 1};

        qp = ibv_create_qp(pd, &qpa);
        if (!qp)
            throw runtime_error("Failed to create QP");

        ibv_qp_attr attr = {};
        attr.qp_state = IBV_QPS_INIT;
        attr.pkey_index = 0;
        attr.port_num = 1;
        attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE;

        int err = ibv_modify_qp(qp, &attr,
                                IBV_QP_STATE | IBV_QP_PKEY_INDEX |
                                    IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);

        if (err)
            throw runtime_error("Failed to modify QP to INIT state");

        ibv_port_attr pattr;
        ibv_query_port(ctx, 1, &pattr);

        union ibv_gid gid;
        err = ibv_query_gid(ctx, 1, 0, &gid);
        if (err)
            throw runtime_error("ibv_query_gid failed");

        conn_info local = {};
        local.lid = pattr.lid;
        local.qp_num = qp->qp_num;
        local.psn = gen_psn();
        local.rkey = mr->rkey;
        local.addr = reinterpret_cast<uintptr_t>(buffer);
        local.gid = gid;

        std::cout << "Local connection info:\n"
                  << "LID: " << local.lid << "\n"
                  << "QP number: " << local.qp_num << "\n"
                  << "PSN: " << local.psn << "\n"
                  << "RKEY: " << local.rkey << "\nGID: ";

        for (int i = 0; i < 16; i++)
            std::printf("%02x", local.gid.raw[i]);
        std::printf("\nBuffer address: 0x%lx\n", local.addr);

        return local;
    }

    void RdmaContext::rdmaSetupPostHs(conn_info remote)
    {
        remote_addr = remote.addr;
        remote_rkey = remote.rkey;

        std::cout << "Remote QPN: " << remote.qp_num << "\n"
                  << "Remote PSN: " << remote.psn << "\n"
                  << "Remote LID: " << remote.lid << "\n"
                  << "Remote GID: "
                  << std::hex << int(remote.gid.raw[0]) << ":"
                  << int(remote.gid.raw[1]) << std::dec << "\n"
                  << "Remote address: 0x" << std::hex << remote.addr << std::dec << "\n"
                  << "Remote rkey: " << remote.rkey << "\n";

        ibv_qp_attr rtr = {};
        rtr.qp_state = IBV_QPS_RTR;
        rtr.path_mtu = IBV_MTU_1024;
        rtr.dest_qp_num = remote.qp_num;
        rtr.rq_psn = remote.psn;
        rtr.max_dest_rd_atomic = 1;
        rtr.min_rnr_timer = 12;
        memset(&rtr.ah_attr, 0, sizeof(rtr.ah_attr));
        rtr.ah_attr.is_global = 1;
        rtr.ah_attr.port_num = 1;
        rtr.ah_attr.dlid = 0;
        rtr.ah_attr.grh.dgid = remote.gid;
        rtr.ah_attr.grh.sgid_index = 0;
        rtr.ah_attr.grh.hop_limit = 1;

        int err = ibv_modify_qp(qp, &rtr,
                                IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                                    IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                                    IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);

        if (err)
            throw runtime_error("Failed to modify QP to RTR state");

        ibv_qp_attr rts = {};
        rts.qp_state = IBV_QPS_RTS;
        rts.sq_psn = local.psn;
        rts.timeout = 14;
        rts.retry_cnt = 7;
        rts.rnr_retry = 7;
        rts.max_rd_atomic = 1;

        err = ibv_modify_qp(qp, &rts,
                            IBV_QP_STATE |
                                IBV_QP_TIMEOUT |
                                IBV_QP_RETRY_CNT |
                                IBV_QP_RNR_RETRY |
                                IBV_QP_SQ_PSN |
                                IBV_QP_MAX_QP_RD_ATOMIC);

        if (err)
            throw std::runtime_error("ibv_modify_qp failed");

        ibv_qp_attr attr2;
        ibv_qp_init_attr iattr = {};
        err = ibv_query_qp(qp, &attr2, IBV_QP_STATE, &iattr);
        if (err)
            throw std::runtime_error("ibv_query_qp failed");

        std::cout << "QP state after RTS = " << attr2.qp_state << "\n";
    }

    serverConnection_t RdmaContext::serverSetup()
    {
        // setup server side
        is_server = TRUE;

        conn_info local = rdmaSetupPreHs();

        int listen_fd = tcp_server_listen();
        std::cout << "Server ready\n";

        serverConnection_t sc;
        sc.fd = listen_fd;
        sc.conn_info_local = local;
        return sc;
    }

    void RdmaContext::serverHandleNewClient(serverConnection_t &sc)
    {
        int sock = accept(sc.fd, nullptr, nullptr);

        conn_info remote;
        conn_info local = sc.conn_info_local;
        if (write(sock, &local, sizeof(local)) < 0 || read(sock, &remote, sizeof(remote)) < 0)
        {
            perror("TCP exchange");
            close(sock);
            exit(EXIT_FAILURE);
        }
        close(sc.fd);

        std::cout << "Accepted new client connection\n";

        rdmaSetupPostHs(remote);

        unique_lock<mutex> lock(mtx_tx);
        atomic_store(is_ready, TRUE);
        cond_tx.notify_all();
        lock.unlock();
    }

    void RdmaContext::clientConnect(uint32_t server_ip, uint16_t server_port)
    {
        is_server = FALSE;

        conn_info local = rdmaSetupPreHs();

        int sock = tcp_connect(server_ip);
        if (sock < 0)
        {
            std::cerr << "Failed to connect to server: " << strerror(errno) << "\n";
            throw runtime_error("tcp_connect failed");
        }

        conn_info remote;
        if (read(sock, &remote, sizeof(remote)) < 0)
        {
            perror("read");
            close(sock);
            throw runtime_error("Failed to read remote connection info");
        }

        if (write(sock, &local, sizeof(local)) < 0)
        {
            perror("write");
            close(sock);
            throw runtime_error("Failed to write local connection info");
        }

        close(sock);

        cout << "Connected to server\n";

        rdmaSetupPostHs(remote);

        unique_lock<mutex> lock(mtx_tx);
        atomic_store(is_ready, TRUE);
        cond_tx.notify_all();
        lock.unlock();
    }

    int RdmaContext::tcp_connect(uint32_t ip)
    {
        // Convert IP address from uint32_t to string
        string ip_str;
        ip_str.resize(16); // Enough space for IPv6
        inet_ntop(AF_INET, &ip, &ip_str[0], ip_str.size());
        ip_str.resize(strlen(ip_str.c_str())); // Resize to actual length

        struct addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *res;

        if (getaddrinfo(ip_str.c_str(), TCP_PORT, &hints, &res) != 0)
        {
            perror("getaddrinfo");
            return -1;
        }

        int fd = socket(res->ai_family, res->ai_socktype, 0);
        if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0)
        {
            perror("connect");
            freeaddrinfo(res);
            return -1;
        }

        freeaddrinfo(res);
        return fd;
    }

    int RdmaContext::tcp_server_listen()
    {
        addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        addrinfo *res;
        getaddrinfo(nullptr, TCP_PORT, &hints, &res);

        int fd = socket(res->ai_family, res->ai_socktype, 0);
        bind(fd, res->ai_addr, res->ai_addrlen);
        listen(fd, 1);

        // Make it non-blocking
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        freeaddrinfo(res);
        return fd;
    }

    ibv_context *RdmaContext::open_device()
    {
        int num_devices = 0;
        ibv_device **device_list = ibv_get_device_list(&num_devices);
        if (!device_list || num_devices == 0)
        {
            std::cerr << "No RDMA devices found.\n";
            return nullptr;
        }

        for (int i = 0; i < num_devices; ++i)
        {
            std::cout << "Device " << i << ": " << ibv_get_device_name(device_list[i]) << "\n";
        }

        ibv_context *ctx = ibv_open_device(device_list[0]);
        ibv_free_device_list(device_list);
        return ctx;
    }

    uint32_t RdmaContext::gen_psn()
    {
        return lrand48() & 0xffffff;
    }

    // SETUP

    void RdmaContext::init()
    {
        atomic_store(&is_ready, FALSE);
        remote_ip = 0;
        buffer = NULL;
        pd = NULL;
        mr = NULL;
        recv_cq = NULL;
        send_cq = NULL;
        remote_rkey = 0;
        remote_addr = 0;

        ringbuffer_client = NULL;
        ringbuffer_server = NULL;

        last_flush_ms = 0;
        is_flushing = FALSE;

        atomic_store(&flush_threshold, THRESHOLD_NOT_AUTOSCALER);

        atomic_store(&n_msg_sent, 0);
        flush_threshold_set_time = 0;

        time_last_recv = 0;
        n_recv_msg = 0;

        fulsh_index ^= fulsh_index; // reset the flush index

        atomic_store(&is_flush_thread_running, FALSE);

        ringbuffer_server = (rdma_ringbuffer_t *)(buffer + NOTIFICATION_OFFSET_SIZE);
        atomic_store(ringbuffer_server->local_read_index, 0);
        atomic_store(ringbuffer_server->remote_read_index, 0);
        atomic_store(ringbuffer_server->remote_write_index, 0);
        atomic_store(ringbuffer_server->local_write_index, 0);
        atomic_store(ringbuffer_server->flags.flags, 0);

        ringbuffer_client = (rdma_ringbuffer_t *)(buffer + NOTIFICATION_OFFSET_SIZE + RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
        atomic_store(ringbuffer_client->local_read_index, 0);
        atomic_store(ringbuffer_client->remote_read_index, 0);
        atomic_store(ringbuffer_client->remote_write_index, 0);
        atomic_store(ringbuffer_client->local_write_index, 0);
        atomic_store(ringbuffer_client->flags.flags, 0);
    }

    void RdmaContext::destroy()
    {
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

        pd = NULL;
        mr = NULL;
        remote_ip = 0;
        remote_addr = 0;
        remote_rkey = 0;
        buffer = NULL;
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
        if (ibv_post_send(qp, &send_wr, &bad_send_wr) != 0) // Post the send work request
            throw runtime_error("Failed to post send - rdma_send_notification");

        // Poll the completion queue
        rdma_poll_cq_send();
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
        int ret = ibv_post_send(qp, &send_wr_data, &bad_send_wr_data);
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

    void RdmaContext::rdma_parse_msg(bpf::BpfMng &bpf_ctx, sk::client_sk_t *client_sks, rdma_msg_t *msg)
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
            struct sock_id proxy_sk_id = bpf_ctx.get_proxy_sk_from_app_sk(swapped);

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

    void RdmaContext::rdma_read_msg(bpf::BpfMng &bpf_ctx, sk::client_sk_t *client_sks, uint32_t start_read_index, uint32_t end_read_index)
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

    const string RdmaContext::get_op_name(CommunicationCode code)
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

    uint64_t RdmaContext::get_time_ms()
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
    }

    void RdmaContext::wait_for_context_ready()
    {
        std::unique_lock<std::mutex> lock(mtx_tx);
        cond_tx.wait(lock, [&]()
                     { return atomic_load(&is_ready) == TRUE; });
    }

}