
#include <RdmaContext.h>

using namespace std;

namespace rdma
{
    int COUNT = 0; // for debugging

    // CLIENT - SERVER

    conn_info RdmaContext::rdmaSetupPreHs()
    {
        srand48(getpid());

        ctx = openDevice();
        if (!ctx)
            throw runtime_error("Failed to open RDMA device: " + string(strerror(errno)));

        pd = ibv_alloc_pd(ctx);
        if (!pd)
            throw runtime_error("Failed to allocate protection domain");

        comp_channel = ibv_create_comp_channel(ctx);
        if (!comp_channel)
            throw runtime_error("Failed to create completion channel");

        // Create multiple send CQs for load balancing
        for (int i = 0; i < Config::QP_N; i++)
        {
            send_cqs[i] = ibv_create_cq(ctx, 16, nullptr, nullptr, 0);
            if (!send_cqs[i])
                throw runtime_error("Failed to create send CQ " + to_string(i));
        }

        // create receive CQ
        recv_cq = ibv_create_cq(ctx, 16, nullptr, comp_channel, 0);
        if (!recv_cq)
            throw runtime_error("Failed to create receive CQ");

        // Create a shared receive CQ
        struct ibv_srq_init_attr srq_attr = {
            .attr = {
                .max_wr = 1024,
                .max_sge = 1}};

        srq = ibv_create_srq(pd, &srq_attr);
        // srq = nullptr;
        if (!srq)
        {
            cerr << "WARNING: Failed to create shared receive queue, using default receive CQ\n";
            srq = nullptr; // Use default receive CQ if SRQ creation fails
        }

        if (ibv_req_notify_cq(recv_cq, 0))
            throw runtime_error("Failed to request notification on receive CQ");

        buffer = (char *)aligned_alloc(4096, MR_SIZE);
        if (!buffer)
            throw runtime_error("Failed to allocate buffer");

        memset(buffer, 0, MR_SIZE);

        mr = ibv_reg_mr(pd, buffer, MR_SIZE,
                        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
        if (!mr)
            throw runtime_error("Failed to register memory region");

        // Create QPs for the connection
        for (int i = 0; i < Config::QP_N; i++)
        {
            ibv_qp_init_attr qpa = {};
            qpa.send_cq = send_cqs[i];
            qpa.recv_cq = recv_cq;
            if (srq)
                qpa.srq = srq; // Use the shared receive CQ only if it was created successfully
            qpa.qp_type = IBV_QPT_RC;
            qpa.cap = {
                .max_send_wr = 16,
                .max_recv_wr = 16,
                .max_send_sge = 1,
                .max_recv_sge = 1};

            qps[i] = ibv_create_qp(pd, &qpa);
            if (!qps[i])
                throw runtime_error("Failed to create QP " + to_string(i));

            ibv_qp_attr attr = {};
            attr.qp_state = IBV_QPS_INIT;
            attr.pkey_index = 0;
            attr.port_num = 1;
            attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE;

            int err = ibv_modify_qp(qps[i], &attr,
                                    IBV_QP_STATE | IBV_QP_PKEY_INDEX |
                                        IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
            if (err)
                throw runtime_error("Failed to modify QP to INIT state");
        }

        ibv_port_attr pattr;
        ibv_query_port(ctx, 1, &pattr);

        union ibv_gid gid;
        int err = ibv_query_gid(ctx, 1, Config::getRdmaDevGidIdx(), &gid);
        if (err)
            throw runtime_error("ibv_query_gid failed");

        conn_info local = {};
        local.lid = pattr.lid;
        local.rkey = mr->rkey;
        local.addr = reinterpret_cast<uintptr_t>(buffer);
        local.gid = gid;
        for (int i = 0; i < Config::QP_N; i++)
        {
            local.qp_num[i] = qps[i]->qp_num;
            local.rq_psn[i] = getPsn();
        }

        return local;
    }

    void RdmaContext::rdmaSetupPostHs(conn_info remote, conn_info local)
    {
        remote_addr = remote.addr;
        remote_rkey = remote.rkey;

        cout << " ==================== CONNECTION INFO ====================\n";

        cout << "## LOCAL ##" << endl;
        std::cout << "Local QPN and PSN: " << endl;
        for (int i = 0; i < Config::QP_N; i++)
            std::cout << "- QPN[" << i << "]: " << local.qp_num[i] << " PSN: " << local.rq_psn[i] << "\n";
        cout << "Local LID: " << local.lid << "\n"
             << "Local BUFFER: " << std::hex << local.addr << std::dec << "\n"
             << "Local RKEY: " << local.rkey << "\n"
             << "Local GID: ";
        for (int i = 0; i < 16; i++)
            std::printf("%02x", local.gid.raw[i]);

        std::cout << endl
                  << endl
                  << "## REMOTE ##" << endl;

        cout << "Remote QPN and PSN: " << endl;
        for (int i = 0; i < Config::QP_N; i++)
            std::cout << "- QPN[" << i << "]: " << remote.qp_num[i] << " PSN: " << remote.rq_psn[i] << "\n";
        cout << "Remote LID: " << remote.lid << "\n"
             << "Remote BUFFER: " << std::hex << remote.addr << std::dec << "\n"
             << "Remote RKEY: " << remote.rkey << "\n"
             << "Remote GID: ";
        for (int i = 0; i < 16; i++)
            std::printf("%02x", remote.gid.raw[i]);

        std::cout << endl
                  << endl
                  << "## DEVICES ##" << endl;
        showDevices();

        std::cout << "\n ==========================================================\n";

        for (int i = 0; i < Config::QP_N; i++)
        {
            ibv_qp_attr rtr = {};
            rtr.qp_state = IBV_QPS_RTR;
            rtr.path_mtu = IBV_MTU_1024;
            rtr.dest_qp_num = remote.qp_num[i];
            rtr.rq_psn = remote.rq_psn[i];
            rtr.max_dest_rd_atomic = 1;
            rtr.min_rnr_timer = 12;
            memset(&rtr.ah_attr, 0, sizeof(rtr.ah_attr));
            rtr.ah_attr.is_global = 1;
            rtr.ah_attr.port_num = 1;
            rtr.ah_attr.dlid = 0;
            rtr.ah_attr.grh.dgid = remote.gid;
            rtr.ah_attr.grh.sgid_index = Config::getRdmaDevGidIdx();
            rtr.ah_attr.grh.hop_limit = 1;

            int err = ibv_modify_qp(qps[i], &rtr,
                                    IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                                        IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                                        IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);

            if (err)
                throw runtime_error("Failed to modify QP to RTR state");

            ibv_qp_attr rts = {};
            rts.qp_state = IBV_QPS_RTS;
            rts.sq_psn = local.rq_psn[i];
            rts.timeout = 14;
            rts.retry_cnt = 7;
            rts.rnr_retry = 7;
            rts.max_rd_atomic = 1;

            err = ibv_modify_qp(qps[i], &rts,
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
            err = ibv_query_qp(qps[i], &attr2, IBV_QP_STATE, &iattr);
            if (err)
                throw std::runtime_error("ibv_query_qp failed");

            if (attr2.qp_state != IBV_QPS_RTS)
                throw std::runtime_error("QP is not in RTS state after modification");
        }

        ringbuffer_server = (rdma_ringbuffer_t *)(buffer + NOTIFICATION_OFFSET_SIZE);
        ringbuffer_server->local_read_index.store(0);
        ringbuffer_server->remote_read_index.store(0);
        ringbuffer_server->remote_write_index.store(0);
        ringbuffer_server->local_write_index.store(0);
        ringbuffer_server->flags.flags.store(0);

        ringbuffer_client = (rdma_ringbuffer_t *)(buffer + NOTIFICATION_OFFSET_SIZE + RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
        ringbuffer_client->local_read_index.store(0);
        ringbuffer_client->remote_read_index.store(0);
        ringbuffer_client->remote_write_index.store(0);
        ringbuffer_client->local_write_index.store(0);
        ringbuffer_client->flags.flags.store(0);

        // Post the initial receive work request to receive the notification
        struct ibv_sge sge;
        sge.addr = (uintptr_t)buffer;
        sge.length = sizeof(notification_t);
        sge.lkey = mr->lkey;

        struct ibv_recv_wr recv_wr;
        recv_wr.wr_id = 0;
        recv_wr.sg_list = &sge;
        recv_wr.num_sge = 1;
        recv_wr.next = nullptr;

        struct ibv_recv_wr *bad_wr = nullptr;
        if (srq)
        {
            if (ibv_post_srq_recv(srq, &recv_wr, &bad_wr) != 0 || bad_wr)
                throw std::runtime_error("Failed to post initial receive work request in SRQ");
        }
        else
        {
            for (int i = 0; i < Config::QP_N; ++i)
                if (ibv_post_recv(qps[i], &recv_wr, &bad_wr) != 0 || bad_wr)
                    throw std::runtime_error("Failed to post initial receive work request to QP " + std::to_string(i));
        }
    }

    serverConnection_t RdmaContext::serverSetup()
    {
        // setup server side
        is_server = true;

        conn_info local = rdmaSetupPreHs();

        int listen_fd = tcpWaitForConnection();
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
            throw runtime_error("Failed to exchange connection info");

        // extract the remote IP address
        sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        if (getpeername(sock, (struct sockaddr *)&addr, &addr_len) < 0)
            throw runtime_error("getpeername failed");
        remote_ip = addr.sin_addr.s_addr;
        close(sc.fd);

        std::cout << "Accepted new client connection\n";

        rdmaSetupPostHs(remote, local);

        unique_lock<mutex> lock(mtx_tx);
        is_ready.store(true, std::memory_order_release);
        cond_tx.notify_all();
        lock.unlock();
    }

    void RdmaContext::clientConnect(uint32_t server_ip, uint16_t server_port)
    {
        is_server = false;

        conn_info local = rdmaSetupPreHs();

        int sock = tcpConnect(server_ip);
        if (sock < 0)
        {
            std::cerr << "Failed to connect to server: " << strerror(errno) << "\n";
            throw runtime_error("tcpConnect failed");
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

        rdmaSetupPostHs(remote, local);

        unique_lock<mutex> lock(mtx_tx);
        is_ready.store(true);
        cond_tx.notify_all();
        lock.unlock();
    }

    int RdmaContext::tcpConnect(uint32_t ip)
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

        if (getaddrinfo(ip_str.c_str(), Config::RDMA_TCP_PORT, &hints, &res) != 0)
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

    int RdmaContext::tcpWaitForConnection()
    {
        addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        addrinfo *res;
        getaddrinfo(nullptr, Config::RDMA_TCP_PORT, &hints, &res);

        int fd = socket(res->ai_family, res->ai_socktype, 0);
        bind(fd, res->ai_addr, res->ai_addrlen);
        listen(fd, 1);

        // Make it non-blocking
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        freeaddrinfo(res);
        return fd;
    }

    void RdmaContext::showDevices()
    {
        int num_devices = 0;
        ibv_device **device_list = ibv_get_device_list(&num_devices);
        if (!device_list || num_devices == 0)
            std::cerr << "No RDMA devices found.\n";

        for (int i = 0; i < num_devices; ++i)
        {
            ibv_context *ctx = ibv_open_device(device_list[i]);
            if (!ctx)
                continue;

            ibv_port_attr port_attr;
            if (ibv_query_port(ctx, Config::RDMA_DEV_PORT, &port_attr) == 0)
            {
                if (port_attr.state == IBV_PORT_ACTIVE)
                    std::cout << "[" << i << "] device UP: " << ibv_get_device_name(device_list[i]) << "\n";
                else
                    std::cout << "[" << i << "] device DOWN: " << ibv_get_device_name(device_list[i]) << "\n";
            }

            ibv_close_device(ctx);
        }
        cout << "Target RDMA device index: " << Config::getDevIdx() << " - GID: " << Config::getRdmaDevGidIdx() << "\n";
        ibv_free_device_list(device_list);
    }

    ibv_context *RdmaContext::openDevice()
    {
        int num_devices = 0;
        ibv_device **device_list = ibv_get_device_list(&num_devices);
        if (!device_list || num_devices == 0)
        {
            std::cerr << "No RDMA devices found.\n";
            return nullptr;
        }

        std::vector<bool> active_devices;
        int active_count = 0;

        for (int i = 0; i < num_devices; ++i)
        {
            ibv_context *ctx = ibv_open_device(device_list[i]);
            if (!ctx)
                continue;

            ibv_port_attr port_attr;
            if (ibv_query_port(ctx, Config::RDMA_DEV_PORT, &port_attr) == 0)
            {
                if (port_attr.state == IBV_PORT_ACTIVE)
                {
                    active_devices.push_back(true);
                    active_count++;
                }
                else
                {
                    active_devices.push_back(false);
                }
            }

            ibv_close_device(ctx);
        }

        if (active_count == 0)
        {
            std::cerr << "No active RDMA devices found.\n";
            ibv_free_device_list(device_list);
            return nullptr;
        }

        int devIndex = Config::getDevIdx();
        if (devIndex >= active_devices.size())
        {
            std::cerr << "Invalid device index (only " << active_devices.size() << " active devices available).\n";
            ibv_free_device_list(device_list);
            throw std::runtime_error("Invalid device index");
        }

        if (!active_devices[devIndex])
        {
            std::cerr << "Selected device is not active, trying to use the first active device...\n";
            for (int i = 0; i < active_devices.size(); ++i)
            {
                if (active_devices[i])
                {
                    devIndex = i;
                    break;
                }
            }
        }

        ibv_context *ctx = ibv_open_device(device_list[devIndex]);
        if (!ctx)
        {
            std::cerr << "Failed to open selected RDMA device.\n";
            ibv_free_device_list(device_list);
            return nullptr;
        }

        ibv_free_device_list(device_list);
        return ctx;
    }

    uint32_t RdmaContext::getPsn()
    {
        return lrand48() & 0xffffff;
    }

    // SETUP

    RdmaContext::RdmaContext()
    {
        is_ready.store(false);
        stop.store(false);
        flush_threshold.store(Config::THRESHOLD_NOT_AUTOSCALER);
        n_msg_sent.store(0);
        buffer = nullptr;
        pd = nullptr;
        mr = nullptr;
        recv_cq = nullptr;
        comp_channel = nullptr;
        for (int i = 0; i < Config::QP_N; i++)
        {
            send_cqs[i] = nullptr;
            qps[i] = nullptr;
        }
        srq = nullptr;
        ringbuffer_client = nullptr;
        ringbuffer_server = nullptr;
        remote_rkey = 0;
        remote_addr = 0;
        last_flush_ms = 0;
        remote_ip = 0;
        send_q_index = 0;
    }

    RdmaContext::~RdmaContext()
    {
        is_ready.store(false);

        for (int i = 0; i < Config::QP_N; i++)
        {
            if (send_cqs[i])
                ibv_destroy_cq(send_cqs[i]);
            if (qps[i])
                ibv_destroy_qp(qps[i]);
        }

        if (srq)
            ibv_destroy_srq(srq);
        if (mr)
            ibv_dereg_mr(mr);
        if (pd)
            ibv_dealloc_pd(pd);
        if (buffer)
            free(buffer);
        if (comp_channel)
            ibv_destroy_comp_channel(comp_channel);

        pd = nullptr;
        mr = nullptr;
        buffer = nullptr;
        remote_ip = 0;
        remote_addr = 0;
        remote_rkey = 0;
    }

    // NOTIFICATIONS

    void RdmaContext::sendNotification(CommunicationCode code)
    {
        notification_t *notification = (notification_t *)buffer;

        if (is_server == true)
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
        send_wr.next = nullptr;

        // Post send with ibv_post_send
        uint32_t qp_index = getNextSendQIndex(); // Get the next QP index for round-robin load balancing

        struct ibv_send_wr *bad_send_wr;
        if (ibv_post_send(qps[qp_index], &send_wr, &bad_send_wr) != 0) // Post the send work request
            throw runtime_error("Failed to post send - sendNotification");

        // Poll the completion queue
        pollCqSend(send_cqs[qp_index]);
        cout << "Sent notification: " << getOpName(code) << endl;
    }

    void RdmaContext::sendDataReady()
    {
        sendNotification(CommunicationCode::RDMA_DATA_READY);
        last_notification_data_ready_ns = getTimeMS();
    }

    // WRITE

    void RdmaContext::postWriteOp(uintptr_t remote_addr_2, uintptr_t local_addr, size_t size_to_write, bool signaled)
    {
        struct ibv_send_wr send_wr_data = {};
        struct ibv_sge sge_data;

        // Fill ibv_sge with local buffer
        sge_data.addr = local_addr;      // Local address of the buffer
        sge_data.length = size_to_write; // Length of the buffer
        sge_data.lkey = mr->lkey;

        // Prepare ibv_send_wr with IBV_WR_RDMA_WRITE
        send_wr_data.opcode = IBV_WR_RDMA_WRITE;
        send_wr_data.wr.rdma.remote_addr = remote_addr_2;
        send_wr_data.wr.rdma.rkey = remote_rkey;
        send_wr_data.sg_list = &sge_data;
        send_wr_data.num_sge = 1;
        if (signaled == true)
            send_wr_data.send_flags = IBV_SEND_SIGNALED;

        // Post send in SQ with ibv_post_send
        uint32_t qp_index = getNextSendQIndex(); // Get the next QP index for round-robin load balancing

        struct ibv_send_wr *bad_send_wr_data;
        int ret = ibv_post_send(qps[qp_index], &send_wr_data, &bad_send_wr_data);
        if (ret != 0) // Post the send work request
        {
            cerr << "Failed to post write - rdma_post_write: " << strerror(errno) << endl;
            cerr << "Error code: " << ret << endl;
            throw runtime_error("Failed to post write - rdma_post_write");
        }

        // Poll the completion queue
        if (signaled == true)
            pollCqSend(send_cqs[qp_index]);
    }

    void RdmaContext::flushRingbuffer(rdma_ringbuffer_t &ringbuffer, uint32_t start_idx, uint32_t end_idx)
    {
        uint32_t w_idx = RING_IDX(end_idx);   // local write index
        uint32_t r_idx = RING_IDX(start_idx); // remote read index

        // cout << "F: " << end_idx - start_idx << endl;

        if (r_idx > w_idx)
        {
            // wrap-around
            uintptr_t batch_start = (uintptr_t)&ringbuffer.data[r_idx];
            size_t batch_size = (Config::MAX_MSG_BUFFER - r_idx) * sizeof(rdma_msg_t);

            uintptr_t remote_addr_2 = remote_addr + ((uintptr_t)batch_start - (uintptr_t)buffer);

            postWriteOp(remote_addr_2, batch_start, batch_size, true);

            batch_start = (uintptr_t)&ringbuffer.data[0];
            batch_size = w_idx * sizeof(rdma_msg_t);

            remote_addr_2 = remote_addr + ((uintptr_t)batch_start - (uintptr_t)buffer);

            postWriteOp(remote_addr_2, batch_start, batch_size, true);
        }
        else
        {
            // normal case
            uintptr_t batch_start = (uintptr_t)&ringbuffer.data[r_idx];
            size_t batch_size = (w_idx - r_idx) * sizeof(rdma_msg_t);

            uintptr_t remote_addr_2 = remote_addr + ((uintptr_t)batch_start - (uintptr_t)buffer);

            postWriteOp(remote_addr_2, batch_start, batch_size, true);
        }

        // calculate the offset
        size_t write_index_offset = (size_t)(reinterpret_cast<const char *>(&ringbuffer) - (char *)buffer) +
                                    offsetof(rdma_ringbuffer_t, remote_write_index);

        uintptr_t remote_addr_write_index = remote_addr + write_index_offset;

        rdma_ringbuffer_t *peer_rb = (is_server == true) ? ringbuffer_client : ringbuffer_server;

        // Critical region to update the write index using C++ std::mutex and std::condition_variable
        std::unique_lock<std::mutex> lock(mtx_commit_flush);
        // Wait until the previous flush is committed
        cond_commit_flush.wait(lock, [&]()
                               { return ringbuffer.remote_write_index.load() == start_idx; });

        // Update the write index
        ringbuffer.remote_write_index.store(end_idx);

        postWriteOp(remote_addr_write_index,
                    (uintptr_t)(buffer + write_index_offset),
                    sizeof(ringbuffer.remote_write_index), true);

        auto flags = peer_rb->flags.flags.load(std::memory_order_acquire);

        if ((flags & static_cast<unsigned int>(RingBufferFlag::RING_BUFFER_POLLING)) == 0)
        {
            if (last_notification_data_ready_ns == 0 ||
                (getTimeMS() - last_notification_data_ready_ns) >= Config::TIME_BTW_DATA_READY_NOTIFICATIONS_MS)
            {
                // If the last notification was sent more than Config::TIME_BTW_DATA_READY_NOTIFICATIONS_MS ago
                sendDataReady();
            }
        }

        cond_commit_flush.notify_all();
        // cout << "Flush completed: in = " << in << ", out = " << out << endl;
        //  std::unique_lock will automatically unlock mtx_commit_flush when it goes out of scope
    }

    int RdmaContext::writeMsg(int src_fd, struct sock_id original_socket)
    {
        rdma_ringbuffer_t *ringbuffer = (is_server == true) ? ringbuffer_server : ringbuffer_client;

        if (!ringbuffer)
            throw runtime_error("ringbuffer is nullptr - writeMsg");

        uint32_t start_w_index, end_w_index, available_space;

        while (1)
        { // wait until there is enough space in the ringbuffer

            unique_lock<mutex> lock(mtx_tx);

            int c = 0;
            while (1)
            {
                start_w_index = ringbuffer->local_write_index.load();
                end_w_index = ringbuffer->remote_write_index.load();

                uint32_t used = start_w_index - end_w_index; // wrap-around safe
                available_space = Config::MAX_MSG_BUFFER - used - 1;

                if (available_space >= 1)
                    break;

                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = (Config::TIME_TO_WAIT_IF_NO_SPACE_MS) * 1000000; // ms -> ns
                nanosleep(&ts, nullptr);
                COUNT++;

                if (COUNT % 100 == 0)
                {
                    cout << "Waiting for space in the ringbuffer (" << COUNT << ")... "
                         << "Used: " << used << ", Available: " << available_space
                         << ", Start Index: " << start_w_index
                         << ", End Index: " << end_w_index << endl;
                    c++;
                }

                if (stop.load() == true)
                {
                    cout << "Stopping writeMsg due to stop signal." << endl;
                    return 1; // stop the thread
                }
            }

            // modulo the indexes
            start_w_index = RING_IDX(start_w_index);
            end_w_index = RING_IDX(end_w_index);

            rdma_msg_t *msg = &ringbuffer->data[start_w_index];

            msg->msg_size = recv(src_fd, msg->msg, Config::MAX_PAYLOAD_SIZE, 0);
            if ((int)msg->msg_size <= 0)
                return msg->msg_size;

            msg->msg_flags = 0;
            msg->original_sk_id = original_socket;
            msg->number_of_slots = 1;

            n_msg_sent.fetch_add(1);
            ringbuffer->local_write_index.fetch_add(1);

            lock.unlock();

            // this_thread::sleep_for(chrono::nanoseconds(1)); // simulate some processing delay
        }

        return 1;
    }

    void RdmaContext::parseMsg(bpf::BpfMng &bpf_ctx, vector<sk::client_sk_t> &client_sks, rdma_msg_t &msg)
    {
        // retrive the proxy_fd
        int fd;

        auto it = sockid_to_fd_map.find(msg.original_sk_id);
        if (it != sockid_to_fd_map.end())
        {
            fd = it->second;
        }
        else
        {
            // loockup the original socket
            // swap the ip and port
            struct sock_id swapped;
            swapped.dip = msg.original_sk_id.sip;
            swapped.sip = msg.original_sk_id.dip;
            swapped.dport = msg.original_sk_id.sport;
            swapped.sport = msg.original_sk_id.dport;

            // find the corresponding proxy socket
            struct sock_id proxy_sk_id = bpf_ctx.getProxySkFromAppSk(swapped);

            // find the original socket in the lists
            int i = 0;
            for (; i < Config::NUMBER_OF_SOCKETS; i++)
            {
                if (client_sks[i].sk_id.dip == proxy_sk_id.dip &&
                    client_sks[i].sk_id.sport == proxy_sk_id.sport &&
                    client_sks[i].sk_id.sip == proxy_sk_id.sip &&
                    client_sks[i].sk_id.dport == proxy_sk_id.dport)
                {
                    // update the map with the new socket
                    std::cout << "New entry: "
                              << msg.original_sk_id.sip << ":" << msg.original_sk_id.sport
                              << " - " << msg.original_sk_id.dip << ":" << msg.original_sk_id.dport
                              << " -> " << client_sks[i].fd << std::endl;
                    // update the map with the new socket
                    sockid_to_fd_map[msg.original_sk_id] = client_sks[i].fd;
                    fd = client_sks[i].fd;
                    break;
                }
            }

            if (i == Config::NUMBER_OF_SOCKETS)
            {
                cout << "Socket not found in the list: "
                     << msg.original_sk_id.sip << ":" << msg.original_sk_id.sport
                     << " -> " << msg.original_sk_id.dip << ":" << msg.original_sk_id.dport
                     << endl;
                throw runtime_error("Socket not found in the list - parseMsg");
            }
        }

        uint32_t sent_size = 0;
        while (sent_size < msg.msg_size)
        {
            uint32_t size = send(fd, msg.msg, msg.msg_size, 0);
            sent_size += size;
            if (size <= 0)
                throw runtime_error("Failed to send message, code: " + to_string(size) + " - parseMsg");
        }
    }

    void RdmaContext::updateRemoteReadIndex(rdma_ringbuffer_t &ringbuffer, uint32_t r_idx)
    {
        // COMMIT the read index
        ringbuffer.remote_read_index.store(r_idx);

        size_t read_index_offset = (size_t)(reinterpret_cast<const char *>(&ringbuffer) - (char *)buffer) +
                                   offsetof(rdma_ringbuffer_t, remote_read_index);

        uintptr_t remote_addr_read_index = remote_addr + read_index_offset;

        postWriteOp(remote_addr_read_index,
                    (uintptr_t)(buffer + read_index_offset),
                    sizeof(ringbuffer.remote_read_index),
                    true);
    }

    void RdmaContext::readMsg(bpf::BpfMng &bpf_ctx, vector<sk::client_sk_t> &client_sks, uint32_t start_read_index, uint32_t end_read_index)
    {
        rdma_ringbuffer_t *ringbuffer = is_server ? ringbuffer_client : ringbuffer_server;

        if (!ringbuffer)
            throw runtime_error("ringbuffer is nullptr - readMsg");

        if (start_read_index == end_read_index)
        {
            // nothing to read
            return;
        }

        uint32_t number_of_msg = (end_read_index + Config::MAX_MSG_BUFFER - start_read_index) % Config::MAX_MSG_BUFFER;

        start_read_index = RING_IDX(start_read_index);
        end_read_index = RING_IDX(end_read_index);

        u_int32_t n = 0;
        for (int i = 0; i < number_of_msg;)
        {
            int idx = RING_IDX(start_read_index + i);
            rdma_msg_t *msg = &ringbuffer->data[idx];
            parseMsg(bpf_ctx, client_sks, *msg);
            i += msg->number_of_slots;
        }
    }

    // UTILS

    void RdmaContext::setPollingStatus(uint32_t is_polling)
    {
        rdma_ringbuffer_t *ringbuffer = (is_server == true) ? ringbuffer_server : ringbuffer_client;
        unsigned int f = ringbuffer->flags.flags.load();

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
        uintptr_t remote_addr_2 = remote_addr + offset;

        postWriteOp(remote_addr_2,
                    (uintptr_t)(buffer + offset),
                    sizeof(ringbuffer->flags.flags),
                    true);

        cout << "Polling status updated: " << (is_polling ? "ON" : "OFF") << endl;
    }

    void RdmaContext::pollCqSend(ibv_cq *send_cq_to_poll)
    {
        if (send_cq_to_poll == nullptr)
            throw runtime_error("send_cq is nullptr - pollCqSend");

        struct ibv_wc wc;
        int num_completions;

        // poll until we get a completion
        while (1)
        {
            num_completions = ibv_poll_cq(send_cq_to_poll, 1, &wc);
            if (num_completions != 0 || stop.load() == true)
                break;
        }

        if (num_completions == 0)
        {
            cout << "Interrupted while polling CQ, no completions found." << endl;
            return; // no completions found, just return
        }

        if (num_completions < 0)
        {
            fprintf(stderr, "CQ error_1: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
            throw runtime_error("Failed to poll CQ - pollCqSend");
        }

        if (wc.status != IBV_WC_SUCCESS)
        {
            fprintf(stderr, "CQ error_2: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
            throw runtime_error("Failed to poll CQ - pollCqSend");
        }
    }

    const string RdmaContext::getOpName(CommunicationCode code)
    {
        switch (code)
        {
        case CommunicationCode::RDMA_DATA_READY:
            return "RDMA_DATA_READY";
        case CommunicationCode::RDMA_CLOSE_CONTEXT:
            return "RDMA_CLOSE_CONTEXT";
        case CommunicationCode::NONE:
            return "NONE";
        default:
            return "UNKNOWN";
        }
    }

    uint64_t RdmaContext::getTimeMS()
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
    }

    void RdmaContext::waitForContextToBeReady()
    {
        std::unique_lock<std::mutex> lock(mtx_tx);
        cond_tx.wait(lock, [&]()
                     { return is_ready.load() == true; });
    }

    uint32_t RdmaContext::getNextSendQIndex()
    {
        unique_lock<std::mutex> lock(mtx_send_q);
        uint32_t index = send_q_index;
        send_q_index = (send_q_index + 1) % Config::QP_N; // round-robin
        return index;
    }

}