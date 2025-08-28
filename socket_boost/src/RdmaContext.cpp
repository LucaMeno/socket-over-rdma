
#include <RdmaContext.h>

using namespace std;

namespace rdma
{
    int COUNT = 0; // for debugging

    conn_info RdmaContext::rdmaSetupPreHs()
    {
        srand48(getpid());
        int err = 0;

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
            send_cqs[i] = ibv_create_cq(ctx, Config::MAX_CQ_ENTRIES, nullptr, nullptr, 0);
            if (!send_cqs[i])
                throw runtime_error("Failed to create send CQ " + to_string(i));
        }

        // create receive CQ
        recv_cq = ibv_create_cq(ctx, Config::MAX_CQ_ENTRIES, nullptr, comp_channel, 0);
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

        err = posix_memalign((void **)&buffer, Config::ALIGNMENT, MR_SIZE);
        if (!buffer || err)
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
                .max_send_wr = Config::MAX_SEND_WR,
                .max_recv_wr = Config::MAX_RECV_WR,
                .max_send_sge = Config::MAX_SEND_SGE,
                .max_recv_sge = Config::MAX_RECV_SGE};

            qps[i] = ibv_create_qp(pd, &qpa);
            if (!qps[i])
                throw runtime_error("Failed to create QP " + to_string(i));

            ibv_qp_attr attr = {};
            attr.qp_state = IBV_QPS_INIT;
            attr.pkey_index = 0;
            attr.port_num = 1;
            attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE;

            err = ibv_modify_qp(qps[i], &attr,
                                IBV_QP_STATE | IBV_QP_PKEY_INDEX |
                                    IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
            if (err)
                throw runtime_error("Failed to modify QP to INIT state");
        }

        ibv_port_attr pattr;
        ibv_query_port(ctx, 1, &pattr);

        union ibv_gid gid;
        err = ibv_query_gid(ctx, 1, Config::getRdmaDevGidIdx(), &gid);
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
        ringbuffer_server->local_read_index = 0;
        ringbuffer_server->remote_read_index.store(0);
        ringbuffer_server->remote_write_index.store(0);
        ringbuffer_server->local_write_index = 0;
        ringbuffer_server->flags.flags.store(0);

        ringbuffer_client = (rdma_ringbuffer_t *)(buffer + NOTIFICATION_OFFSET_SIZE + RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
        ringbuffer_client->local_read_index = 0;
        ringbuffer_client->remote_read_index.store(0);
        ringbuffer_client->remote_write_index.store(0);
        ringbuffer_client->local_write_index = 0;
        ringbuffer_client->flags.flags.store(0);

        // Post the initial receive work request to receive the notification
        postReceive(-1, true);

        if (is_server)
        {
            buffer_to_write = ringbuffer_server;
            buffer_to_read = ringbuffer_client;
        }
        else
        {
            buffer_to_write = ringbuffer_client;
            buffer_to_read = ringbuffer_server;
        }

        cout << " ==================== CONNECTION INFO ====================\n";

        cout << "## LOCAL ##" << endl;
        std::cout << "Local QPN and PSN: " << endl;
        for (int i = 0; i < Config::QP_N; i++)
            std::cout << "- QPN[" << i << "]: " << local.qp_num[i] << " PSN: " << local.rq_psn[i] << "\n";
        cout << "Local LID: " << local.lid << "\n"
             << "Local BUFFER client: " << std::hex << ringbuffer_client << std::dec << "\n"
             << "Local BUFFER server: " << std::hex << ringbuffer_server << std::dec << "\n"
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

        local_remote_write_index_offset = (size_t)((char *)buffer_to_write - (char *)buffer) +
                                          offsetof(rdma_ringbuffer_t, remote_write_index);

        remote_addr_write_index = remote_addr + local_remote_write_index_offset;

        local_remote_read_index_offset = (size_t)((char *)buffer_to_read - (char *)buffer) +
                                         offsetof(rdma_ringbuffer_t, remote_read_index);

        remote_addr_read_index = remote_addr + local_remote_read_index_offset;
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
                    std::cout << "[" << i << "] device UP: " << ibv_get_device_name(device_list[i]);
                else
                    std::cout << "[" << i << "] device DOWN: " << ibv_get_device_name(device_list[i]);

                if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET)
                    std::cout << " (Ethernet)\n";
                else
                    std::cout << " (InfiniBand)\n";
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

    RdmaContext::RdmaContext(bpf::BpfMng &bpf_ctx, std::vector<sk::client_sk_t> &client_sks)
        : bpf_ctx(bpf_ctx), client_sks(client_sks)
    {
        is_ready.store(false);
        stop.store(false);
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
        buffer_to_read = nullptr;
        buffer_to_write = nullptr;
        remote_rkey = 0;
        remote_addr = 0;
        remote_ip = 0;

        for (uint32_t i = 0; i < Config::WORK_REQUEST_POOL_SIZE; i++)
            if (!wr_available_idx_queue.push(i))
                throw std::runtime_error("Work request pool is exhausted");

        for (int i = 0; i < Config::QP_N; i++)
            is_qp_idx_available[i] = true;
        is_qp_idx_available[Config::DEFAULT_QP_IDX] = false;

        for (size_t i = 0; i < Config::QP_N - 1; i++)
            flush_threads[i] = std::thread(&RdmaContext::flushThread, this);
        reader_thread = std::thread(&RdmaContext::readerThread, this);
        update_remote_r_thread = std::thread(&RdmaContext::updateRemoteReadIndexThread, this);
    }

    RdmaContext::~RdmaContext()
    {
        is_ready.store(false);
        stop.store(true);

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
        buffer_to_read = nullptr;
        buffer_to_write = nullptr;
        remote_ip = 0;
        remote_addr = 0;
        remote_rkey = 0;

        unique_lock<mutex> lock_tx(mtx_tx);
        cond_tx.notify_all();
        lock_tx.unlock();

        cout << "[Shutdown] -- Waiting for reader threads to finish" << endl;
        if (reader_thread.joinable())
            reader_thread.join();
        cout << "[Shutdown] -- Reader thread joined" << endl;
        cout << "[Shutdown] -- Waiting for update remote read index thread to finish" << endl;
        if (update_remote_r_thread.joinable())
            update_remote_r_thread.join();
        cout << "[Shutdown] -- Update remote read index thread joined" << endl;
        cout << "[Shutdown] -- Waiting for flush threads to finish" << endl;
        for (int i = 0; i < Config::QP_N - 1; i++)
            if (flush_threads[i].joinable())
            {
                flush_threads[i].join();
                cout << "[Shutdown] -- Flush thread " << i << " joined" << endl;
            }
        cout << "[Shutdown] -- All flush threads joined" << endl;
    }

    void RdmaContext::readerThread()
    {
        waitForContextToBeReady();
        if (stop.load())
            return;
        cout << "[Debug] -- starting ReaderThread" << endl;
        int ret = readMsgLoop();
        cout << "Read msgLoop terminated with: " << ret << endl;
        cout << "[Debug] -- ReaderThread exiting" << endl;
    }

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
        int qp_index = getFreeQpIndex();

        struct ibv_send_wr *bad_send_wr;
        if (ibv_post_send(qps[qp_index], &send_wr, &bad_send_wr) != 0) // Post the send work request
        {
            releaseQpIndex(qp_index);
            throw runtime_error("Failed to post send - sendNotification");
        }

        // Poll the completion queue
        pollCqSend(send_cqs[qp_index]);
        cout << "Sent notification: " << getOpName(code) << endl;
        releaseQpIndex(qp_index);
    }

    void RdmaContext::sendDataReady()
    {
        sendNotification(CommunicationCode::RDMA_DATA_READY);
        last_notification_data_ready_ns = getTimeMS();
    }

    inline void RdmaContext::enqueueWr(uint32_t start_idx, uint32_t end_idx, size_t data_size)
    {
        uint32_t idx;
        bool p = false;
        while (!wr_available_idx_queue.pop(idx))
        {
            if (!p)
            {
                cout << "No available work request indices, waiting..." << endl;
                p = true;
            }
            this_thread::yield(); // backoff
            if (stop.load() == true)
            {
                cout << "Stopping readMsgFromSk due to stop signal" << endl;
                break;
            }
        }

        uint32_t r_idx = RING_IDX(start_idx);

        uintptr_t batch_start = (uintptr_t)&buffer_to_write->data[r_idx];
        uintptr_t remote_addr_2 = remote_addr +
                                  ((uintptr_t)batch_start - (uintptr_t)buffer); // offset

        createWrAtIdx(remote_addr_2, batch_start, data_size, idx);

        if (!wr_busy_idx_queue.push(idx))
            throw runtime_error("Failed to push index to wr_busy_idx_queue");
    }

    inline WorkRequest RdmaContext::createWr(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, bool signaled)
    {
        WorkRequest wr = {0};

        wr.sge.addr = local_addr;      // Local address of the buffer
        wr.sge.length = size_to_write; // Size of the data to write
        wr.sge.lkey = mr->lkey;        // Local key from registered memory region

        wr.wr.wr_id = 0; // Set to 0 for simplicity
        wr.wr.sg_list = &wr.sge;
        wr.wr.num_sge = 1;
        wr.wr.opcode = IBV_WR_RDMA_WRITE;
        wr.wr.next = nullptr;
        wr.wr.wr.rdma.remote_addr = remote_addr; // Remote address to write to
        wr.wr.wr.rdma.rkey = remote_rkey;        // Remote key
        wr.wr.send_flags = 0;
        if (signaled)
            wr.wr.send_flags |= IBV_SEND_SIGNALED;

        return wr;
    }

    inline void RdmaContext::createWrAtIdx(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, uint32_t idx)
    {
        WorkRequest *wr = &wr_pool[idx];

        wr->sge.addr = local_addr;      // Local address of the buffer
        wr->sge.length = size_to_write; // Size of the data to write
        wr->sge.lkey = mr->lkey;        // Local key from registered memory region

        wr->wr.wr_id = 0; // Set to 0 for simplicity
        wr->wr.sg_list = &wr->sge;
        wr->wr.num_sge = 1;
        wr->wr.opcode = IBV_WR_RDMA_WRITE;
        wr->wr.next = nullptr;
        wr->wr.wr.rdma.remote_addr = remote_addr; // Remote address to write to
        wr->wr.wr.rdma.rkey = remote_rkey;        // Remote key
        wr->wr.send_flags = 0;
    }

    inline void RdmaContext::postWrBatchListOnQp(vector<WorkRequest *> &wr_batch, int qp_idx)
    {
        // Prepare the work requests for posting
        size_t i = 0;
        for (; i < wr_batch.size() - 1; ++i)
        {
            wr_batch[i]->wr.sg_list = &wr_batch[i]->sge; // Link the SGE to the WR
            wr_batch[i]->wr.next = &wr_batch[i + 1]->wr; // Link the WRs together
        }
        // last WR
        wr_batch[i]->wr.sg_list = &wr_batch[i]->sge;     // Link the SGE to the WR
        wr_batch[i]->wr.next = nullptr;                  // Last WR does not have a next pointer
        wr_batch[i]->wr.send_flags |= IBV_SEND_SIGNALED; // Set the last WR to be signaled

        // post
        struct ibv_send_wr *bad_send_wr_data;
        int ret = ibv_post_send(qps[qp_idx], &wr_batch[0]->wr, &bad_send_wr_data);
        if (ret != 0)
            throw runtime_error("Failed to post write - flushWrQueue - code: " + to_string(ret) + " on QP_idx: " + to_string(qp_idx));

        // cout << "Posted: " << wr_batch.size() << " wr on qp: " << qp_idx << endl;
    }

    void RdmaContext::flushThread()
    {
        waitForContextToBeReady();
        if (stop.load())
            return;

        int qp_idx = getFreeQpIndex();

        cout << "[Debug] -- starting FlushThread on QP: " << qp_idx << endl;

        auto *wr_batch = new std::vector<WorkRequest *>();
        wr_batch->reserve(Config::MAX_WR_PER_POST_PER_QP);

        auto *indexes = new std::vector<uint32_t>();
        indexes->reserve(Config::MAX_WR_PER_POST_PER_QP);

        while (stop.load() == false)
        {
            uint32_t idx = 0;
            WorkRequest *wr;
            int j = 0;

            wr_batch->clear();
            indexes->clear();

            uint64_t local_last_flush = getTimeMS();

            while (true)
            {
                if (stop.load() == true)
                    return;

                if (j >= Config::MAX_WR_PER_POST_PER_QP)
                    break;

                if (getTimeMS() - local_last_flush > Config::FLUSH_INTERVAL_MS && j > 0)
                {
                    // cout << "TIME, j: " << j << endl;
                    break;
                }

                if (!wr_busy_idx_queue.pop(idx))
                    continue;

                wr = &wr_pool[idx];
                wr_batch->push_back(wr);
                indexes->push_back(idx);

                j++;
            }

            postWrBatchListOnQp(*wr_batch, qp_idx);
            outgoing_wrs[qp_idx].fetch_add(1);
            uint32_t n = outgoing_wrs[qp_idx].load();
            if (n >= Config::POLL_CQ_AFTER_WR)
            {
                pollCqSend(send_cqs[qp_idx], n);
                outgoing_wrs[qp_idx].fetch_sub(n);
            }

            for (size_t i = 0; i < indexes->size(); i++)
                if (!wr_available_idx_queue.push((*indexes)[i]))
                    throw runtime_error("Failed to push index to wr_available_idx_queue");
        }

        cout << "[Debug] -- FlushThread exiting for QP: " << qp_idx << endl;
    }

    int RdmaContext::writeMsg(int src_fd, struct sock_id original_socket)
    {
        uint32_t start_w_index, end_w_index, available_space;

        unique_lock<mutex> lock(mtx_tx);

        // Wait until there is space in the ring buffer
        while (true)
        {
            start_w_index = buffer_to_write->local_write_index;
            end_w_index = buffer_to_write->remote_read_index.load();

            uint32_t used = start_w_index - end_w_index; // wrap-around safe
            available_space = Config::MAX_MSG_BUFFER - used - 1;

            if (available_space >= 1)
                break;

            COUNT++;

            // this_thread::yield(); // backoff

            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = (Config::TIME_TO_WAIT_IF_NO_SPACE_MS) * 1000000; // ms -> ns
            nanosleep(&ts, nullptr);

            if (COUNT % 100 == 0)
            {
                cout << "Waiting for space in the ringbuffer (" << COUNT << ")... "
                     << "Used: " << used << ", Available: " << available_space
                     << ", Start Index: " << start_w_index
                     << ", End Index: " << end_w_index << endl;
            }

            if (stop.load() == true)
                throw runtime_error("Stopping writeMsg due to stop signal");
        }

        // write all possible messages in the buffer
        while (available_space >= 1)
        {
            rdma_msg_t *msg = &buffer_to_write->data[RING_IDX(start_w_index)];

            msg->msg_size = recv(src_fd, msg->msg, Config::MAX_PAYLOAD_SIZE, 0);

            if ((int)msg->msg_size <= 0)
                return msg->msg_size;

            msg->msg_flags = 0;
            msg->original_sk_id = original_socket;
            msg->number_of_slots = 1;
            uint32_t sn = seq_number_write.fetch_add(1);
            msg->seq_number_head = sn;
            msg->seq_number_tail = sn;
            //  cout << "WRITE: sn: " << sn << " size: " << msg->msg_size << endl;

            buffer_to_write->local_write_index += msg->number_of_slots;

            enqueueWr(start_w_index,
                      start_w_index + msg->number_of_slots,
                      sizeof(rdma_msg_t));

            available_space -= msg->number_of_slots;
            start_w_index += msg->number_of_slots;
        }

        return 1;
    }

    inline int RdmaContext::parseMsg(rdma_msg_t &msg)
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
                    sockid_to_fd_map[msg.original_sk_id] = client_sks[i].fd;
                    fd = client_sks[i].fd;
                    break;
                }
            }

            if (i == Config::NUMBER_OF_SOCKETS)
            {
                cerr << "Socket not found in the list: "
                     << msg.original_sk_id.sip << ":" << msg.original_sk_id.sport
                     << " -> " << msg.original_sk_id.dip << ":" << msg.original_sk_id.dport
                     << endl;
                return 1; // socket not found, cannot parse the message
            }
        }

        int rem = msg.msg_size;
        char *ptr = msg.msg;
        int c = 0;
        while (rem > 0)
        {
            int size = send(fd, ptr, rem, 0);
            if (size <= 0)
            {
                cerr << "Failed to send message - parseMsg: " + string(strerror(errno)) << endl;
                return 1;
            }
            rem -= size;
            ptr += size;
            if (c++ > 1)
                cout << "Warn - " << c << endl;
        }

        return 0;
    }

    void RdmaContext::updateRemoteReadIndexThread()
    {
        waitForContextToBeReady();
        if (stop.load())
            return;
        cout << "[Debug] -- starting updateRemoteReadIndexThread" << endl;

        while (stop.load() == false)
        {
            while (buffer_to_read->local_read_index.load() == buffer_to_read->remote_read_index.load())
            {
                this_thread::yield();
                if (stop.load() == true)
                    return; // stop the reading
            }

            buffer_to_read->remote_read_index.store(buffer_to_read->local_read_index.load(), memory_order_release);

            // cout << "Update rem read idx -> " << buffer_to_read->remote_read_index.load() << endl;

            WorkRequest wr = createWr(remote_addr_read_index,
                                      (uintptr_t)(buffer + local_remote_read_index_offset),
                                      sizeof(buffer_to_read->remote_read_index),
                                      true);

            wr.wr.sg_list = &wr.sge; // Link the SGE to the WR
            wr.wr.num_sge = 1;       // Set the number of SG
            wr.wr.next = nullptr;    // Last WR does not have a next pointer

            struct ibv_send_wr *bad_send_wr_data;

            int ret = ibv_post_send(qps[Config::DEFAULT_QP_IDX], &wr.wr, &bad_send_wr_data);
            if (ret != 0) // Post the send work request
            {
                cout << "Wr failed: " << endl
                     << "- Remote Address: " << std::hex << wr.wr.wr.rdma.remote_addr << std::dec << endl
                     << "- Local Address: " << std::hex << wr.sge.addr << std::dec << endl
                     << "- Size: " << wr.sge.length << endl
                     << "- RKey: " << wr.wr.wr.rdma.rkey << endl;
                cout << "- Error code: " << ret << endl;
                cout << "- Bad send WR data: " << (bad_send_wr_data ? "not null" : "null") << endl;
                cout << "- QP index: " << Config::DEFAULT_QP_IDX << endl;

                throw runtime_error("Failed to post write - updateRemoteReadIndex - code: " + to_string(ret));
            }

            pollCqSend(send_cqs[Config::DEFAULT_QP_IDX], 1);
        }
        cout << "[Debug] -- updateRemoteReadIndexThread exiting" << endl;
    }

    int RdmaContext::readMsgLoop()
    {
        // removeClosedSocket(sockid_to_fd_map);

        if (!buffer_to_read)
            throw runtime_error("ringbuffer is nullptr - readMsgLoop");

        while (stop.load() == false)
        {
            for (size_t i = 0; i < Config::MAX_MSG_BUFFER;)
            {
                rdma_msg_t *msg = &buffer_to_read->data[i];

                uint32_t sn = seq_number_read.fetch_add(1);
                while (msg->seq_number_head != sn || msg->seq_number_tail != sn)
                {
                    this_thread::yield();
                    if (stop.load() == true)
                        return 1; // stop the reading
                }

                // cout << "READ: sn: " << sn << " size: " << msg->msg_size << endl;

                if (msg->msg_size == 0 || msg->msg_size > Config::MAX_PAYLOAD_SIZE || msg->number_of_slots != 1)
                    throw runtime_error("Invalid message received - readMsgLoop");

                int ret = parseMsg(*msg);
                /*if (ret != 0)
                    return ret;*/

                i += msg->number_of_slots;
                buffer_to_read->local_read_index.fetch_add(msg->number_of_slots, memory_order_release);
            }
        }

        return 0;
    }

    void RdmaContext::setPollingStatus(uint32_t is_polling)
    {
        unsigned int f = buffer_to_write->flags.flags.load();

        // is polling?
        if (f & static_cast<unsigned int>(RingBufferFlag::RING_BUFFER_POLLING) == is_polling)
            return;

        uint32_t expected = buffer_to_write->flags.flags.load(std::memory_order_relaxed);
        uint32_t desired;

        do
        {
            desired = expected ^ static_cast<uint32_t>(RingBufferFlag::RING_BUFFER_POLLING); // toggle bit
            desired |= static_cast<uint32_t>(RingBufferFlag::RING_BUFFER_CAN_POLLING);       // set bit
        } while (!buffer_to_write->flags.flags.compare_exchange_weak(
            expected,                  // -- on success this becomes the old value
            desired,                   // -- the new value you want to write
            std::memory_order_acq_rel, // success order
            std::memory_order_relaxed)); // failure order

        // update the polling status on the remote side
        size_t offset = (size_t)((char *)buffer_to_write - (char *)buffer);
        uintptr_t remote_addr_2 = remote_addr + offset;

        /* TODO executeWrNow(remote_addr_2,
                     (uintptr_t)(buffer + offset),
                     sizeof(buffer_to_write->flags.flags),
                     true);*/

        cout << "Polling status updated: " << (is_polling ? "ON" : "OFF") << endl;
    }

    void RdmaContext::pollCqSend(ibv_cq *send_cq_to_poll, int num_entry)
    {
        if (send_cq_to_poll == nullptr)
            throw runtime_error("send_cq is nullptr - pollCqSend");

        // struct ibv_wc wc;
        std::vector<ibv_wc> wc_array(num_entry);
        int num_completions;
        int remaining = num_entry;

        while (remaining > 0)
        { // poll until we get a completion
            while (1)
            {
                num_completions = ibv_poll_cq(send_cq_to_poll, remaining, wc_array.data());
                if (num_completions != 0 || stop.load() == true)
                    break;
            }

            if (stop.load() == true)
            {
                cout << "Interrupted while polling CQ, no completions found." << endl;
                return; // no completions found, just return
            }

            if (num_completions < 0)
            {
                throw runtime_error("Failed to poll CQ - pollCqSend");
            }

            for (int i = 0; i < num_completions; ++i)
                if (wc_array[i].status != IBV_WC_SUCCESS)
                    throw runtime_error("Work completion error: " + to_string(wc_array[i].status) + " - pollCqSend");

            remaining -= num_completions;
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
                     { return is_ready.load() == true || stop.load(); });
    }

    void RdmaContext::postReceive(int qpIdx, bool allQp = false)
    {
        if ((qpIdx < 0 && !allQp) || qpIdx >= Config::QP_N)
            throw std::out_of_range("Invalid QP index");

        ibv_sge sge{
            .addr = reinterpret_cast<uintptr_t>(buffer),
            .length = sizeof(notification_t),
            .lkey = mr->lkey};

        ibv_recv_wr recv_wr = {};
        recv_wr.wr_id = 0;
        recv_wr.sg_list = &sge;
        recv_wr.num_sge = 1;
        recv_wr.next = nullptr;

        ibv_recv_wr *bad_wr = nullptr;
        if (srq)
        {
            if (ibv_post_srq_recv(srq, &recv_wr, &bad_wr) != 0 || bad_wr)
                throw std::runtime_error("Failed to post SRQ receive work request");
        }
        else
        {
            if (allQp)
            {
                for (int i = 0; i < Config::QP_N; ++i)
                    if (ibv_post_recv(qps[i], &recv_wr, &bad_wr) != 0 || bad_wr)
                        throw std::runtime_error("Failed to post initial receive work request to QP " + std::to_string(i));
            }
            else
            {
                if (ibv_post_recv(qps[qpIdx], &recv_wr, &bad_wr) != 0 || bad_wr)
                    throw std::runtime_error("Failed to post receive work request");
            }
        }
    }

    int RdmaContext::getFreeQpIndex()
    {
        std::unique_lock<std::mutex> lock(mtx_qp_idx);

        cv_qp_idx.wait(lock, [&]
                       {
                        if(stop.load())  return true;
                        for (int i = 0; i < Config::QP_N; i++)
                            if (is_qp_idx_available[i])
                                return true;
                        cout << "[Debug] -- No idx available, getFreeQpIndex wait... " << endl;
                        return false; });

        if (stop.load())
            throw std::runtime_error("Stopping getFreeQpIndex due to stop signal");

        for (int i = 0; i < Config::QP_N; i++)
        {
            if (is_qp_idx_available[i])
            {
                is_qp_idx_available[i] = false;
                return i;
            }
        }

        // should never reach this point...
        throw std::runtime_error("No available index found");
    }
    std::vector<int> RdmaContext::getFreeQpIndexes(int n)
    {
        if (n <= 0 || n > Config::QP_N)
            throw std::invalid_argument("Invalid number of indices requested");

        std::vector<int> result;
        result.reserve(n);

        std::unique_lock<std::mutex> lock(mtx_qp_idx);

        cv_qp_idx.wait(lock, [&]
                       {
                        if(stop.load())  return true;
                        int free_count = 0;
                        for (int i = 0; i < Config::QP_N; i++)
                            if (is_qp_idx_available[i]) free_count++;
                        if(free_count >= n) return true;
                        cout << "[Debug] -- No idx available, getFreeQpIndex("<<n<<") wait... " <<endl;
                        return false; });

        if (stop.load())
            throw std::runtime_error("Stopping getFreeQpIndexes due to stop signal");

        int j = 0;
        for (int i = 0; i < Config::QP_N; i++)
        {
            if (is_qp_idx_available[i])
            {
                is_qp_idx_available[i] = false;
                result.push_back(i);
                j++;
                if (j == n)
                    break;
            }
        }

        if (result.size() != n)
            throw std::runtime_error("Failed to acquire the requested number of indices");

        return result;
    }

    void RdmaContext::releaseQpIndex(int index)
    {
        releaseQpIndexes({index});
    }

    void RdmaContext::releaseQpIndexes(const std::vector<int> &indexes)
    {
        lock_guard<std::mutex> lock(mtx_qp_idx);
        for (int index : indexes)
            is_qp_idx_available[index] = true;
        cv_qp_idx.notify_all();
    }
}
