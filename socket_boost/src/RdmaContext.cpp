
#include <RdmaContext.h>

using namespace std;

namespace rdma
{
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
            logger.log(LogLevel::WARNING, "Failed to create shared receive queue, using default receive CQ");
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
                .max_recv_sge = Config::MAX_RECV_SGE,
                .max_inline_data = sizeof(rdma_ringbuffer_t::remote_read_index)}; // used only for the remote read index update

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

        logger.log(LogLevel::CONNECT, " ==================== CONNECTION INFO ====================");

        logger.log(LogLevel::CONNECT, "## LOCAL ##");
        logger.log(LogLevel::CONNECT, "Local QPN and PSN: ");
        for (int i = 0; i < Config::QP_N; i++)
            logger.log(LogLevel::CONNECT, "- QPN[" + std::to_string(i) + "]: " + std::to_string(local.qp_num[i]) + " PSN: " + std::to_string(local.rq_psn[i]));
        logger.log(LogLevel::CONNECT, "Local LID: " + std::to_string(local.lid));
        logger.log(LogLevel::CONNECT, "Local BUFFER client: " + std::to_string(reinterpret_cast<uintptr_t>(ringbuffer_client)));
        logger.log(LogLevel::CONNECT, "Local BUFFER server: " + std::to_string(reinterpret_cast<uintptr_t>(ringbuffer_server)));
        logger.log(LogLevel::CONNECT, "Local RKEY: " + std::to_string(local.rkey));
        std::ostringstream oss1;
        for (int i = 0; i < 16; i++)
            oss1 << std::hex << std::setw(2) << std::setfill('0') << (int)local.gid.raw[i];
        logger.log(LogLevel::CONNECT, "Local GID: " + oss1.str());

        logger.log(LogLevel::CONNECT, "## REMOTE ##");

        logger.log(LogLevel::CONNECT, "Remote QPN and PSN: ");
        for (int i = 0; i < Config::QP_N; i++)
            logger.log(LogLevel::CONNECT, "- QPN[" + std::to_string(i) + "]: " + std::to_string(remote.qp_num[i]) + " PSN: " + std::to_string(remote.rq_psn[i]));
        logger.log(LogLevel::CONNECT, "Remote LID: " + std::to_string(remote.lid));
        logger.log(LogLevel::CONNECT, "Remote BUFFER: " + std::to_string(reinterpret_cast<uintptr_t>(remote.addr)));
        logger.log(LogLevel::CONNECT, "Remote RKEY: " + std::to_string(remote.rkey));
        std::ostringstream oss2;
        for (int i = 0; i < 16; i++)
            oss2 << std::hex << std::setw(2) << std::setfill('0') << (int)remote.gid.raw[i];

        logger.log(LogLevel::INFO, "Remote GID: " + oss2.str());

        showDevices();

        logger.log(LogLevel::CONNECT, "==========================================================");

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
        logger.log(LogLevel::INFO, "Server ready");

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

        logger.log(LogLevel::INFO, "Accepted new client connection");

        rdmaSetupPostHs(remote, local);

        signalContextReady();
    }

    void RdmaContext::clientConnect(uint32_t server_ip, uint16_t server_port)
    {
        is_server = false;

        conn_info local = rdmaSetupPreHs();

        int sock = tcpConnect(server_ip);
        if (sock < 0)
        {
            logger.log(LogLevel::ERROR, "Failed to connect to server: " + std::string(strerror(errno)));
            throw runtime_error("tcpConnect failed");
        }

        conn_info remote;
        if (read(sock, &remote, sizeof(remote)) < 0)
        {
            logger.log(LogLevel::ERROR, "Failed to read remote connection info");
            close(sock);
            throw runtime_error("Failed to read remote connection info");
        }

        if (write(sock, &local, sizeof(local)) < 0)
        {
            logger.log(LogLevel::ERROR, "Failed to write local connection info");
            close(sock);
            throw runtime_error("Failed to write local connection info");
        }

        close(sock);

        logger.log(LogLevel::INFO, "Connected to server");

        rdmaSetupPostHs(remote, local);

        signalContextReady();
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
            logger.log(LogLevel::ERROR, "getaddrinfo failed");
            return -1;
        }

        int fd = socket(res->ai_family, res->ai_socktype, 0);
        if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0)
        {
            logger.log(LogLevel::ERROR, "connect failed");
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
            logger.log(LogLevel::ERROR, "No RDMA devices found.");

        logger.log(LogLevel::CONNECT, "## DEVICES ##");
        for (int i = 0; i < num_devices; ++i)
        {
            ibv_context *ctx = ibv_open_device(device_list[i]);
            if (!ctx)
                continue;

            ibv_port_attr port_attr;

            if (ibv_query_port(ctx, Config::RDMA_DEV_PORT, &port_attr) == 0)
            {
                std::ostringstream oss;

                oss << "[" << i << "] device "
                    << (port_attr.state == IBV_PORT_ACTIVE ? "UP: " : "DOWN: ")
                    << ibv_get_device_name(device_list[i])
                    << " ("
                    << (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET ? "Ethernet" : "InfiniBand")
                    << ")";

                logger.log(LogLevel::CONNECT, oss.str());
            }
            ibv_close_device(ctx);
        }
        logger.log(LogLevel::CONNECT, "Target RDMA device index: " + std::to_string(Config::getDevIdx()) + " - GID: " + std::to_string(Config::getRdmaDevGidIdx()));
        ibv_free_device_list(device_list);
    }

    ibv_context *RdmaContext::openDevice()
    {
        int num_devices = 0;
        ibv_device **device_list = ibv_get_device_list(&num_devices);
        if (!device_list || num_devices == 0)
        {
            logger.log(LogLevel::ERROR, "No RDMA devices found.");
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
            logger.log(LogLevel::ERROR, "No active RDMA devices found.");
            ibv_free_device_list(device_list);
            return nullptr;
        }

        int devIndex = Config::getDevIdx();
        if (devIndex >= active_devices.size())
        {
            logger.log(LogLevel::ERROR, "Invalid device index (only " + std::to_string(active_devices.size()) + " active devices available).");
            ibv_free_device_list(device_list);
            throw std::runtime_error("Invalid device index");
        }

        if (!active_devices[devIndex])
        {
            logger.log(LogLevel::WARNING, "Selected device is not active, trying to use the first active device...");
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
            logger.log(LogLevel::ERROR, "Failed to open selected RDMA device.");
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

        for (int i = 1; i < Config::QP_N; i++)
        {
            flush_threads[i - 1] = std::thread(&RdmaContext::flushThread, this, i);
            pthread_setname_np(flush_threads[i - 1].native_handle(), "FlushThrd");
        }

        update_remote_r_thread = std::thread(&RdmaContext::updateRemoteReadIndexThread, this);
        pthread_setname_np(update_remote_r_thread.native_handle(), "UpdRmtRdIdx");
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

        // Wake up threads waiting for the context to be ready
        signalContextReady();

        logger.log(LogLevel::SHUTDOWN, "Waiting for update remote read index thread to finish");
        if (update_remote_r_thread.joinable())
            update_remote_r_thread.join();
        logger.log(LogLevel::SHUTDOWN, "Update remote read index thread joined");
        logger.log(LogLevel::SHUTDOWN, "Waiting for flush threads to finish");
        for (int i = 0; i < Config::QP_N - 1; i++)
            if (flush_threads[i].joinable())
                flush_threads[i].join();
        logger.log(LogLevel::SHUTDOWN, "All flush threads joined");
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
        int qp_index = Config::DEFAULT_QP_IDX;

        struct ibv_send_wr *bad_send_wr;
        if (ibv_post_send(qps[qp_index], &send_wr, &bad_send_wr) != 0) // Post the send work request
        {
            throw runtime_error("Failed to post send - sendNotification");
        }

        // Poll the completion queue
        pollCqSend(send_cqs[qp_index]);
        logger.log(LogLevel::DEBUG, "Sent notification: " + getOpName(code));
    }

    void RdmaContext::sendDataReady()
    {
        sendNotification(CommunicationCode::RDMA_DATA_READY);
        last_notification_data_ready_ns = getTimeMS();
    }

    inline void RdmaContext::createWrAtIdxFromBufferIdx(uint32_t buffer_idx, WorkRequest *wr)
    {
        uint32_t wrapped_idx = RING_IDX(buffer_idx);
        rdma_msg_t *msg = &buffer_to_write->data[wrapped_idx];

        uintptr_t batch_start = (uintptr_t)&buffer_to_write->data[wrapped_idx];
        uintptr_t remote_addr_2 = remote_addr +
                                  ((uintptr_t)batch_start - (uintptr_t)buffer); // offset

        createWrAtIdx(remote_addr_2,
                      (uintptr_t)msg,
                      sizeof(rdma_msg_t),
                      wr);
    }

    inline void RdmaContext::createWrAtIdx(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, WorkRequest *wr)
    {
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

        // logger.log(LogLevel::DEBUG, "Posted: " + std::to_string(end - start) + " wr on qp: " + std::to_string(qp_idx));
    }

    void RdmaContext::flushThread(int id)
    {
        waitForContextToBeReady();

        auto local_wr_batch = vector<WorkRequest *>();
        local_wr_batch.reserve(Config::MAX_WR_PER_POST_PER_QP);

        WorkRequest wr_array[Config::MAX_WR_PER_POST_PER_QP];
        memset(wr_array, 0, sizeof(wr_array));

        int qp_idx = id;
        int queue_idx = (qp_idx - 1) % Config::N_OF_QUEUES; // start from a different queue each time

        while (stop.load() == false)
        {
            uint32_t idx = 0;
            int j = 0;

            uint64_t local_last_flush = 0;
            local_wr_batch.clear();
            bool started = false;
            while (true)
            {
                if (stop.load() == true)
                    return;

                if (j >= Config::MAX_WR_PER_POST_PER_QP)
                    break;

                if (started &&
                    j > 0 &&
                    getTimeMS() - local_last_flush > Config::FLUSH_INTERVAL_MS)
                {
                    qp_index_repeater.reset(); // avoid other WR to be posted on this QP
                    if (msgs_idx_to_flush_queue[queue_idx].pop(idx))
                    {
                        createWrAtIdxFromBufferIdx(idx, &wr_array[j]);
                        local_wr_batch.push_back(&wr_array[j]);
                    }

                    /*if (j < 5)
                        logger.log(LogLevel::DEBUG, "TIME wr:" + std::to_string(j) + " on qp_idx: " + std::to_string(qp_idx));*/

                    break;
                }

                if (!msgs_idx_to_flush_queue[queue_idx].pop(idx))
                    continue;

                if (!started)
                {
                    local_last_flush = getTimeMS();
                    started = true;
                }

                createWrAtIdxFromBufferIdx(idx, &wr_array[j]);

                local_wr_batch.push_back(&wr_array[j]);
                j++;
            }

            postWrBatchListOnQp(local_wr_batch, qp_idx);
            outgoing_wrs[qp_idx] += 1;
            uint32_t n = outgoing_wrs[qp_idx];

            if (n >= Config::POLL_CQ_AFTER_WR)
            {
                pollCqSend(send_cqs[qp_idx], n);
                outgoing_wrs[qp_idx] -= n;
            }
        }
    }

    uint32_t COUNT = 0; // for debugging
    int RdmaContext::writeMsg(int src_fd, struct sock_id original_socket, const std::function<bool()> &is_valid)
    {
        uint32_t start_w_index, end_w_index, available_space;

        scoped_lock<mutex> lock(mtx_tx);

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

            if (COUNT % Config::PRINT_NO_SPACE_EVERY == 0)
                logger.log(LogLevel::DEBUG, "Waiting for space in the ringbuffer (" + std::to_string(COUNT) + ")... " + " remote_read_idx: " + std::to_string(end_w_index));

            if (stop.load() == true)
                throw runtime_error("Stopping writeMsg due to stop signal");

            if (!is_valid())
            {
                logger.log(LogLevel::DEBUG, "Socket not valid anymore, stopping writeMsg");
                return 1; // stop writing if the socket is not valid anymore
            }
        }

        // write all possible messages in the buffer
        while (available_space >= 1)
        {
            rdma_msg_t *msg = &buffer_to_write->data[RING_IDX(start_w_index)];

            int retry = Config::N_RETRY_WRITE_MSG;
            msg->msg_size = 0;
            while (retry > 0)
            {
                int sz = recv(src_fd, msg->msg + msg->msg_size, Config::MAX_PAYLOAD_SIZE - msg->msg_size, 0);
                if (sz > 0)
                    msg->msg_size += sz;
                else if (sz == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
                    return sz; // error

                if (msg->msg_size >= Config::MAX_PAYLOAD_SIZE)
                    break;

                retry--;
            }

            if (msg->msg_size == 0)
                return 1; // EOF

            msg->msg_flags = 0;
            msg->original_sk_id = original_socket;
            msg->number_of_slots = 1;
            uint32_t sn = seq_number_write.fetch_add(1);
            msg->seq_number_head = sn;
            msg->seq_number_tail = sn;

            msgs_idx_to_flush_queue[qp_index_repeater.get()].push(buffer_to_write->local_write_index);

            buffer_to_write->local_write_index += msg->number_of_slots;
            available_space -= msg->number_of_slots;
            start_w_index += msg->number_of_slots;

            if (!is_valid())
            {
                logger.log(LogLevel::DEBUG, "Socket not valid anymore, stopping writeMsg");
                return 1; // stop writing if the socket is not valid anymore
            }
        }

        return 1;
    }

    void RdmaContext::updateRemoteReadIndexThread()
    {
        waitForContextToBeReady();

        WorkRequest wr;
        while (stop.load() == false)
        {
            while (buffer_to_read->local_read_index.load() == buffer_to_read->remote_read_index.load())
            {
                // this_thread::yield();
                if (stop.load() == true)
                    return; // stop the reading
            }

            buffer_to_read->remote_read_index.store(buffer_to_read->local_read_index.load(), memory_order_release);

            createWrAtIdx(remote_addr_read_index,
                          (uintptr_t)(buffer + local_remote_read_index_offset),
                          sizeof(buffer_to_read->remote_read_index),
                          &wr);

            wr.wr.send_flags = IBV_SEND_SIGNALED; // We want a completion for this WR

            wr.wr.sg_list = &wr.sge; // Link the SGE to the WR
            wr.wr.num_sge = 1;       // Set the number of SG
            wr.wr.next = nullptr;    // Last WR does not have a next pointer

            struct ibv_send_wr *bad_send_wr_data;

            int ret = ibv_post_send(qps[Config::DEFAULT_QP_IDX], &wr.wr, &bad_send_wr_data);
            if (ret != 0) // Post the send work request
            {
                logger.log(LogLevel::ERROR, "Wr failed: ");
                logger.log(LogLevel::ERROR, "- Remote Address: " + std::to_string(wr.wr.wr.rdma.remote_addr));
                logger.log(LogLevel::ERROR, "- Local Address: " + std::to_string(wr.sge.addr));
                logger.log(LogLevel::ERROR, "- Size: " + std::to_string(wr.sge.length));
                logger.log(LogLevel::ERROR, "- RKey: " + std::to_string(wr.wr.wr.rdma.rkey));
                logger.log(LogLevel::ERROR, "- Error code: " + std::to_string(ret));
                logger.log(LogLevel::ERROR, "- Bad send WR data: " + std::string(bad_send_wr_data ? "not null" : "null"));
                logger.log(LogLevel::ERROR, "- QP index: " + std::to_string(Config::DEFAULT_QP_IDX));

                throw runtime_error("Failed to post write - updateRemoteReadIndex - code: " + to_string(ret));
            }

            outgoing_wrs[Config::DEFAULT_QP_IDX] += 1;
            int counter = outgoing_wrs[Config::DEFAULT_QP_IDX];
            if (counter >= Config::POLL_CQ_AFTER_WR)
            {
                pollCqSend(send_cqs[Config::DEFAULT_QP_IDX], counter);
                outgoing_wrs[Config::DEFAULT_QP_IDX] -= counter;
            }
        }
    }

    inline void RdmaContext::sendMsg(struct mmsghdr *msgs, int n_of_msg, int dest_fd)
    {
        int sent = 0;
        while (sent < n_of_msg)
        {
            int n = sendmmsg(dest_fd, &msgs[sent], n_of_msg - sent, MSG_NOSIGNAL | MSG_ZEROCOPY);
            if (n < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    // std::this_thread::yield();
                    logger.log(LogLevel::WARNING, "sendmmsg would block");
                    continue;
                }
                logger.log(LogLevel::ERROR, "sendmmsg failed");
                throw std::runtime_error("sendmmsg failed");
            }
            else if (n == 0)
            {
                throw std::runtime_error("sendmmsg sent 0 messages, socket closed?");
            }
            sent += n;
        }
    }

    int RdmaContext::readMsgLoop(int dest_fd, sock_id_t target_sk, const std::function<bool()> &is_valid)
    {
        if (!buffer_to_read)
            throw runtime_error("ringbuffer is nullptr - readMsg");

        struct mmsghdr msgs[Config::IOVS_BATCH_SIZE];
        struct iovec iovs[Config::IOVS_BATCH_SIZE];
        int idx_batch = 0;

        memset(msgs, 0, sizeof(msgs));
        memset(iovs, 0, sizeof(iovs));
        for (int i = 0; i < Config::IOVS_BATCH_SIZE; i++)
        {
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }

        auto flush = [&]
        {
            /*if (idx_batch != Config::IOVS_BATCH_SIZE)
                logger.log(LogLevel::DEBUG, "Flushing partial batch: " + std::to_string(idx_batch));*/
            sendMsg(msgs, idx_batch, dest_fd);
            buffer_to_read->local_read_index.fetch_add(idx_batch, std::memory_order_release);
            idx_batch = 0;
        };

        int c = 0;

        while (stop.load() == false)
        {
            for (size_t i = 0; i < Config::MAX_MSG_BUFFER;)
            {
                rdma_msg_t *msg;

                while (true)
                {
                    uint32_t sn = seq_number_read.load();
                    i = RING_IDX(sn - 1);
                    msg = &buffer_to_read->data[i];

                    if (stop.load() == true)
                        return 1; // stop the reading

                    if (idx_batch != 0)
                        flush();

                    if (!is_valid())
                    {
                        logger.log(LogLevel::DEBUG, "Socket not valid anymore, stopping readMsgLoop");
                        this_thread::sleep_for(std::chrono::milliseconds(100));
                        // Before to quit, flush the data not read yet
                        // TODO: this logic should be improved to avoid data loss
                        buffer_to_read->local_read_index.fetch_add(idx_batch, std::memory_order_release);
                        int k = 0;
                        for (int j = 0; j < Config::MAX_MSG_BUFFER; j++)
                        {
                            msg = &buffer_to_read->data[j];
                            if (sk::SocketMng::areSkEqual(msg->original_sk_id, target_sk) &&
                                (msg->msg_flags & static_cast<uint32_t>(MsgFlag::MSG_ALREADY_READ)) == 0)
                            {
                                msg->msg_flags |= static_cast<uint32_t>(MsgFlag::MSG_ALREADY_READ);
                                k++;
                            }
                        }
                        buffer_to_read->local_read_index.fetch_add(k, std::memory_order_release);
                        return 1;
                    }

                    if (msg->seq_number_tail != sn || msg->seq_number_head != sn)
                        continue;

                    if (sk::SocketMng::areSkEqual(msg->original_sk_id, target_sk))
                    {
                        seq_number_read.fetch_add(1);
                        break;
                    }
                }

                /*if (msg->msg_size != RdmaTestConf::MAX_PAYLOAD_SIZE)
                {
                    double perc = (double)msg->msg_size / (double)RdmaTestConf::MAX_PAYLOAD_SIZE * 100.0;
                    logger.log(LogLevel::DEBUG, "Received msg size: " + std::to_string(msg->msg_size) + " expected: " + std::to_string(RdmaTestConf::MAX_PAYLOAD_SIZE) + " - " + std::to_string(perc) + "%");
                }*/

                if (msg->msg_size == 0 || msg->number_of_slots != 1)
                    throw runtime_error("Invalid message received: " + to_string(msg->msg_size) + ", " + to_string(msg->number_of_slots));

                iovs[idx_batch].iov_base = msg->msg;
                iovs[idx_batch].iov_len = msg->msg_size;

                idx_batch++;

                msg->msg_flags |= static_cast<uint32_t>(MsgFlag::MSG_ALREADY_READ);

                if (idx_batch == Config::IOVS_BATCH_SIZE)
                    flush();

                i += msg->number_of_slots;
            }
        }

        return 0;
    }

    void RdmaContext::resetBuffer()
    {
        if (active_sockets.load() != 0)
            return;

        buffer_to_read->local_read_index.store(0);
        buffer_to_read->remote_read_index.store(0);
        buffer_to_write->local_write_index = 0;

        seq_number_read.store(1); // start from 1 (0 means empty)
        seq_number_write.store(1);

        rdma_msg_t *msg;
        for (int i = 0; i < Config::MAX_MSG_BUFFER; i++)
        {
            msg = &buffer_to_write->data[i];
            msg->seq_number_head = 0;
            msg->seq_number_tail = 0;
        }

        logger.log(LogLevel::INFO, "Ringbuffer flushed");
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

        logger.log(LogLevel::INFO, "Polling status updated: " + string(is_polling ? "ON" : "OFF"));
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
                logger.log(LogLevel::WARNING, "Interrupted while polling CQ, no completions found.");
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

    void RdmaContext::signalContextReady()
    {
        unique_lock<mutex> lock(mtx_ctx_ready);
        is_ready.store(true, std::memory_order_release);
        cond_ctx_ready.notify_all();
    }

    void RdmaContext::waitForContextToBeReady()
    {
        std::unique_lock<std::mutex> lock(mtx_ctx_ready);
        cond_ctx_ready.wait(lock, [&]()
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

}
