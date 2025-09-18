
#include "RdmaMng.h"

using namespace std;
using namespace rdma;

namespace rdmaMng
{
    RdmaMng::RdmaMng(uint16_t proxy_port, uint32_t proxy_ip, uint16_t rdma_port, const std::vector<uint16_t> &target_ports_to_set)
    {
        stop_threads.store(false);
        rdma_port = rdma_port;

        sk_ctx.init(proxy_port, proxy_ip);

        bpf::EventHandler handler = {
            .ctx = this,
            .handle_event = &RdmaMng::wrapper};
        bpf_ctx.init(handler, target_ports_to_set, proxy_port, sk_ctx.client_sk_fd);

        logger.log(LogLevel::CONFIG, "==================  CONFIGURATION ==================");

        cout << "Configuration:" << endl;
        cout << " RDMA port: " << rdma_port << endl;
        cout << " RDMA TCP port: " << Config::RDMA_TCP_PORT << endl;
        cout << " Proxy port: " << Config::PROXY_PORT << endl;
        cout << " Proxy IP: " << Config::SERVER_IP << endl;
        cout << " MAX_PAYLOAD_SIZE: " << (Config::MAX_PAYLOAD_SIZE / 1024) << "kB" << endl;
        cout << " MAX_MSG_BUFFER: " << (Config::MAX_MSG_BUFFER / 1024) << "k" << endl;
        cout << " N_WRITER_THREADS: " << Config::N_WRITER_THREADS << endl;
        cout << " Q pairs: " << Config::QP_N << endl;
        cout << " Target ports: ";
        for (const auto &port : Config::getTargetPorts())
            logger.log(LogLevel::CONFIG, "  " + std::to_string(port));

        logger.log(LogLevel::CONFIG, "=======================================================");

        for (int i = 0; i < Config::NUMBER_OF_SOCKETS; i++)
        {
            int fd = sk_ctx.client_sk_fd[i].fd;
            fd_sk_asoc_map[fd] = {0};
        }

        run();
    }

    RdmaMng::~RdmaMng()
    {
        stop_threads.store(true, memory_order_release);

        // Cleanup RDMA contexts
        cout << "[Cleanup ] -- Clearing RDMA contexts..." << endl;
        ctxs.clear();
        cout << "[Cleanup ] -- RDMA contexts cleared" << endl;

        for (auto &ctx : ctxs)
            ctx->stop.store(true);

        if (server_thread.joinable())
        {
            cout << "[Shutdown] -- Waiting for server thread to finish..." << endl;
            server_thread.join();
            cout << "[Shutdown] -- Server thread joined" << endl;
        }

        for (auto &thread : writer_threads)
            if (thread.joinable())
                thread.join();
        cout << "[Shutdown] Writer threads joined" << endl;

        if (notification_thread.joinable())
        {
            cout << "[Shutdown] Waiting for notification thread to finish..." << endl;
            notification_thread.join();
            cout << "[Shutdown] Notification thread joined" << endl;
        }

        // Notify all reader threads to exit
        wakeReaderThread();
        for (auto &thread : reader_threads)
            if (thread.joinable())
                thread.join();
        cout << "[Shutdown] Reader threads joined" << endl;

        cout << "[Cleanup ] RdmaMng cleanup completed" << endl;

        // bpf and socket managers cleanup are handled in their destructors automatically
    }

    int RdmaMng::bpfEventHandler(void *data, size_t len)
    {
        struct userspace_data_t *user_data = (struct userspace_data_t *)data;

        // Lambda for logging
        auto logSocketEvent = [this](const std::string &prefix,
                                     struct sock_id &app,
                                     struct sock_id &proxy,
                                     const std::string &role,
                                     int fd)
        {
            std::cout << prefix << " "
                      << sk::SocketMng::getPrintableSkId(app) << " <-> "
                      << sk::SocketMng::getPrintableSkId(proxy) << " - "
                      << role << " - fd: " << fd
                      << std::endl;
        };

        switch (user_data->event_type)
        {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        {
            // client side, connect the RDMA context
            connect(user_data->association.app);
            int fd = sk_ctx.getProxyFdFromSockid(user_data->association.proxy);
            logSocketEvent("NEW", user_data->association.app, user_data->association.proxy, "CLIENT", fd);
            setFdSkAssociation(fd, user_data->association.app);
            wakeReaderThread();
            break;
        }
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        {
            // server side, do not connect the RDMA context
            int fd = sk_ctx.getProxyFdFromSockid(user_data->association.proxy);
            logSocketEvent("NEW", user_data->association.app, user_data->association.proxy, "SERVER", fd);
            setFdSkAssociation(fd, user_data->association.app);
            wakeReaderThread();
            break;
        }
        case REMOVE_SOCKET:
        {
            int fd = sk_ctx.getProxyFdFromSockid(user_data->association.proxy);
            setFdSkAssociation(fd, {0});
            logSocketEvent("REMOVE", user_data->association.app, user_data->association.proxy, "ND", fd);
            break;
        }
        default:
            std::cerr << "Unknown event type: " << user_data->event_type << std::endl;
            return -1; // Unknown event type
        }

        return 0;
    }

    void RdmaMng::run()
    {
        // start the server thread
        server_thread = thread(&RdmaMng::serverThread, this);

        // start the writer threads
        const int per_thread = Config::NUMBER_OF_SOCKETS / Config::N_WRITER_THREADS;
        int leftover = Config::NUMBER_OF_SOCKETS % Config::N_WRITER_THREADS;

        std::size_t idx = 0;
        writer_threads.reserve(Config::N_WRITER_THREADS);

        for (int i = 0; i < Config::N_WRITER_THREADS; ++i)
        {
            int n_fd = per_thread + (leftover-- > 0 ? 1 : 0);

            // Slice the global - or externally supplied - client_sks array
            std::vector<ThreadContext> tcs;
            tcs.reserve(n_fd);
            for (int k = 0; k < n_fd; ++k)
            {
                auto csk = sk_ctx.client_sk_fd[idx++];
                tcs.push_back(ThreadContext(csk.sk_id, csk.fd));
            }

            // Launch the writer thread; capture *this and move the socket list in
            try
            {
                writer_threads.emplace_back(
                    [this, tcs = std::move(tcs)]() mutable
                    {
                        writerThread(std::move(tcs));
                    });
            }
            catch (const std::system_error &e)
            {
                throw std::runtime_error(
                    "Failed to create writer thread: " + std::string(e.what()));
            }
        }

        reader_threads.reserve(Config::N_READER_THREADS);
        for (int i = 0; i < Config::N_READER_THREADS; i++)
        {
            reader_threads.emplace_back(
                [this, target_socket = sk_ctx.client_sk_fd[i]]()
                {
                    readerThread(ThreadContext(target_socket.sk_id, target_socket.fd));
                });
        }
    }

    void RdmaMng::serverThread()
    {
        try
        {
            cout << "Server thread started" << endl;

            while (stop_threads.load() == false)
            {
                unique_ptr<rdma::RdmaContext> ctx = make_unique<rdma::RdmaContext>(bpf_ctx, sk_ctx.client_sk_fd);

                serverConnection_t sc = ctx->serverSetup();

                int ready = 0;
                vector<int> fds = {sc.fd};
                while (stop_threads.load() == false && waitOnSelect(fds).empty())
                    ;

                if (stop_threads.load() == true)
                    return; // Exit if stop_threads is set

                ctx->serverHandleNewClient(sc);

                {
                    std::scoped_lock lock(mtx_ctx_access);
                    ctxs.push_back(std::move(ctx));
                }

                launchBackgroundThreads();
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in serverThread: " << e.what() << endl;
            perror("Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    int RdmaMng::getFreeContextId()
    {
        scoped_lock lock(mtx_ctx_access);
        ctxs.push_back(make_unique<rdma::RdmaContext>(bpf_ctx, sk_ctx.client_sk_fd));
        return ctxs.size() - 1; // Return the index of the newly added context
    }

    void RdmaMng::setFdSkAssociation(int fd, sock_id_t sk_id)
    {
        if (fd < 0)
            throw std::runtime_error("Invalid fd in setFdSkAssociation");
        fd_sk_asoc_map[fd] = sk_id;
    }

    bool RdmaMng::isFdValid(int fd)
    {
        return sk::SocketMng::isSkIdValid(fd_sk_asoc_map[fd].load());
    }

    void RdmaMng::fillThreadContext(ThreadContext &tc)
    {
        if (tc.fd < 0 || !sk::SocketMng::isSkIdValid(tc.proxy))
            throw std::runtime_error("Invalid ThreadContext parameters - fillThreadContext");

        // From the proxy socket, retrieve the app socket
        tc.app = fd_sk_asoc_map[tc.fd].load();

        // look for the context with the same remote IP
        while (true)
        {
            tc.ctx = getContextByIp(tc.app.dip);
            if (tc.ctx != nullptr)
                break;
            if (stop_threads.load())
                return;
        }

        // Wait for the context to be ready
        tc.ctx->waitForContextToBeReady();
    }

    void RdmaMng::wakeReaderThread()
    {
        scoped_lock lock(mtx_reader_thread);
        cv_reader_thread.notify_all();
    }

    void RdmaMng::readerThread(ThreadContext tc)
    {
        auto isValid = [this, fd = tc.fd]() -> bool
        {
            return isFdValid(fd);
        };

        try
        {
            while (stop_threads.load() == false)
            {
                // wait for the socket to be assigned
                {
                    std::unique_lock<std::mutex> lock(mtx_reader_thread);
                    cv_reader_thread.wait(lock, [this, &tc, isValid]()
                                          { return isValid() || stop_threads.load(); });
                }

                if (stop_threads.load())
                    return;

                fillThreadContext(tc);
                cout << "[RT      ] -- RT started: " << tc.toString() << endl;

                sock_id_t swapped_sk = {0};
                swapped_sk.sip = tc.app.dip;
                swapped_sk.dip = tc.app.sip;
                swapped_sk.sport = tc.app.dport;
                swapped_sk.dport = tc.app.sport;

                tc.ctx->readMsgLoop(tc.fd, swapped_sk, isValid);
                tc.ctx = nullptr; // reset the context to force re-fetching it
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in readerThread: " << e.what() << endl;
            perror("Details");
        }
    }

    inline bool areSkEqual(const sock_id_t &sk1, const sock_id_t &sk2)
    {
        return std::memcmp(&sk1, &sk2, sizeof(sock_id_t)) == 0;
    }

    void RdmaMng::writerThread(vector<ThreadContext> tcs)
    {
        if (tcs.empty())
            throw std::runtime_error("No sockets to monitor in writer thread");

        unordered_map<int, ThreadContext> writer_map;
        vector<int> sk_fds;
        for (const auto &tc : tcs)
        {
            sk_fds.push_back(tc.fd);
            writer_map[tc.fd] = tc;
        }

        try
        {
            while (!stop_threads.load())
            {
                auto ready_fds = waitOnSelect(sk_fds);

                if (stop_threads.load())
                    break;

                for (int i = 0; i < ready_fds.size(); ++i)
                {
                    int fd = ready_fds[i];
                    sock_id_t sk_id;

                    while (true)
                    {
                        sk_id = fd_sk_asoc_map[fd].load();
                        if (sk::SocketMng::isSkIdValid(sk_id))
                            break;
                        if (stop_threads.load())
                            return;
                    }

                    if (!sk::SocketMng::areSkEqual(writer_map[fd].app, sk_id))
                    {
                        writer_map[fd].ctx = nullptr; // force re-fetching the context if the app socket changed
                        fillThreadContext(writer_map[fd]);
                    }

                    auto isValid = [this, fd]() -> bool
                    {
                        return isFdValid(fd);
                    };

                    int ret = writer_map[fd].ctx->writeMsg(fd, sk_id, isValid);

                    if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                        throw runtime_error("Connection closed - writerThread err: " + std::to_string(ret) + " errno: " + std::to_string(errno));
                }
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in writerThread: " << e.what() << endl;
            perror("   - Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    void RdmaMng::launchBackgroundThreads()
    {
        if (notification_thread.joinable())
        {
            return; // If the notification thread is already running, do not start it again
        }

        // Launch the notification thread
        notification_thread = thread(&RdmaMng::listenThread, this);
    }

    void RdmaMng::connect(struct sock_id original_socket)
    {
        rdma::RdmaContext *ctx = getContextByIp(original_socket.dip);

        if (ctx == nullptr) // no previous connection to the given node, create a new one
        {
            int ctx_id = getFreeContextId();
            auto ctx = ctxs[ctx_id].get();        // get the context by index
            ctx->remote_ip = original_socket.dip; // set the remote IP

            ctx->clientConnect(original_socket.dip, rdma_port);

            launchBackgroundThreads();
        }
    }

    rdma::RdmaContext *RdmaMng::getContextByIp(uint32_t remote_ip)
    {
        std::scoped_lock lock(mtx_ctx_access);
        for (auto &ctx : ctxs)
            if (ctx.get()->remote_ip == remote_ip)
                return ctx.get();
        return nullptr; // Context not found
    }

    void RdmaMng::startPolling(rdma::RdmaContext &ctx)
    {
        // Try to set polling status
        ctx.setPollingStatus(true);
    }

    void RdmaMng::stopPolling(rdma::RdmaContext &ctx)
    {
        // Try to set polling status
        ctx.setPollingStatus(false);
    }

    void RdmaMng::parseNotification(rdma::RdmaContext &ctx)
    {
        rdma::notification_t *notification = (rdma::notification_t *)ctx.buffer;
        rdma::CommunicationCode code; // enum rdma_communication_code
        if (ctx.is_server == true)
        {
            code = notification->from_client.code;
            notification->from_client.code = rdma::CommunicationCode::NONE; // reset the code
            cout << "S: Received: " << ctx.getOpName(code) << " (" << static_cast<int>(code) << ")" << endl;
        }
        else // client
        {
            code = notification->from_server.code;
            notification->from_server.code = rdma::CommunicationCode::NONE; // reset the code
            cout << "C: Received: " << ctx.getOpName(code) << " (" << static_cast<int>(code) << ")" << endl;
        }

        switch (code)
        {
        case CommunicationCode::RDMA_DATA_READY:
        {
            startPolling(ctx);
            break;
        }

        default:
        {
            cout << "Unknown notification code: " << static_cast<int>(code) << endl;
            break;
        }
        }
    }

    void RdmaMng::listenThread()
    {
        try
        {
            std::cout << "Listening for notifications..." << std::endl;

            vector<int> fds_to_monitor;
            for (const auto &ctx_ptr : ctxs)
            {
                RdmaContext *ctx = ctx_ptr.get();
                if (!ctx->recv_cq || !ctx->comp_channel)
                {
                    std::cerr << "Context not ready, skipping\n";
                    continue;
                }
                fds_to_monitor.push_back(ctx->comp_channel->fd);
            }

            while (!stop_threads)
            {
                vector<int> fd_ready = waitOnSelect(fds_to_monitor);

                for (int fd : fd_ready)
                {
                    RdmaContext *ctx = nullptr;
                    for (const auto &c : ctxs)
                    {
                        if (c->comp_channel && c->comp_channel->fd == fd)
                        {
                            ctx = c.get();
                            break;
                        }
                    }

                    if (!ctx)
                        throw std::runtime_error("Context not found for fd");

                    struct ibv_cq *ev_cq = nullptr;
                    void *ev_ctx = nullptr;
                    if (ibv_get_cq_event(ctx->comp_channel, &ev_cq, &ev_ctx))
                    {
                        perror("ibv_get_cq_event");
                        continue;
                    }

                    ibv_ack_cq_events(ev_cq, 1);

                    if (ibv_req_notify_cq(ctx->recv_cq, 0))
                    {
                        perror("ibv_req_notify_cq");
                        continue;
                    }

                    struct ibv_wc wc{};
                    int num_completions = ibv_poll_cq(ctx->recv_cq, 1, &wc);
                    if (num_completions < 0)
                    {
                        std::cerr << "Failed to poll CQ: " << strerror(errno) << std::endl;
                        continue;
                    }

                    if (num_completions == 0)
                        continue;

                    if (wc.status != IBV_WC_SUCCESS)
                    {
                        std::cerr << "CQ error: " << ibv_wc_status_str(wc.status) << "\n";
                        continue;
                    }

                    // Repost receive
                    ctx->postReceive(Config::DEFAULT_QP_IDX, false);
                    parseNotification(*ctx);
                }
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in listenThread: " << e.what() << endl;
            perror("Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    vector<int> RdmaMng::waitOnSelect(const vector<int> &fds)
    {
        if (fds.empty())
            return {}; // Nothing to watch.

        // Create epoll instance
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1)
            throw std::runtime_error("epoll_create1() failed");

        // Register all fds
        for (int fd : fds)
        {
            if (fd < 0)
                continue;

            struct epoll_event ev = {};
            ev.events = EPOLLIN;
            ev.data.fd = fd;

            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1)
                throw std::runtime_error("epoll_ctl failed for fd " + std::to_string(fd));
        }

        std::vector<int> result;
        const int MAX_EVENTS = 256;
        struct epoll_event events[MAX_EVENTS];

        while (!stop_threads.load())
        {
            int timeout_ms = Config::TIME_STOP_SELECT_SEC * 1000;
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout_ms);

            if (nfds < 0)
            {
                throw std::runtime_error("epoll_wait() failed");
            }
            else if (nfds > 0)
            {
                result.reserve(nfds);
                for (int i = 0; i < nfds; ++i)
                    result.push_back(events[i].data.fd);
                break;
            }

            // If timeout with 0 fds, loop again (or exit on stop_threads)
        }

        close(epoll_fd);
        return result;
    }
};