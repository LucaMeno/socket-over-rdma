
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

        logger.log(LogLevel::CONFIG, " RDMA port: " + std::to_string(rdma_port));
        logger.log(LogLevel::CONFIG, string(" RDMA TCP port: ") + Config::RDMA_TCP_PORT);
        logger.log(LogLevel::CONFIG, " Proxy port: " + std::to_string(Config::PROXY_PORT));
        logger.log(LogLevel::CONFIG, string(" Proxy IP: ") + Config::SERVER_IP);
        logger.log(LogLevel::CONFIG, " MAX_PAYLOAD_SIZE: " + std::to_string(Config::MAX_PAYLOAD_SIZE / 1024) + "kB");
        logger.log(LogLevel::CONFIG, " MAX_MSG_BUFFER: " + std::to_string(Config::MAX_MSG_BUFFER / 1024) + "k");
        logger.log(LogLevel::CONFIG, " N_WRITER_THREADS: " + std::to_string(Config::N_WRITER_THREADS));
        logger.log(LogLevel::CONFIG, " Q pairs: " + std::to_string(Config::QP_N));
        logger.log(LogLevel::CONFIG, " TIME_FLUSH_INTERVAL_NS: " + std::to_string(Config::FLUSH_INTERVAL_NS) + "ns");
        logger.log(LogLevel::CONFIG, " Target ports: ");
        ostringstream oss;
        for (const auto &port : Config::getTargetPorts())
            oss << port << " ";
        logger.log(LogLevel::CONFIG, "  " + oss.str());

        logger.log(LogLevel::CONFIG, "==================  END CONFIGURATION ==================");

        for (int i = 0; i < Config::NUMBER_OF_SOCKETS; i++)
        {
            int fd = sk_ctx.client_sk_fd[i].fd;
            fd_sk_asoc_map[fd] = {0};
        }
    }

    RdmaMng::~RdmaMng()
    {
        stop_threads.store(true, memory_order_release);

        // Cleanup RDMA contexts
        logger.log(LogLevel::CLEANUP, "Cleaning up RDMA contexts");
        ctxs.clear();
        logger.log(LogLevel::CLEANUP, "RDMA contexts cleared");

        for (auto &ctx : ctxs)
            ctx->stop.store(true);

        if (server_thread.joinable())
        {
            logger.log(LogLevel::CLEANUP, "Waiting for server thread to finish...");
            server_thread.join();
            logger.log(LogLevel::CLEANUP, "Server thread joined");
        }

        for (auto &thread : writer_threads)
            if (thread.joinable())
                thread.join();
        logger.log(LogLevel::CLEANUP, "Writer threads joined");

        if (notification_thread.joinable())
        {
            logger.log(LogLevel::CLEANUP, "Waiting for notification thread to finish...");
            notification_thread.join();
            logger.log(LogLevel::CLEANUP, "Notification thread joined");
        }

        // Notify all reader threads to exit
        wakeReaderThread();
        for (auto &thread : reader_threads)
            if (thread.joinable())
                thread.join();
        logger.log(LogLevel::CLEANUP, "Reader threads joined");

        logger.log(LogLevel::CLEANUP, "RdmaMng cleanup completed");

        // bpf and socket managers cleanup are handled in their destructors automatically
    }

    void RdmaMng::run()
    {
        logger.log(LogLevel::INIT, "Starting RdmaMng...");

        // start the server thread
        server_thread = thread(&RdmaMng::serverThread, this);
        pthread_setname_np(server_thread.native_handle(), "SrvThrd");

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
                        pthread_setname_np(pthread_self(), "WrtThrd");
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
                    pthread_setname_np(pthread_self(), "RdrThrd");
                    readerThread(ThreadContext(target_socket.sk_id, target_socket.fd));
                });
        }
    }

    void RdmaMng::serverThread()
    {
        try
        {
            logger.log(LogLevel::INFO, "Server thread started");

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
            logger.log(LogLevel::ERROR, "Exception in serverThread: " + std::string(e.what()));
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
                tc.ctx->active_sockets.fetch_add(1);
                logger.log(LogLevel::INFO, "RT: " + tc.toString());

                sock_id_t swapped_sk = {0};
                swapped_sk.sip = tc.app.dip;
                swapped_sk.dip = tc.app.sip;
                swapped_sk.sport = tc.app.dport;
                swapped_sk.dport = tc.app.sport;

                tc.ctx->readMsgLoop(tc.fd, swapped_sk, isValid);

                uint32_t prev = tc.ctx->active_sockets.fetch_sub(1);
                if (prev == 1)
                    tc.ctx->resetBuffer(); // flush any remaining data if this was the last active socket

                tc.ctx = nullptr; // reset the context to force re-fetching it
            }
        }
        catch (const std::exception &e)
        {
            logger.log(LogLevel::ERROR, "Exception in readerThread: " + std::string(e.what()));
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
            logger.log(LogLevel::ERROR, "Exception in writerThread: " + std::string(e.what()));
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
        pthread_setname_np(notification_thread.native_handle(), "NotificThrd");
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
            logger.log(LogLevel::INFO, "S: Received: " + ctx.getOpName(code) + " (" + std::to_string(static_cast<int>(code)) + ")");
        }
        else // client
        {
            code = notification->from_server.code;
            notification->from_server.code = rdma::CommunicationCode::NONE; // reset the code
            logger.log(LogLevel::INFO, "C: Received: " + ctx.getOpName(code) + " (" + std::to_string(static_cast<int>(code)) + ")");
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
            logger.log(LogLevel::WARNING, "Unknown notification code: " + std::to_string(static_cast<int>(code)));
            break;
        }
        }
    }

    void RdmaMng::listenThread()
    {
        try
        {
            logger.log(LogLevel::INFO, "Listening for notifications...");

            vector<int> fds_to_monitor;
            for (const auto &ctx_ptr : ctxs)
            {
                RdmaContext *ctx = ctx_ptr.get();
                if (!ctx->recv_cq || !ctx->comp_channel)
                {
                    logger.log(LogLevel::WARNING, "Context not ready, skipping");
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
                        logger.log(LogLevel::ERROR, "ibv_get_cq_event failed");
                        continue;
                    }

                    ibv_ack_cq_events(ev_cq, 1);

                    if (ibv_req_notify_cq(ctx->recv_cq, 0))
                    {
                        logger.log(LogLevel::ERROR, "ibv_req_notify_cq failed");
                        continue;
                    }

                    struct ibv_wc wc{};
                    int num_completions = ibv_poll_cq(ctx->recv_cq, 1, &wc);
                    if (num_completions < 0)
                    {
                        logger.log(LogLevel::ERROR, "Failed to poll CQ: " + std::string(strerror(errno)));
                        continue;
                    }

                    if (num_completions == 0)
                        continue;

                    if (wc.status != IBV_WC_SUCCESS)
                    {
                        logger.log(LogLevel::ERROR, "CQ error: " + std::string(ibv_wc_status_str(wc.status)));
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
            logger.log(LogLevel::ERROR, "Exception in listenThread: " + std::string(e.what()));
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