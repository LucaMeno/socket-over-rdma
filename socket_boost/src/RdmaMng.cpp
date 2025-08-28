
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

        cout << "==================  CONFIGURATION ==================" << endl;

        cout << "Configuration:" << endl;
        cout << " RDMA port: " << rdma_port << endl;
        cout << " RDMA TCP port: " << Config::RDMA_TCP_PORT << endl;
        cout << " Proxy port: " << Config::PROXY_PORT << endl;
        cout << " Proxy IP: " << Config::SERVER_IP << endl;
        cout << " MAX_PAYLOAD_SIZE: " << (Config::MAX_PAYLOAD_SIZE / 1024) << "kB" << endl;
        cout << " MAX_MSG_BUFFER: " << (Config::MAX_MSG_BUFFER / 1024) << "k" << endl;
        cout << " THRESHOLD: " << Config::THRESHOLD_NOT_AUTOSCALER << endl;
        cout << " N_WRITER_THREADS: " << Config::N_WRITER_THREADS << endl;
        cout << " N_THREAD_POOL_THREADS: " << Config::N_THREAD_POOL_THREADS << endl;
        cout << " Q pairs: " << Config::QP_N << endl;
        cout << " Target ports: ";
        for (const auto &port : Config::getTargetPorts())
            cout << port << " ";

        cout << endl
             << "=======================================================" << endl;
    }

    RdmaMng::~RdmaMng()
    {
        stop_threads.store(true, memory_order_release);

        for (auto &ctx : ctxs)
            ctx->stop.store(true);

        if (server_thread.joinable())
        {
            cout << "[Shutdown] Waiting for server thread to finish..." << endl;
            server_thread.join();
            cout << "[Shutdown] Server thread joined" << endl;
        }

        for (auto &thread : writer_threads)
        {
            if (thread.joinable())
                thread.join();
        }
        cout << "[Shutdown] Writer threads joined" << endl;

        if (notification_thread.joinable())
        {
            cout << "[Shutdown] Waiting for notification thread to finish..." << endl;
            notification_thread.join();
            cout << "[Shutdown] Notification thread joined" << endl;
        }

        // Cleanup RDMA contexts
        cout << "[Cleanup ] Clearing RDMA contexts..." << endl;
        ctxs.clear();
        cout << "[Cleanup ] RDMA contexts cleared" << endl;

        // bpf and socket managers cleanup are handled in their destructors automatically
    }

    void RdmaMng::run()
    {
        // start the server thread
        server_thread = thread(&RdmaMng::serverThread, this);
        cout << "Server th created" << endl;

        // start the writer threads
        const int per_thread = Config::NUMBER_OF_SOCKETS / Config::N_WRITER_THREADS;
        int leftover = Config::NUMBER_OF_SOCKETS % Config::N_WRITER_THREADS;

        std::size_t idx = 0;
        writer_threads.reserve(Config::N_WRITER_THREADS);

        for (int i = 0; i < Config::N_WRITER_THREADS; ++i)
        {
            int n_fd = per_thread + (leftover-- > 0 ? 1 : 0);

            // Slice the global - or externally supplied - client_sks array
            std::vector<sk::client_sk_t> sockets;
            sockets.reserve(n_fd);
            for (int k = 0; k < n_fd; ++k)
                sockets.push_back(sk_ctx.client_sk_fd[idx++]);

            // Launch the writer thread; capture *this and move the socket list in
            try
            {
                writer_threads.emplace_back(
                    [this, sockets = std::move(sockets)]() mutable
                    {
                        writerThread(std::move(sockets));
                    });
            }
            catch (const std::system_error &e)
            {
                throw std::runtime_error(
                    "Failed to create writer thread: " + std::string(e.what()));
            }
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

                ctxs.push_back(std::move(ctx));

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
        ctxs.push_back(make_unique<rdma::RdmaContext>(bpf_ctx, sk_ctx.client_sk_fd));
        return ctxs.size() - 1; // Return the index of the newly added context
    }

    WriterThreadData RdmaMng::populateWriterThreadData(std::vector<sk::client_sk_t> &sockets, int fd)
    {
        // Find the socket in the list of client sockets
        auto skIt = std::find_if(sockets.begin(), sockets.end(),
                                 [&](const auto &s)
                                 { return s.fd == fd; });

        if (skIt == sockets.end())
            throw std::runtime_error("Socket non trovato - populateWriterThreadData");

        // From the proxy socket, retrieve the app socket
        sock_id app = bpf_ctx.getAppSkFromProxySk(skIt->sk_id);

        // look for the context with the same remote IP
        auto ctxIt = std::find_if(ctxs.begin(), ctxs.end(),
                                  [&](const auto &c)
                                  { return c->remote_ip == app.dip; });

        if (ctxIt == ctxs.end())
            throw std::runtime_error("Context non trovato per IP: " + std::to_string(app.dip));

        rdma::RdmaContext *ctx = ctxIt->get();

        // Wait for the context to be ready
        ctx->waitForContextToBeReady();

        return WriterThreadData(app, ctx);
    }

    void RdmaMng::writerThread(vector<sk::client_sk_t> sk_to_monitor)
    {
        if (sk_to_monitor.empty())
            throw std::runtime_error("No sockets to monitor in writer thread");

        unordered_map<int, WriterThreadData> writer_map;

        int epoll_fd = epoll_create1(0);
        if (epoll_fd < 0)
            throw std::runtime_error("Failed to create epoll instance");

        for (const auto &sk : sk_to_monitor)
        {
            if (sk.fd < 0)
                throw std::runtime_error("Invalid socket fd in writer thread");

            struct epoll_event ev = {};
            ev.events = EPOLLIN; // interested in readable events
            ev.data.fd = sk.fd;

            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sk.fd, &ev) == -1)
                throw std::runtime_error("epoll_ctl failed for fd " + std::to_string(sk.fd));
        }

        const int MAX_EVENTS = 64;
        epoll_event events[MAX_EVENTS];

        try
        {
            while (!stop_threads.load())
            {
                int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, Config::TIME_STOP_SELECT_SEC * 1000);

                if (nfds == -1)
                {
                    if (errno == EINTR)
                        break;
                    throw std::runtime_error("epoll_wait failed");
                }

                if (stop_threads.load())
                    break;

                if (remove_sk_tx.load(std::memory_order_acquire))
                {
                    std::unique_lock<std::mutex> lock(mtx_sk_removal_tx);

                    for (auto it_fd = sk_to_remove_tx.begin(); it_fd != sk_to_remove_tx.end();)
                    {
                        int fd = *it_fd;

                        auto it = writer_map.find(fd);
                        if (it != writer_map.end())
                        {
                            writer_map.erase(it);
                            // cout << "Removed fd " << fd << " from writer_map" << endl;

                            // Remove FD from list since it was processed
                            it_fd = sk_to_remove_tx.erase(it_fd);
                        }
                        else
                        {
                            // Keep FD in list if it’s not in writer_map yet
                            ++it_fd;
                        }
                    }

                    if (sk_to_remove_tx.empty())
                        remove_sk_tx.store(false, std::memory_order_release);
                }

                for (int i = 0; i < nfds; ++i)
                {
                    int fd = events[i].data.fd;

                    WriterThreadData data;
                    auto it = writer_map.find(fd);
                    if (it == writer_map.end())
                    {
                        data = populateWriterThreadData(sk_to_monitor, fd);
                        it = writer_map.emplace(fd, std::move(data)).first;
                    }

                    WriterThreadData &writer_data = it->second;

                    // int ret = writer_data.ctx->readMsgFromSk(fd, writer_data.app);
                    int ret = writer_data.ctx->writeMsg(fd, writer_data.app);

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

    void RdmaMng::connect(struct sock_id original_socket, int proxy_sk_fd)
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