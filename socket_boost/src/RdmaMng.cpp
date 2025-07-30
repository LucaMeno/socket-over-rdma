
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

        // setup the pool
        thPool = make_unique<ThreadPool>(Config::N_THREAD_POOL_THREADS);

        // polling thread
        is_polling_thread_running = false;

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
        stop_threads = true;

        for (auto &ctx : ctxs)
            ctx->stop.store(true);

        if (server_thread.joinable())
        {
            cout << "Waiting for server thread to finish..." << endl;
            server_thread.join();
        }

        cout << "Server thread joined" << endl;

        for (auto &thread : writer_threads)
        {
            if (thread.joinable())
                thread.join();
        }

        cout << "Writer threads joined" << endl;

        if (notification_thread.joinable())
        {
            cout << "Waiting for notification thread to finish..." << endl;
            notification_thread.join();
        }

        cout << "Notification thread joined" << endl;

        if (is_polling_thread_running == false)
        {
            unique_lock<mutex> lock(mtx_polling);
            is_polling_thread_running = true;
            cond_polling.notify_all();
        }

        if (polling_thread.joinable())
        {
            cout << "Waiting for polling thread to finish..." << endl;
            polling_thread.join();
        }

        cout << "Polling thread joined" << endl;

        if (flush_thread.joinable())
        {
            cout << "Waiting for flush thread to finish..." << endl;
            flush_thread.join();
        }

        cout << "Flush thread joined" << endl;

        // Cleanup RDMA contexts
        ctxs.clear();
        cout << "RDMA contexts cleared" << endl;

        thPool->destroy();
        cout << "Thread pool destroyed" << endl;
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
                unique_ptr<rdma::RdmaContext> ctx = make_unique<rdma::RdmaContext>();

                serverConnection_t sc = ctx->serverSetup();

                int ready = 0;
                vector<int> fds = {sc.fd};
                while (stop_threads.load() == false && waitOnSelect(fds).empty())
                    ;

                if (stop_threads.load() == true)
                    return; // Exit if stop_threads is set

                ctx->serverHandleNewClient(sc);

                ctxs.push_back(std::move(ctx));

                if (!notification_thread.joinable())
                {
                    launchBackbroundThread();
                }
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
        ctxs.push_back(make_unique<rdma::RdmaContext>());
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

    inline bool has_data(int sockfd)
    {
        char buf[1];
        if (recv(sockfd, buf, sizeof(buf), MSG_PEEK) > 0)
            return true;
        return false;
    }

    void RdmaMng::writerThread(vector<sk::client_sk_t> sk_to_monitor)
    {
        if (sk_to_monitor.empty())
            throw std::runtime_error("No sockets to monitor in writer thread");

        for (const auto &sk : sk_to_monitor)
            if (sk.fd < 0)
                throw std::runtime_error("Invalid socket fd in writer thread");

        unordered_map<int, WriterThreadData> writer_map;

        try
        {
            uint32_t c = 0;
            while (!stop_threads)
            {
                for (int i = 0; i < sk_to_monitor.size(); ++i)
                {
                    int fd = sk_to_monitor[i].fd;

                    // check if there are some data
                    if (!has_data(fd))
                        continue; // No data to write, continue to the next socket

                    // populate the writer thread data
                    WriterThreadData data;
                    if (writer_map.find(fd) == writer_map.end())
                    {
                        // add the writer thread data
                        data = populateWriterThreadData(sk_to_monitor, fd);
                        writer_map[fd] = data;
                    }
                    else
                    {
                        data = writer_map[fd];
                    }

                    int ret = data.ctx->writeMsg(fd, data.app);

                    if (ret <= 0)
                    {
                        if (ret == 0)
                            throw runtime_error("Connection closed - writerThread");
                        else if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            if (++c % 1000 == 0)
                                cout << "No data - fd: " << fd << " count: " << c << endl;
                        }
                        else
                            throw runtime_error("Connection closed - writerThread " + to_string(errno));
                    }
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

    void RdmaMng::pollingThread()
    {
        try
        {
            cout << "Polling thread started" << endl;

            unique_lock<mutex> lock(mtx_polling);
            is_polling_thread_running = false;
            while (is_polling_thread_running == false && stop_threads.load() == false)
            {
                cout << "Waiting for polling thread to start..." << endl;
                cond_polling.wait(lock);
            }
            lock.unlock();

            auto ctxIt = ctxs.begin();

            cout << "Polling thread is running" << endl;

            while (stop_threads.load() == false)
            {
                auto &ctx = **ctxIt;
                int ret;
                try
                {
                    ret = consumeRingbuffer(ctx, ctx.is_server ? *ctx.ringbuffer_client : *ctx.ringbuffer_server);
                }
                catch (const std::exception &e)
                {
                    cerr << "Exception in pollingThread1: " << e.what() << endl;
                }
                if (ret < 0)
                {
                    throw runtime_error("Error consuming ring buffer - pollingThread");
                }
                else if (ret == 1)
                {
                    // no msg to read
                    // break;
                }

                ctxIt++;
                if (ctxIt == ctxs.end())
                    ctxIt = ctxs.begin(); // reset the iterator to the beginning
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in pollingThread2: " << e.what() << endl;
            perror("Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    int RdmaMng::consumeRingbuffer(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb_remote)
    {
        while (1)
        {
            uint32_t remote_w = rb_remote.remote_write_index.load();
            uint32_t local_r = rb_remote.local_read_index;

            if (remote_w != local_r)
            {
                // set the local read index to avoid reading the same data again
                uint32_t start_read_index = local_r;
                uint32_t end_read_index = remote_w;

                rb_remote.local_read_index = remote_w; // reset the local write index

                ctx.readMsg(bpf_ctx, sk_ctx.client_sk_fd, start_read_index, end_read_index);
                ctx.updateRemoteReadIndex(end_read_index);
            }
            else
            {
                return 1; // no messages to read
            }
        }
    }

    void RdmaMng::flushThreadWorker(rdma::RdmaContext &ctx)
    {
        try
        {
            ctx.flushWrQueue(); // Flush the work requests queue
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in flushThreadWorker: " << e.what() << endl;
            throw;
        }
    }

    void RdmaMng::launchBackbroundThread()
    {
        // Launch the notification thread
        notification_thread = thread(&RdmaMng::listenThread, this);

        // Launch the polling thread
        polling_thread = thread(&RdmaMng::pollingThread, this);

        // Launch the flush thread
        flush_thread = thread(&RdmaMng::flushThread, this);
    }

    void RdmaMng::connect(struct sock_id original_socket, int proxy_sk_fd)
    {
        rdma::RdmaContext *ctx = getContextByIp(original_socket.dip);

        if (ctx == nullptr) // no previus connection to the given node, create a new one
        {
            int ctx_id = getFreeContextId();
            auto ctx = ctxs[ctx_id].get();        // get the context by index
            ctx->remote_ip = original_socket.dip; // set the remote IP

            ctx->clientConnect(original_socket.dip, rdma_port);

            launchBackbroundThread();
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

        // wake up the polling thread
        unique_lock<mutex> lock(mtx_polling);
        is_polling_thread_running = true;
        cond_polling.notify_all();
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

            while (!stop_threads)
            {
                fd_set fds;
                FD_ZERO(&fds);
                int max_fd = -1;

                for (const auto &ctx_ptr : ctxs)
                {
                    RdmaContext *ctx = ctx_ptr.get();
                    if (!ctx->recv_cq || !ctx->comp_channel)
                    {
                        std::cerr << "Context not ready, skipping\n";
                        continue;
                    }

                    FD_SET(ctx->comp_channel->fd, &fds);
                    max_fd = std::max(max_fd, ctx->comp_channel->fd);
                }

                if (max_fd < 0)
                {
                    throw std::runtime_error("No valid contexts to monitor");
                }

                timeval tv{Config::TIME_STOP_SELECT_SEC, 0};

                int activity = select(max_fd + 1, &fds, nullptr, nullptr, &tv);
                if (activity == -1)
                {
                    if (errno == EINTR)
                    {
                        std::cout << "Select interrupted by signal\n";
                        break;
                    }
                    perror("select error");
                    break;
                }

                for (int fd = 0; fd <= max_fd; ++fd)
                {
                    if (!FD_ISSET(fd, &fds))
                        continue;

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
                    {
                        throw std::runtime_error("Context not found for fd");
                    }

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
                    ibv_sge sge{
                        .addr = reinterpret_cast<uintptr_t>(ctx->buffer),
                        .length = sizeof(notification_t),
                        .lkey = ctx->mr->lkey};

                    ibv_recv_wr recv_wr = {};
                    recv_wr.wr_id = 0;
                    recv_wr.sg_list = &sge;
                    recv_wr.num_sge = 1;
                    recv_wr.next = nullptr;

                    ibv_recv_wr *bad_wr = nullptr;
                    if (ctx->srq)
                    {
                        if (ibv_post_srq_recv(ctx->srq, &recv_wr, &bad_wr) != 0 || bad_wr)
                            throw std::runtime_error("Failed to post SRQ receive work request");
                    }
                    else
                    {
                        if (ibv_post_recv(ctx->qps[0], &recv_wr, &bad_wr) != 0 || bad_wr)
                            throw std::runtime_error("Failed to post receive work request");
                    }
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

    void RdmaMng::flushThread()
    {
        cout << "Flush thread started" << endl;

        while (stop_threads.load() == false)
        {
            auto ctxIt = ctxs.begin();
            for (; ctxIt != ctxs.end(); ++ctxIt)
            {
                auto &ctx = **ctxIt;
                if (ctx.is_ready.load() == false)
                {
                    // context is not ready, skip it
                    continue;
                }

                rdma_ringbuffer_t &rb = *((ctx.is_server == true) ? ctx.ringbuffer_server : ctx.ringbuffer_client);

                while (1)
                {
                    uint64_t now = ctx.getTimeMS();

                    if (ctx.shouldFlushWrQueue() ||
                        (now - ctx.last_flush_ms >= Config::FLUSH_INTERVAL_MS))
                    {
                        ctx.last_flush_ms = now;
                        thPool->enqueue([this, &ctx]()
                                        { flushThreadWorker(ctx); });
                        break;
                    }
                }
            }
        }

        cout << "Flush thread stopped" << endl;
    }

    vector<int> RdmaMng::waitOnSelect(const vector<int> &fds)
    {
        if (fds.empty())
            return {}; // Nothing to watch.

        fd_set read_set;
        FD_ZERO(&read_set);
        int ready = 0;

        while (stop_threads.load() == false)
        {
            int max_fd = -1;
            for (int fd : fds)
            {
                if (fd < 0)
                    continue; // Skip invalid entries.
                FD_SET(fd, &read_set);
                if (fd > max_fd)
                    max_fd = fd;
            }
            if (max_fd < 0)
                return {}; // No valid descriptors.

            // Prepare timeout.
            struct timeval tv;
            tv.tv_sec = Config::TIME_STOP_SELECT_SEC;
            tv.tv_usec = 0;

            int ready = ::select(max_fd + 1, &read_set, nullptr, nullptr, &tv);
            if (ready < 0)
                throw std::runtime_error("select() failed");
            else if (ready > 0)
                break; // Some file descriptors are ready.
        }

        std::vector<int> result;
        result.reserve(static_cast<std::size_t>(ready));

        for (int fd : fds)
            if (fd >= 0 && FD_ISSET(fd, &read_set))
                result.push_back(fd);

        return result;
    }
};