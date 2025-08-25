
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

        reader_th_workers.reserve(Config::N_READER_THREADS);

        if (Config::N_READER_THREADS != Config::NUMBER_OF_SOCKETS)
            throw runtime_error("N_READER_THREADS must be equal to NUMBER_OF_SOCKETS - at least for now...");

        sock_id_t temp = {0};
        for (int i = 0; i < Config::N_READER_THREADS; ++i)
        {
            readThParams[i].keep_run.store(false);
            readThParams[i].dest_fd = sk_ctx.client_sk_fd[i].fd;
            readThParams[i].proxy_sk = sk_ctx.client_sk_fd[i].sk_id;
            readThParams[i].app_sk = temp;

            reader_th_workers.emplace_back(&RdmaMng::readThreadWorker, this, ref(readThParams[i]));
        }

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

        if (flush_thread.joinable())
        {
            cout << "[Shutdown] Waiting for flush thread to finish..." << endl;
            flush_thread.join();
            cout << "[Shutdown] Flush thread joined" << endl;
        }

        cout << "[Cleanup ] Destroying reader masters..." << endl;
        for (auto &m : reader_th_master)
            if (m.joinable())
                m.join();
        cout << "[Cleanup ] reader masters destroyed" << endl;

        cout << "[Cleanup ] Clearing RDMA contexts..." << endl;
        ctxs.clear();
        cout << "[Cleanup ] RDMA contexts cleared" << endl;

        cout << "[Cleanup ] Destroying reader workers..." << endl;
        unique_lock<mutex> lock(mtx_wait_for_sk);
        cond_wait_for_sk.notify_all();
        lock.unlock();
        for (auto &worker : reader_th_workers)
            if (worker.joinable())
                worker.join();
        cout << "[Cleanup ] reader workers destroyed" << endl;

        cout << "[Cleanup ] Destroying thread pool..." << endl;
        thPool->destroy();
        cout << "[Cleanup ] Thread pool destroyed" << endl;

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
                unique_ptr<rdma::RdmaContext> ctx = make_unique<rdma::RdmaContext>();

                serverConnection_t sc = ctx->serverSetup();

                int ready = 0;
                vector<int> fds = {sc.fd};
                while (stop_threads.load() == false && waitOnSelect(fds).empty())
                    ;

                if (stop_threads.load() == true)
                    return; // Exit if stop_threads is set

                ctx->serverHandleNewClient(sc);

                unique_lock<mutex> lock(mtx_ctxs);
                ctxs.push_back(std::move(ctx));
                lock.unlock();

                launchBackgroundThreads(*ctxs.back());
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
        unique_lock<mutex> lock(mtx_ctxs);
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
            perror(" Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    inline bool areSkEqual(const sock_id_t &sk1, const sock_id_t &sk2)
    {
        return std::memcmp(&sk1, &sk2, sizeof(sock_id_t)) == 0;
    }

    void RdmaMng::onSocketOpen(sock_id_t proxy_sk, sock_id_t app_sk)
    {
        launchReaderThWorker(proxy_sk, app_sk);
    }

    void RdmaMng::onSocketClose(sock_id_t proxy_sk, sock_id_t app_sk)
    {
        for (int i = 0; i < Config::N_READER_THREADS; i++)
        {
            if (areSkEqual(readThParams[i].proxy_sk, proxy_sk))
            {
                readThParams[i].keep_run.store(false);
                return;
            }
        }
        throw runtime_error("No matching reader thread found for proxy socket - onSocketClose");
    }

    void RdmaMng::launchReaderThWorker(sock_id_t proxy_sk, sock_id_t app_sk)
    {
        for (int i = 0; i < Config::N_READER_THREADS; i++)
        {
            // lookup for the correct thread
            if (areSkEqual(readThParams[i].proxy_sk, proxy_sk))
            {
                if (readThParams[i].keep_run.load())
                    throw runtime_error("Reader thread is already running - launchReaderThWorker");

                readThParams[i].keep_run.store(true);
                readThParams[i].app_sk = app_sk;

                // wake up the thread
                unique_lock<mutex> lock(mtx_wait_for_sk);
                cond_wait_for_sk.notify_all();

                return;
            }
        }

        throw runtime_error("No available reader thread parameters - launchReaderThWorker");
    }

    void RdmaMng::launchReaderThMaster(rdma::RdmaContext &ctx)
    {
        ctx.waitForContextToBeReady();
        // If the context is not already running a master thread
        if (ctx.is_readTh_master_running.load() == false)
        {
            ctx.is_readTh_master_running.store(true);
            reader_th_master.emplace_back(&RdmaMng::readThreadMaster, this, ref(ctx));
        }
    }

    void RdmaMng::readThreadWorker(ReaderThreadData &params)
    {
        try
        {
        backToWait:
            RdmaContext *ctx = nullptr;

            unique_lock<mutex> lock(mtx_wait_for_sk);
            cond_wait_for_sk.wait(lock, [&params, this]
                                  { return params.keep_run.load() == true || stop_threads.load() == true; });
            lock.unlock();

            if (stop_threads.load())
                return; // Exit if stop_threads is set

            // the thread is awakened
            // first retrive the app sk starting from the proxy one
            uint32_t remote_ip = params.app_sk.dip;

            // it have to find out to which context has been assigned
            while (stop_threads.load() == false && params.keep_run.load() == true)
            {
                ctx = getContextByIp(remote_ip);
                if (ctx != nullptr)
                    break;
            }

            ctx->waitForContextToBeReady();
            ctx->tot_r_thread.fetch_add(1);

            if (stop_threads.load())
                return; // Exit if stop_threads is set

            // cout << "Reader Worker: " << sk_ctx.get_printable_sockid(&params.proxy_sk) << " to " << sk_ctx.get_printable_sockid(&params.app_sk) << " fd: " << params.dest_fd << endl;

            auto shouldStop = [&ctx, &params, this]()
            {
                return ctx->stop.load() == true ||
                       params.keep_run.load() == false ||
                       stop_threads.load() == true;
            };

            // reverse the app sk for reading
            struct sock_id swapped;
            swapped.dip = params.app_sk.sip;
            swapped.sip = params.app_sk.dip;
            swapped.dport = params.app_sk.sport;
            swapped.sport = params.app_sk.dport;

            params.app_sk = swapped;

            while (!shouldStop())
            {
                uint32_t end_idx = ctx->end_read_idx.load();
                uint32_t start_idx = ctx->start_read_idx.load();

                if (start_idx != end_idx)
                {
                    try
                    {
                        ctx->readMsg(start_idx, end_idx, params.app_sk, params.dest_fd);
                    }
                    catch (const std::exception &e)
                    {
                        cerr << "Exception in readThreadWorker: " << e.what() << endl;
                        perror("Details");
                    }

                    ctx->reading_th_ready_for_commit.fetch_add(1);
                }

                // wait for new data to consume
                // unique_lock<mutex> lock(ctx->mtx_data_to_consume);
                while (ctx->end_read_idx.load() == end_idx && !shouldStop())
                    ;
                /*ctx->cv_data_to_consume.wait(lock, [&ctx, shouldStop, end_idx]
                                             { return ctx->end_read_idx.load() != end_idx || shouldStop(); });*/
                // lock.unlock();
            }

            // if here means that the thread is done processing
            ctx->tot_r_thread.fetch_sub(1);
            ctx->reading_th_ready_for_commit.fetch_add(1);
            if (ctx->stop.load() == false &&
                stop_threads.load() == false &&
                params.keep_run.load() == false)
            {
                sock_id_t tmp = {0};
                params.app_sk = tmp; // reset the app socket
                // cout << "Reader Worker CLOSED: " << sk_ctx.get_printable_sockid(&params.proxy_sk) << " to " << sk_ctx.get_printable_sockid(&params.app_sk) << " fd: " << params.dest_fd << endl;

                goto backToWait;
            }
            // else -> exit
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in readThreadWorker: " << e.what() << endl;
            perror("Details");
        }
    }

    void RdmaMng::readThreadMaster(rdma::RdmaContext &ctx)
    {
        auto shouldStop = [&ctx, this]()
        {
            return ctx.stop.load() == true || stop_threads.load() == true;
        };

        // Master thread logic for reading
        // there is one master reader thread per context
        while (!shouldStop())
        {
            uint32_t start_idx = ctx.buffer_to_read->local_read_index;
            uint32_t end_idx = ctx.buffer_to_read->remote_write_index.load();

            if (start_idx == end_idx)
                continue;

            // wake the thread
            // unique_lock<mutex> lock(ctx.mtx_data_to_consume);
            ctx.reading_th_ready_for_commit.store(0);
            ctx.start_read_idx.store(start_idx);
            ctx.end_read_idx.store(end_idx);

            /*ctx.cv_data_to_consume.notify_all();
            lock.unlock();*/

            // wait for the threads
            while (ctx.reading_th_ready_for_commit.load() < ctx.tot_r_thread.load() && !shouldStop())
                ;

            if (shouldStop())
                break;

            // now all the data has been consumed
            ctx.buffer_to_read->local_read_index = end_idx;
            ctx.buffer_to_read->remote_read_index.store(end_idx);

            thPool->enqueue(
                &RdmaMng::updateRemoteReadIdxWorker, this, ref(ctx));
        }
    }

    void RdmaMng::updateRemoteReadIdxWorker(rdma::RdmaContext &ctx)
    {
        try
        {
            ctx.updateRemoteReadIndex();
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in updateRemoteReadIdxWorker: " << e.what() << endl;
            perror("Details");
        }
    }

    void RdmaMng::flushThreadWorker(rdma::RdmaContext &ctx, bool updateRemoteIndex)
    {
        try
        {
            ctx.flushWrQueue();
            if (updateRemoteIndex)
                ctx.updateRemoteWriteIndex();
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in flushThreadWorker: " << e.what() << endl;
            perror("Details");
        }
    }

    void RdmaMng::launchBackgroundThreads(RdmaContext &ctx)
    {
        launchReaderThMaster(ctx);

        if (notification_thread.joinable())
        {
            return; // If the notification thread is already running, do not start it again
        }

        // Launch the notification thread
        notification_thread = thread(&RdmaMng::listenThread, this);

        // Launch the flush thread
        flush_thread = thread(&RdmaMng::flushThread, this);
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

            launchBackgroundThreads(*ctx);
        }
    }

    rdma::RdmaContext *RdmaMng::getContextByIp(uint32_t remote_ip)
    {
        unique_lock<mutex> lock(mtx_ctxs);
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

    void RdmaMng::flushThread()
    {
        cout << "[Debug] -- Flush thread started" << endl;

        while (stop_threads.load() == false)
        {
            auto ctxIt = ctxs.begin();
            for (; ctxIt != ctxs.end(); ++ctxIt)
            {
                auto &ctx = **ctxIt;
                if (ctx.is_ready.load() == false)
                    continue; // context is not ready, skip it

                uint64_t now = ctx.getTimeMS();

                if (ctx.shouldFlushWrQueue())
                {
                    ctx.last_flush_ms = now;
                    ctx.number_of_flushes++;

                    bool updateIndex = false;
                    if (ctx.number_of_flushes >= Config::N_OF_FLUSHES_BEFORE_UPDATE_INDEX)
                    {
                        updateIndex = true;
                        ctx.number_of_flushes = 0;
                    }

                    thPool->enqueue([this, &ctx, updateIndex]()
                                    { flushThreadWorker(ctx, updateIndex); });
                    break;
                }
                else if (now - ctx.last_flush_ms >= Config::FLUSH_INTERVAL_MS)
                {
                    ctx.last_flush_ms = now;
                    ctx.number_of_flushes = 0;
                    thPool->enqueue([this, &ctx]()
                                    { flushThreadWorker(ctx, true); });
                    break;
                }
            }
        }

        cout << "[Shutdown] Flush thread stopped" << endl;
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