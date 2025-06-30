
#include "RdmaMng.h"

using namespace std;
using namespace rdma;

namespace rdmaMng
{
    RdmaMng::RdmaMng(uint16_t srv_port, vector<sk::client_sk_t> &proxy_sks, bpf::BpfMng &bpf) : bpf_ctx{bpf},
                                                                                                rdma_port{srv_port},
                                                                                                client_sks{proxy_sks}
    {
        stop_threads.store(false);

        // setup the pool
        thPool = make_unique<ThreadPool>(N_WRITER_THREADS);

        // polling thread
        is_polling_thread_running = false;
        cout << "Configuration:" << endl;
        cout << " RDMA port: " << rdma_port << endl;
        cout << " MAX_PAYLOAD_SIZE: " << (MAX_PAYLOAD_SIZE / 1024) << "kB" << endl;
        cout << " MAX_MSG_BUFFER: " << (MAX_MSG_BUFFER / 1024) << "k" << endl;
        cout << " THRESHOLD: " << THRESHOLD_NOT_AUTOSCALER << endl;
        cout << " N_WRITER_THREADS: " << N_WRITER_THREADS << endl;
        cout << " Port used for RDMA: " << rdma_port << endl;
    }

    RdmaMng::~RdmaMng()
    {
        stop_threads = true;

        if (server_thread.joinable())
            server_thread.join();

        cout << "Server thread joined" << endl;

        for (auto &thread : writer_threads)
        {
            if (thread.joinable())
                thread.join();
        }

        cout << "Writer threads joined" << endl;

        if (notification_thread.joinable())
            notification_thread.join();

        cout << "Notification thread joined" << endl;

        if (is_polling_thread_running == false)
        {
            unique_lock<mutex> lock(mtx_polling);
            is_polling_thread_running = true;
            cond_polling.notify_all();
        }

        if (polling_thread.joinable())
            polling_thread.join();

        cout << "Polling thread joined" << endl;

        if (flush_thread.joinable())
            flush_thread.join();

        cout << "Flush thread joined" << endl;

        // Cleanup RDMA contexts
        ctxs.clear();
        cout << "RDMA contexts cleared" << endl;

        thPool->destroy();
        cout << "Thread pool destroyed" << endl;
    }

    void RdmaMng::rdma_manager_run()
    {
        // start the server thread
        server_thread = thread(&RdmaMng::rdma_manager_server_thread, this);
        cout << "Server th created" << endl;

        // start the writer threads
        const int per_thread = NUMBER_OF_SOCKETS / N_WRITER_THREADS;
        int leftover = NUMBER_OF_SOCKETS % N_WRITER_THREADS;

        std::size_t idx = 0;
        writer_threads.reserve(N_WRITER_THREADS);

        for (int i = 0; i < N_WRITER_THREADS; ++i)
        {
            int n_fd = per_thread + (leftover-- > 0 ? 1 : 0);

            // Slice the global - or externally supplied - client_sks array
            std::vector<sk::client_sk_t> sockets;
            sockets.reserve(n_fd);
            for (int k = 0; k < n_fd; ++k)
                sockets.push_back(client_sks[idx++]);

            // Launch the writer thread; capture *this and move the socket list in
            try
            {
                writer_threads.emplace_back(
                    [this, sockets = std::move(sockets)]() mutable
                    {
                        rdma_manager_writer_thread(std::move(sockets));
                    });
            }
            catch (const std::system_error &e)
            {
                throw std::runtime_error(
                    "Failed to create writer thread: " + std::string(e.what()));
            }
        }
    }

    void RdmaMng::rdma_manager_server_thread()
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

            ctx->serverHandleNewClient(sc);

            ctxs.push_back(std::move(ctx));

            if (!notification_thread.joinable())
            {
                rdma_manager_launch_background_threads();
            }
        }
    }

    int RdmaMng::rdma_manager_get_free_context_id()
    {
        ctxs.push_back(make_unique<rdma::RdmaContext>());
        return ctxs.size() - 1; // Return the index of the newly added context
    }

    void RdmaMng::rdma_manager_writer_thread(vector<sk::client_sk_t> sk_to_monitor)
    {
        if (sk_to_monitor.empty())
        {
            cout << "No sockets to monitor in writer thread" << endl;
            return;
        }

        fd_set read_fds, temp_fds;
        ssize_t bytes_received;

        // Initialize the file descriptor set
        FD_ZERO(&read_fds);

        int max_fd = -1;

        for (int i = 0; i < sk_to_monitor.size(); i++)
        {
            if (sk_to_monitor[i].fd >= 0)
            {
                FD_SET(sk_to_monitor[i].fd, &read_fds);
                if (sk_to_monitor[i].fd > max_fd)
                    max_fd = sk_to_monitor[i].fd;
            }
        }

        if (max_fd < 0)
        {
            cout << "No valid sockets to monitor in writer thread" << endl;
            return;
        }

        int k = 1;
        while (atomic_load(&stop_threads) == false)
        {
            temp_fds = read_fds;

            struct timeval tv;
            tv.tv_sec = TIME_STOP_SELECT_SEC;
            tv.tv_usec = 0;

            int activity = select(max_fd + 1, &temp_fds, nullptr, nullptr, &tv);
            if (activity == -1)
            {
                if (errno == EINTR)
                {
                    cout << "Select interrupted by signal in writer_thread" << endl;
                    break;
                }
                perror("select error");
                break;
            }
            else if (stop_threads == true)
            {
                break; // stop the thread if stop_threads is set
            }

            // Handle data on client sockets
            for (int fd = 0; fd <= max_fd; fd++)
            {
                if (FD_ISSET(fd, &temp_fds))
                {
                    //  retrieve the proxy socket id
                    int j = 0;
                    for (; j < sk_to_monitor.size(); j++)
                        if (sk_to_monitor[j].fd == fd)
                            break;
                    if (j == sk_to_monitor.size())
                    {
                        cout << "Socket not found in the list - writer_thread" << endl;
                        continue;
                    }

                    struct sock_id app = bpf_ctx.get_app_sk_from_proxy_sk(sk_to_monitor[j].sk_id);
                    if (app.sip == 0)
                    {
                        cout << "No app socket found for fd: " << fd << endl;
                        FD_CLR(fd, &read_fds);
                        continue;
                    }

                    // get the context
                    auto ctxIt = ctxs.begin();
                    for (; ctxIt != ctxs.end(); ++ctxIt)
                        if ((*ctxIt)->remote_ip == app.dip)
                            break; // found the context for this fd

                    if (ctxIt == ctxs.end())
                    {
                        cout << "Context not found - writer_thread" << endl;
                        continue; // no context for this IP
                    }

                    auto &ctx = **ctxIt;

                    // Wait for the context to be ready
                    ctx.wait_for_context_ready();

                    while (1)
                    {
                        int ret = ctx.rdma_write_msg(fd, app);

                        if (ret == 0)
                        {
                            cout << "0" << endl;
                            throw runtime_error("Connection closed - rdma_manager_writer_thread");
                        }
                        else if (ret < 0)
                        {
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                            {
                                break;
                            }
                            else
                            {
                                cerr << "recv error" << endl;
                                perror("recv error");
                                throw runtime_error("Connection closed - rdma_manager_writer_thread");
                            }
                        }
                    }
                }
            }
        }
    }

    void RdmaMng::rdma_manager_polling_thread()
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
                ret = rdma_manager_consume_ringbuffer(ctx, ctx.is_server ? *ctx.ringbuffer_client : *ctx.ringbuffer_server);
            }
            catch (const std::exception &e)
            {
                cerr << "Exception in rdma_manager_polling_thread: " << e.what() << endl;
            }
            if (ret < 0)
            {
                throw runtime_error("Error consuming ring buffer - rdma_manager_polling_thread");
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

    int RdmaMng::rdma_manager_consume_ringbuffer(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb_remote)
    {
        while (1)
        {
            uint32_t remote_w = rb_remote.remote_write_index.load(); // atomic_load(&rb_remote->remote_write_index);
            uint32_t local_r = rb_remote.local_read_index.load();    // atomic_load(&rb_remote->local_read_index);

            if (remote_w != local_r)
            {
                // set the local read index to avoid reading the same data again
                uint32_t start_read_index = local_r;
                uint32_t end_read_index = remote_w;

                rb_remote.local_read_index.store(remote_w); // reset the local write index

                ctx.rdma_read_msg(bpf_ctx, client_sks, start_read_index, end_read_index);
                ctx.rdma_update_remote_read_idx(rb_remote, end_read_index);
            }
            else
            {
                return 1; // no messages to read
            }
        }
    }

    void RdmaMng::rdma_manager_flush_buffer(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb)
    {
        uint32_t start_idx = rb.local_read_index.load();
        uint32_t end_idx = rb.local_write_index.load();

        thPool->enqueue([this, &ctx, &rb, start_idx, end_idx]()
                        { flush_thread_worker(ctx, rb, start_idx, end_idx); });

        rb.local_read_index.store(rb.local_write_index.load());

        ctx.last_flush_ms = ctx.get_time_ms();
    }

    void RdmaMng::flush_thread_worker(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb, uint32_t start_idx, uint32_t end_idx)
    {
        ctx.rdma_flush_buffer(rb, start_idx, end_idx);
    }

    void RdmaMng::rdma_manager_launch_background_threads()
    {
        // Launch the notification thread
        notification_thread = thread(&RdmaMng::rdma_manager_listen_thread, this);

        // Launch the polling thread
        polling_thread = thread(&RdmaMng::rdma_manager_polling_thread, this);

        // Launch the flush thread
        flush_thread = thread(&RdmaMng::rdma_manager_flush_thread, this);
    }

    void RdmaMng::rdma_manager_connect(struct sock_id original_socket, int proxy_sk_fd)
    {
        rdma::RdmaContext *ctx = rdma_manager_get_context_by_ip(original_socket.dip);

        if (ctx == nullptr) // no previus connection to the given node, create a new one
        {
            int ctx_id = rdma_manager_get_free_context_id();
            auto ctx = ctxs[ctx_id].get();        // get the context by index
            ctx->remote_ip = original_socket.dip; // set the remote IP

            ctx->clientConnect(original_socket.dip, rdma_port);

            rdma_manager_launch_background_threads();
        }
    }

    rdma::RdmaContext *RdmaMng::rdma_manager_get_context_by_ip(uint32_t remote_ip)
    {
        for (auto &ctx : ctxs)
            if (ctx.get()->remote_ip == remote_ip)
                return ctx.get();
        return nullptr; // Context not found
    }

    void RdmaMng::rdma_manager_start_polling(rdma::RdmaContext &ctx)
    {
        // Try to set polling status
        ctx.rdma_set_polling_status(TRUE);

        // wake up the polling thread
        unique_lock<mutex> lock(mtx_polling);
        is_polling_thread_running = true;
        ctx.time_start_polling = ctx.get_time_ms();
        ctx.loop_with_no_msg = 0;
        cond_polling.notify_all();
    }

    void RdmaMng::rdma_manager_stop_polling(rdma::RdmaContext &ctx)
    {
        // Try to set polling status
        ctx.rdma_set_polling_status(FALSE);
    }

    void RdmaMng::rdma_parse_notification(rdma::RdmaContext &ctx)
    {
        rdma::notification_t *notification = (rdma::notification_t *)ctx.buffer;
        rdma::CommunicationCode code; // enum rdma_communication_code
        if (ctx.is_server == true)
        {
            code = notification->from_client.code;
            notification->from_client.code = rdma::CommunicationCode::NONE; // reset the code
            cout << "S: Received: " << ctx.get_op_name(code) << " (" << static_cast<int>(code) << ")" << endl;
        }
        else // client
        {
            code = notification->from_server.code;
            notification->from_server.code = rdma::CommunicationCode::NONE; // reset the code
            cout << "C: Received: " << ctx.get_op_name(code) << " (" << static_cast<int>(code) << ")" << endl;
        }

        switch (code)
        {
        case CommunicationCode::RDMA_DATA_READY:
        {
            rdma_manager_start_polling(ctx);
            break;
        }

        default:
        {
            cout << "Unknown notification code: " << static_cast<int>(code) << endl;
            break;
        }
        }
    }

    void RdmaMng::rdma_manager_listen_thread()
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

            timeval tv{TIME_STOP_SELECT_SEC, 0};

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
                if (ibv_post_recv(ctx->qp, &recv_wr, &bad_wr) != 0 || bad_wr)
                {
                    std::cerr << "Error posting recv: " << strerror(errno) << "\n";
                    break;
                }

                rdma_parse_notification(*ctx);
            }
        }
    }

    void RdmaMng::rdma_manager_flush_thread()
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

                uint32_t msg_sent = ctx.n_msg_sent.load();
                uint32_t counter = 0;
                rdma_ringbuffer_t &rb = *((ctx.is_server == true) ? ctx.ringbuffer_server : ctx.ringbuffer_client);

                while (1)
                {
                    uint64_t now = ctx.get_time_ms();

                    if (msg_sent >= ctx.flush_threshold ||
                        ((now - ctx.last_flush_ms >= FLUSH_INTERVAL_MS) && msg_sent > 0))
                    {
                        ctx.n_msg_sent.store(0); // reset the atomic counter
                        rdma_manager_flush_buffer(ctx, rb);
                    }

                    msg_sent = ctx.n_msg_sent.load(); // reload the atomic counter
                    if (msg_sent == 0)
                    {
                        // no messages to flush, break the loop
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
            tv.tv_sec = TIME_STOP_SELECT_SEC;
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