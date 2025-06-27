
#include "RdmaMng.h"

using namespace std;
using namespace rdma;

namespace rdmaMng
{
    void RdmaMng::init(uint16_t srv_port, sk::client_sk_t *proxy_sks, bpf::BpfMng *bpf_ctx)
    {
        rdma_port = srv_port;
        stop_threads = false;
        client_sks = proxy_sks;
        bpf_ctx = bpf_ctx;

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

    void RdmaMng::destroy()
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

        thPool->destroy();
        cout << "Thread pool destroyed" << endl;

        cout << "RDMA contexts cleared" << endl;
    }

    void RdmaMng::rdma_manager_run(uint16_t srv_port, bpf::BpfMng *bpf_ctx, sk::client_sk_t *proxy_sks)
    {
        // init the maanger
        init(srv_port, proxy_sks, bpf_ctx);

        // start the server thread
        rdma_manager_server_setup();

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

    void RdmaMng::rdma_manager_server_setup()
    {
        struct addrinfo *res;
        struct addrinfo hints = {
            .ai_flags = AI_PASSIVE,
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM};

        char port[6];
        snprintf(port, sizeof(port), "%u", rdma_port);

        if (getaddrinfo(NULL, port, &hints, &res))
            throw runtime_error("getaddrinfo failed");

        struct rdma_event_channel *ec = rdma_create_event_channel();
        if (!ec)
            throw runtime_error("rdma_create_event_channel failed");

        struct rdma_cm_id *listener;
        if (rdma_create_id(ec, &listener, NULL, RDMA_PS_TCP))
            throw runtime_error("rdma_create_id failed");

        if (rdma_bind_addr(listener, res->ai_addr))
            throw runtime_error("rdma_bind_addr failed");

        freeaddrinfo(res);

        if (rdma_listen(listener, 10))
            throw runtime_error("rdma_listen failed");

        if (listener == NULL)
            throw runtime_error("Listener is NULL after rdma_listen");

        server_ec = ec;
        listener = listener;
    }

    void RdmaMng::rdma_manager_server_thread()
    {
        int fd = server_ec->fd;

        struct pollfd pfd = {
            .fd = fd,
            .events = POLLIN};

        while (stop_threads == false)
        {
            int ret = poll(&pfd, 1, 1000);

            if (ret < 0)
            {
                perror("poll");
                continue;
            }
            else if (ret == 0)
            {
                if (stop_threads == true)
                    break;
                continue; // timeout, no new connection
            }

            struct rdma_cm_event *event;
            if (rdma_get_cm_event(server_ec, &event))
            {
                perror("rdma_get_cm_event");
                continue;
            }

            if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
            {
                // add new context
                int free_ctx_id = rdma_manager_get_free_context_id();

                auto &ctx = *ctxs[free_ctx_id];

                ctx.conn = event->id;
                ctx.is_server = TRUE;
                struct sockaddr_in *addr_in = (struct sockaddr_in *)&event->id->route.addr.dst_addr; // TODO: understand this
                ctx.remote_ip = addr_in->sin_addr.s_addr;                                            // get the IP address of the client

                rdma_ack_cm_event(event);

                ctx.rdma_server_handle_new_client(server_ec);

                rdma_manager_launch_background_threads();
            }
            else
            {
                cout << "Unexpected event: " << rdma_event_str(event->event) << endl;
                rdma_ack_cm_event(event); // ignore other events
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

            int activity = select(max_fd + 1, &temp_fds, NULL, NULL, &tv);
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

                    cout << "Socket ID: ";
                    cout << sk_to_monitor[j].sk_id.sip << ":" << sk_to_monitor[j].sk_id.sport << " -> "
                         << sk_to_monitor[j].sk_id.dip << ":" << sk_to_monitor[j].sk_id.dport << endl;

                    struct sock_id app = bpf_ctx->get_app_sk_from_proxy_sk(sk_to_monitor[j].sk_id);
                    if (app.sip == 0)
                    {
                        cout << "No app socket found for fd: " << fd << endl;
                        FD_CLR(fd, &read_fds);
                        continue;
                    }

                    // get the context
                    // vector<unique_ptr<RdmaContext>>::iterator ctx;
                    auto ctxIt = ctxs.begin();
                    for (; ctxIt != ctxs.end(); ++ctxIt)
                        if ((*ctxIt)->remote_ip == app.dip)
                            break; // found the context for this fd

                    if (ctxIt == ctxs.end())
                    {
                        cout << "Context not found - writer_thread" << endl;
                        continue; // no context for this IP
                    }

                    auto &ctx = *ctxIt;

                    // Wait for the context to be ready
                    ctx->wait_for_context_ready();

                    while (1)
                    {
                        int ret = ctx->rdma_write_msg(fd, app);

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

        int i;
        rdma::rdma_ringbuffer_t *rb_local = NULL;
        rdma::rdma_ringbuffer_t *rb_remote = NULL;

        // TODO: remove
        unique_lock<mutex> lock(mtx_polling);
        is_polling_thread_running = false;
        while (is_polling_thread_running == false && stop_threads == false)
        {
            cout << "Waiting for polling thread to start..." << endl;
            cond_polling.wait(lock);
        }
        lock.unlock();

        if (stop_threads == true)
        {
            return; // stop the thread if stop_threads is set
        }

        auto ctxIt = ctxs.begin();

        while (stop_threads == false)
        {
            auto &ctx = *ctxIt;
            int ret = rdma_manager_consume_ringbuffer(ctx.get(), ctx->is_server ? ctx->ringbuffer_client : ctx->ringbuffer_server);
            if (ret < 0)
            {
                throw runtime_error("Error consuming ring buffer - rdma_manager_polling_thread");
            }
            else if (ret == 1)
            {
                // no msg to read
                break;
            }

            ctxIt++;
            if (ctxIt == ctxs.end())
            {
                ctxIt = ctxs.begin(); // reset the iterator to the beginning
            }
        }
    }

    int RdmaMng::rdma_manager_consume_ringbuffer(rdma::RdmaContext *ctx, rdma::rdma_ringbuffer_t *rb_remote)
    {
        if (ctx == nullptr || rb_remote == nullptr)
        {
            throw runtime_error("Context or remote ring buffer is NULL - rdma_manager_consume_ringbuffer");
        }

        while (1)
        {
            uint32_t remote_w = atomic_load(&rb_remote->remote_write_index);
            uint32_t local_r = atomic_load(&rb_remote->local_read_index);

            if (remote_w != local_r)
            {
                // set the local read index to avoid reading the same data again
                uint32_t start_read_index = local_r;
                uint32_t end_read_index = remote_w;

                atomic_store(&rb_remote->local_read_index, remote_w);

                ctx->rdma_read_msg(bpf_ctx.get(), client_sks, start_read_index, end_read_index);
                ctx->rdma_update_remote_read_idx(rb_remote, end_read_index);
            }
            else
            {
                return 1; // no messages to read
            }
        }
    }

    void RdmaMng::rdma_manager_flush_buffer(rdma::RdmaContext *ctx, rdma::rdma_ringbuffer_t *rb)
    {
        uint32_t start_idx = rb->local_read_index.load();
        uint32_t end_idx = rb->local_write_index.load();

        thPool->enqueue([this, ctx, rb, start_idx, end_idx]()
                        { flush_thread_worker(ctx, rb, start_idx, end_idx); });

        // atomic_store(&rb->local_read_index, atomic_load(&rb->local_write_index)); // reset the local read index
        rb->local_read_index.store(rb->local_write_index.load());

        ctx->last_flush_ms = ctx->get_time_ms();
    }

    void RdmaMng::flush_thread_worker(rdma::RdmaContext *ctx, rdma::rdma_ringbuffer_t *rb, uint32_t start_idx, uint32_t end_idx)
    {
        if (ctx == nullptr || rb == nullptr)
            throw runtime_error("Context or ring buffer is NULL - flush_thread_worker");

        ctx->rdma_flush_buffer(rb, start_idx, end_idx);
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

            ctx->rdma_client_setup(original_socket.dip, rdma_port);
            ctx->rdma_client_connect();
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

    void RdmaMng::rdma_manager_start_polling(rdma::RdmaContext *ctx)
    {
        // Try to set polling status
        ctx->rdma_set_polling_status(TRUE);

        // wake up the polling thread
        unique_lock<mutex> lock(mtx_polling);
        is_polling_thread_running = true;
        ctx->time_start_polling = ctx->get_time_ms();
        ctx->loop_with_no_msg = 0;
        cond_polling.notify_all();
    }

    void RdmaMng::rdma_manager_stop_polling(rdma::RdmaContext *ctx)
    {
        // Try to set polling status
        ctx->rdma_set_polling_status(FALSE);
    }

    void RdmaMng::rdma_parse_notification(rdma::RdmaContext *ctx)
    {
        rdma::notification_t *notification = (rdma::notification_t *)ctx->buffer;
        rdma::CommunicationCode code; // enum rdma_communication_code
        if (ctx->is_server == TRUE)
        {
            code = notification->from_client.code;
            notification->from_client.code = rdma::CommunicationCode::NONE; // reset the code
            cout << "S: Received: " << ctx->get_op_name(code) << " (" << static_cast<int>(code) << ")" << endl;
        }
        else // client
        {
            code = notification->from_server.code;
            notification->from_server.code = rdma::CommunicationCode::NONE; // reset the code
            cout << "C: Received: " << ctx->get_op_name(code) << " (" << static_cast<int>(code) << ")" << endl;
        }

        switch (code)
        {
        case rdma::CommunicationCode::EXCHANGE_REMOTE_INFO:
        {
            if (ctx->remote_addr != 0)
            {
                cout << "Remote address already set, ignoring EXCHANGE_REMOTE_INFO notification" << endl;
                return;
            }

            rdma::rdma_meta_info_t *remote_info = (rdma::rdma_meta_info_t *)(ctx->buffer + sizeof(rdma::notification_t));

            // save the remote address and rkey
            ctx->remote_addr = remote_info->addr;
            ctx->remote_rkey = remote_info->rkey;

            ctx->ringbuffer_server = (rdma_ringbuffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE);
            atomic_store(&ctx->ringbuffer_server->local_read_index, 0);
            atomic_store(&ctx->ringbuffer_server->remote_read_index, 0);
            atomic_store(&ctx->ringbuffer_server->remote_write_index, 0);
            atomic_store(&ctx->ringbuffer_server->local_write_index, 0);
            atomic_store(&ctx->ringbuffer_server->flags.flags, 0);

            ctx->ringbuffer_client = (rdma_ringbuffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE + RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
            atomic_store(&ctx->ringbuffer_client->local_read_index, 0);
            atomic_store(&ctx->ringbuffer_client->remote_read_index, 0);
            atomic_store(&ctx->ringbuffer_client->remote_write_index, 0);
            atomic_store(&ctx->ringbuffer_client->local_write_index, 0);
            atomic_store(&ctx->ringbuffer_client->flags.flags, 0);

            unique_lock<mutex> lock(ctx->mtx_tx);
            atomic_store(&ctx->is_ready, TRUE);
            ctx->cond_tx.notify_all();
            lock.unlock();

            break;
        }

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
        cout << "Listening for notifications..." << endl;
        struct timeval tv;

        while (stop_threads == false)
        {
            fd_set fds;
            FD_ZERO(&fds);
            int max_fd = -1;

            for (auto &ctx : ctxs)
            {
                if (ctx.get()->recv_cq != NULL && ctx.get()->comp_channel != NULL)
                {
                    FD_SET(ctx.get()->comp_channel->fd, &fds);
                    if (ctx.get()->comp_channel->fd > max_fd)
                        max_fd = ctx.get()->comp_channel->fd;
                }
                else
                {
                    cout << "Context not ready, skipping in rdma_manager_listen_thread" << endl;
                }
            }

            if (max_fd < 0)
                throw runtime_error("No valid contexts to monitor in rdma_manager_listen_thread");

            // Set timeout to avoid blocking indefinitely
            tv.tv_sec = TIME_STOP_SELECT_SEC;
            tv.tv_usec = 0;

            int activity = select(max_fd + 1, &fds, NULL, NULL, &tv);
            if (activity == -1)
            {
                if (errno == EINTR)
                {
                    cout << "Select interrupted by signal in rdma_manager_listen_thread" << endl;
                    break;
                }
                perror("select error");
                break;
            }

            for (int fd = 0; fd <= max_fd; fd++)
            {
                if (FD_ISSET(fd, &fds))
                {
                    // lookup to get the context

                    RdmaContext *ctx = nullptr;
                    for (auto &c : ctxs)
                    {
                        if (c.get()->comp_channel == nullptr || c.get()->comp_channel->fd != fd)
                            continue;
                        ctx = c.get();
                        break; // found the context for this fd
                    }

                    if (ctx == nullptr)
                        throw runtime_error("Context not found for fd in rdma_manager_listen_thread");

                    struct ibv_cq *ev_cq;
                    void *ev_ctx;
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

                    struct ibv_wc wc;
                    int num_completions = ibv_poll_cq(ctx->recv_cq, 1, &wc);
                    if (num_completions < 0)
                    {
                        cerr << "Failed to poll CQ: " << strerror(errno) << endl;
                        continue;
                    }

                    if (num_completions == 0) // it should not happen, but just in case
                        continue;

                    if (wc.status != IBV_WC_SUCCESS)
                    {
                        cerr << "CQ error: " << ibv_wc_status_str(wc.status) << " (" << wc.status << ")" << endl;
                        continue;
                    }

                    // repost another receive request
                    struct ibv_sge sge;
                    sge.addr = (uintptr_t)ctx->buffer;
                    sge.length = sizeof(notification_t);
                    sge.lkey = ctx->mr->lkey;

                    struct ibv_recv_wr recv_wr;
                    recv_wr.wr_id = 0;
                    recv_wr.sg_list = &sge;
                    recv_wr.num_sge = 1;
                    recv_wr.next = NULL;

                    struct ibv_recv_wr *bad_wr = NULL;
                    if (ibv_post_recv(ctx->conn->qp, &recv_wr, &bad_wr) != 0 || bad_wr)
                    {
                        cerr << "Bad WR: " << (bad_wr ? bad_wr->wr_id : 0) << endl;
                        cerr << "Error posting recv: " << strerror(errno) << endl;
                        break;
                    }

                    rdma_parse_notification(ctx);
                }
            }
        }
    }

    void RdmaMng::rdma_manager_flush_thread()
    {
        cout << "Flush thread started" << endl;

        while (stop_threads == false)
        {
            auto ctxIt = ctxs.begin();
            for (; ctxIt != ctxs.end(); ++ctxIt)
            {
                auto &ctx = *ctxIt;
                if (ctx->is_ready == FALSE)
                {
                    // context is not ready, skip it
                    continue;
                }

                uint32_t is_flushing_thread_running = ctx->is_flush_thread_running.load();
                if (is_flushing_thread_running == TRUE)
                {
                    // flush thread is already running, skip this context
                    continue;
                }

                uint32_t msg_sent = ctx->n_msg_sent.load();
                uint32_t counter = 0;
                rdma_ringbuffer_t *rb = (ctx->is_server == TRUE) ? ctx->ringbuffer_server : ctx->ringbuffer_client;

                while (1)
                {
                    uint64_t now = ctx->get_time_ms();

                    if (msg_sent >= ctx->flush_threshold ||
                        ((now - ctx->last_flush_ms >= FLUSH_INTERVAL_MS) && msg_sent > 0))
                    {
                        ctx->n_msg_sent.store(0); // reset the atomic counter
                        rdma_manager_flush_buffer(&(*ctx), rb);
                    }

                    msg_sent = ctx->n_msg_sent.load(); // reload the atomic counter
                    if (msg_sent == 0)
                    {
                        // no messages to flush, break the loop
                        break;
                    }
                }
            }
        }
    }
}
