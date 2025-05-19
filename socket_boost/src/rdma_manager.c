#define _POSIX_C_SOURCE 200112L

#include "rdma_manager.h"

/** PRIVATE FUNCTION */

// BACKGROUND THREADS
void *rdma_manager_listen_thread(void *arg);
void *rdma_manager_server_thread(void *arg);
void *rdma_manager_polling_thread(void *arg);
void *rdma_manager_flush_thread(void *arg);

void *rdma_manager_writer_thread(void *arg);

// WORKER THREADS
// void send_thread(void *arg);
void read_thread(void *arg);
void flush_thread(void *arg);

// CLIENT - SERVER
int rdma_manager_server_setup(rdma_context_manager_t *ctxm);
int rdma_manager_init(rdma_context_manager_t *ctxm, uint16_t rdma_port, client_sk_t *proxy_sks, bpf_context_t *bpf_ctx);
int rdma_manager_get_free_context_id(rdma_context_manager_t *ctxm);

// THREAD POOL
void *worker(void *arg);
thread_pool_t *thread_pool_create(int num_threads);
int thread_pool_add(thread_pool_t *pool, void (*function)(void *), void *arg);
void thread_pool_destroy(thread_pool_t *pool);

// MISC
int rdma_manager_get_context_id(rdma_context_manager_t *ctxm, uint32_t remote_ip);
int start_polling(rdma_context_manager_t *ctxm, rdma_context_t *ctx);

int manager_ret_err(rdma_context_t *rdma_ctx, char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    if (rdma_ctx)
    {
        /*printf("Cleaning up RMDA...\n");
        rdma_context_close(rdma_ctx);*/
    }
    return -1;
}

void *manager_ret_null(rdma_context_t *rdma_ctx, char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    if (rdma_ctx)
    {
        /*printf("Cleaning up RMDA...\n");
        rdma_context_close(rdma_ctx);*/
    }
    return NULL;
}

void manager_ret_void(rdma_context_t *rdma_ctx, char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    if (rdma_ctx)
    {
        /*printf("Cleaning up RMDA...\n");
        rdma_context_close(rdma_ctx);*/
    }
    return;
}

/** SETUP */

int rdma_manager_run(rdma_context_manager_t *ctxm, uint16_t srv_port, bpf_context_t *bpf_ctx, client_sk_t *proxy_sks)
{
    // init the maanger
    if (rdma_manager_init(ctxm, srv_port, proxy_sks, bpf_ctx) != 0)
        return manager_ret_err(NULL, "Failed to init rdma manager - rdma_manager_run");

    // start the server thread
    // get the listener
    if (rdma_manager_server_setup(ctxm))
        return manager_ret_err(NULL, "Failed to setup server - rdma_manager_run");

    if (ctxm->listener == NULL)
        return manager_ret_err(NULL, "Failed to setup listener - rdma_manager_run");

    // start the server thread
    pthread_t thread;
    if (pthread_create(&thread, NULL, rdma_manager_server_thread, ctxm) != 0)
        return manager_ret_err(NULL, "Failed to create thread - rdma_manager_start_server");
    ctxm->server_thread = thread;

    printf("Listener created\n");

    // start the writer threads
    writer_thread_arg_t *writer_arg = malloc(N_WRITER_THREADS * sizeof(writer_thread_arg_t));
    if (writer_arg == NULL)
        return manager_ret_err(NULL, "Failed to allocate memory for writer thread arg - rdma_manager_start_server");

    int n_fd_per_thread = NUMBER_OF_SOCKETS / N_WRITER_THREADS;
    int n_fd_remaining = NUMBER_OF_SOCKETS % N_WRITER_THREADS;

    int j = 0;

    for (int i = 0; i < N_WRITER_THREADS; i++)
    {
        writer_arg[i].ctxm = ctxm;
        int n_fd = n_fd_per_thread;
        if (n_fd_remaining > 0)
        {
            n_fd++;
            n_fd_remaining--;
        }
        writer_arg[i].n = n_fd;
        writer_arg[i].sk_to_monitor = malloc(n_fd * sizeof(client_sk_t));

        if (writer_arg[i].sk_to_monitor == NULL)
            return manager_ret_err(NULL, "Failed to allocate memory for writer thread arg - rdma_manager_start_server");

        for (int k = 0; k < n_fd; k++)
        {
            writer_arg[i].sk_to_monitor[k] = ctxm->client_sks[j];
            j++;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, rdma_manager_writer_thread, &writer_arg[i]) != 0)
            return manager_ret_err(NULL, "Failed to create thread - rdma_manager_start_server");
        ctxm->writer_thread[i] = thread;
    }

    return 0;
}

int rdma_manager_connect(rdma_context_manager_t *ctxm, struct sock_id original_socket, int proxy_sk_fd)
{
    // get the context
    int ctx_id = rdma_manager_get_context_id(ctxm, original_socket.dip);

    if (ctx_id < 0) // no previus connection to the given node, create a new one
    {
        ctx_id = rdma_manager_get_free_context_id(ctxm);
        if (ctx_id < 0)
            return manager_ret_err(NULL, "Failed to get free context - rdma_manager_connect");

        // init the new context
        rdma_setup_context(&ctxm->ctxs[ctx_id]);
        ctxm->ctxs[ctx_id].remote_ip = original_socket.dip;

        // since the context is new, we need to connect to the corresponding server
        if (rdma_client_setup(&ctxm->ctxs[ctx_id], original_socket.dip, ctxm->rdma_port) != 0)
            return manager_ret_err(NULL, "Failed to setup client - rdma_manager_connect");

        if (rdma_client_connect(&ctxm->ctxs[ctx_id]) != 0)
            return manager_ret_err(NULL, "Failed to connect client - rdma_manager_connect");

        // if the notification thread is not running, start it
        if (ctxm->notification_thread == 0)
        {
            // create a thread to listen for notifications
            pthread_t thread;
            if (pthread_create(&thread, NULL, rdma_manager_listen_thread, ctxm) != 0)
                return manager_ret_err(NULL, "Failed to create thread - rdma_manager_connect");
            ctxm->notification_thread = thread;
        }

        // if the flush thread is not running, start it
        if (ctxm->flush_thread == 0)
        {
            // create a thread to flush the buffer
            pthread_t thread;
            if (pthread_create(&thread, NULL, rdma_manager_flush_thread, ctxm) != 0)
                return manager_ret_err(NULL, "Failed to create thread - rdma_manager_connect");
            ctxm->flush_thread = thread;
        }
    }
    return 0;
}

int rdma_manager_init(rdma_context_manager_t *ctxm, uint16_t rdma_port, client_sk_t *proxy_sks, bpf_context_t *bpf_ctx)
{
    ctxm->ctxs = malloc(INITIAL_CONTEXT_NUMBER * sizeof(rdma_context_t));
    if (ctxm->ctxs == NULL)
        return manager_ret_err(NULL, "Failed to allocate memory for contexts - rdma_manager_init");

    for (int i = 0; i < INITIAL_CONTEXT_NUMBER; i++)
    {
        rdma_setup_context(&ctxm->ctxs[i]);
    }
    ctxm->ctx_count = INITIAL_CONTEXT_NUMBER;
    ctxm->rdma_port = rdma_port;
    ctxm->server_thread = 0;
    ctxm->notification_thread = 0;
    ctxm->flush_thread = 0;
    ctxm->polling_thread = 0;
    ctxm->stop_threads = FALSE;
    ctxm->client_sks = proxy_sks;
    ctxm->bpf_ctx = bpf_ctx;

    // setup the pool
    ctxm->pool = thread_pool_create(N_THREADS_POOL);

    return 0;
}

int rdma_manager_destroy(rdma_context_manager_t *ctxm)
{
    // stop the threads
    ctxm->stop_threads = TRUE;
    printf("Stopping threads...\n");

    // destroy the threads
    /*if (ctxm->notification_thread)
    {
        pthread_join(ctxm->notification_thread, NULL);
        ctxm->notification_thread = 0;
    }

    printf("Notification thread stopped\n");

    if (ctxm->polling_thread)
    {
        pthread_join(ctxm->polling_thread, NULL);
        ctxm->polling_thread = 0;
    }

    printf("Polling thread stopped\n");

    /*if (ctxm->server_thread)
    {
        pthread_join(ctxm->server_thread, NULL);
        ctxm->server_thread = 0;
    }

    printf("Server thread stopped\n");*/

    // destroy the thread pool
    thread_pool_destroy(ctxm->pool);
    ctxm->pool = NULL;

    printf("Destroying RDMA manager...\n");

    for (int i = 0; i < ctxm->ctx_count; i++)
    {
        rdma_context_t *ctx = &ctxm->ctxs[i];
        if (ctx->buffer != NULL || atomic_load(&ctx->is_ready) == TRUE)
            rdma_context_close(ctx);
    }
    free(ctxm->ctxs);

    ctxm->ctxs = NULL;
    ctxm->ctx_count = 0;
    ctxm->rdma_port = 0;
    ctxm->client_sks = NULL;
    ctxm->bpf_ctx = NULL;

    // destroy the listener
    if (ctxm->listener)
    {
        rdma_destroy_id(ctxm->listener);
        ctxm->listener = NULL;
    }

    // destroy the event channel
    if (ctxm->server_ec)
    {
        rdma_destroy_event_channel(ctxm->server_ec);
        ctxm->server_ec = NULL;
    }

    return 0;
}

/** UTILS */

int rdma_manager_get_free_context_id(rdma_context_manager_t *ctxm)
{
    int free_ctx_id = 0;
    for (; free_ctx_id < ctxm->ctx_count; free_ctx_id++)
    {
        if (ctxm->ctxs[free_ctx_id].remote_ip == 0)
        {
            return free_ctx_id;
        }
    }

    // no free context available, reallocate the array
    int new_count = ctxm->ctx_count + N_CONTEXT_REALLOC;

    rdma_context_t *new_ctxs = realloc(ctxm->ctxs, new_count * sizeof(rdma_context_t));
    if (new_ctxs == NULL)
        return manager_ret_err(NULL, "Failed to realloc context array - rdma_manager_get_free_context_id");

    ctxm->ctxs = new_ctxs;
    ctxm->ctx_count = new_count;

    // init the new contexts
    if (rdma_setup_context(&ctxm->ctxs[free_ctx_id]) != 0)
        return manager_ret_err(NULL, "Failed to setup context - rdma_manager_get_free_context_id");
}

int rdma_manager_get_context_id(rdma_context_manager_t *ctxm, uint32_t remote_ip)
{
    for (int i = 0; i < ctxm->ctx_count; i++)
    {
        if (ctxm->ctxs[i].remote_ip == remote_ip)
            return i;
    }
    return -1;
}

/** NOTIFICATION */

int rdma_recv_notification(rdma_context_manager_t *ctxm, rdma_context_t *ctx)
{
    notification_t *notification = (notification_t *)ctx->buffer;
    int code; // enum rdma_communication_code
    if (ctx->is_server == TRUE)
    {
        code = notification->from_client.code;
        notification->from_client.code = NONE; // reset the code
        printf("S: Received: %s (%d)\n", get_op_name(code), code);
    }
    else // client
    {
        code = notification->from_server.code;
        notification->from_server.code = NONE; // reset the code
        printf("C: Received: %s (%d)\n", get_op_name(code), code);
    }

    switch (code)
    {
    case EXCHANGE_REMOTE_INFO:
        if (ctx->remote_addr != 0)
        {
            printf("Remote address already set......\n");
            return 0;
        }

        rdma_meta_info_t *remote_info = (rdma_meta_info_t *)(ctx->buffer + sizeof(notification_t));

        // save the remote address and rkey
        ctx->remote_addr = remote_info->addr;
        ctx->remote_rkey = remote_info->rkey;

        // server
        /*printf("S: My address: %p, my rkey: %u\n", (void *)ctx->buffer, ctx->mr->rkey);
        printf("S: Remote address: %p, Remote rkey: %u\n", (void *)ctx->remote_addr, ctx->remote_rkey);*/

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

        pthread_mutex_lock(&ctx->mtx_tx);
        atomic_store(&ctx->is_ready, TRUE);
        pthread_cond_signal(&ctx->cond_tx);
        pthread_mutex_unlock(&ctx->mtx_tx);

        break;

    case RDMA_DATA_READY:

        if (start_polling(ctxm, ctx) != 0)
            return manager_ret_err(ctx, "Failed to send data ready notification - rdma_recv_notification");

        break;

    default:
        printf("Unknown notification code\n");
        break;
    }

    return 0;
}

int start_polling(rdma_context_manager_t *ctxm, rdma_context_t *ctx)
{
    rdma_ringbuffer_t *ringbuffer = (ctx->is_server == TRUE) ? ctx->ringbuffer_server : ctx->ringbuffer_client;

    // check if the buffer is already polling
    uint32_t f = atomic_load(&ringbuffer->flags.flags);
    if ((f & RING_BUFFER_POLLING) == RING_BUFFER_POLLING)
        return 0;

    // set the polling status
    if (rdma_set_polling_status(ctx, RING_BUFFER_POLLING) != 0)
        return manager_ret_err(ctx, "Failed to send data ready notification - start_polling");

    if (ctxm->polling_thread != 0)
        return 0; // polling thread already running

    // launch the polling thread
    thread_pool_arg_t *arg = malloc(sizeof(thread_pool_arg_t));
    if (arg == NULL)
        return manager_ret_err(ctx, "Failed to allocate memory for thread pool arg - start_polling");

    arg->ctxm = ctxm;

    if (pthread_create(&ctxm->polling_thread, NULL, rdma_manager_polling_thread, arg) != 0)
        return manager_ret_err(ctx, "Failed to create thread - start_polling");

    return 0;
}

void *rdma_manager_listen_thread(void *arg)
{
    rdma_context_manager_t *ctxm = (rdma_context_manager_t *)arg;
    printf("Notification thread running\n");

    while (ctxm->stop_threads == FALSE)
    {
        rdma_context_t *ctx = NULL;
        int j;
        // listen for notifications
        for (int i = 0; i < ctxm->ctx_count; i++)
        {
            ctx = &ctxm->ctxs[i];
            if (ctx->remote_ip == 0 || ctx->conn == NULL || ctx->recv_cq == NULL)
            {
                continue; // context not connected
            }

            struct ibv_wc wc = {};
            int num_completions = -1;
            j = 0;

            while (j != N_POLL_PER_CQ)
            {
                j++;
                num_completions = ibv_poll_cq(ctx->recv_cq, 1, &wc);
                if (num_completions != 0) // we have something to process
                    break;
            };

            if (ctxm->stop_threads == TRUE)
                break;

            if (num_completions == 0)
                continue; // no completion, go to the next context

            if (num_completions < 0)
                return manager_ret_null(ctx, "Failed to poll CQ (num_completions<0) - rdma_manager_listen_thread");

            if (wc.status != IBV_WC_SUCCESS)
            {
                fprintf(stderr, "CQ error: %s (%d)\n", ibv_wc_status_str(wc.status), wc.status);
                return manager_ret_null(ctx, "Failed to poll CQ - rdma_manager_listen_thread");
            }

            // post another receive work request
            struct ibv_sge sge = {
                .addr = (uintptr_t)ctx->buffer, // address of the buffer
                .length = sizeof(notification_t),
                .lkey = ctx->mr->lkey};

            // Prepare ibv_recv_wr with IBV_WR_RECV
            struct ibv_recv_wr recv_wr = {.wr_id = 0, .sg_list = &sge, .num_sge = 1};
            struct ibv_recv_wr *bad_wr = NULL;

            // Post receive with ibv_post_recv
            if (ibv_post_recv(ctx->conn->qp, &recv_wr, &bad_wr) != 0 || bad_wr)
                return manager_ret_null(ctx, "Failed to post recv - rdma_recv");

            // process the notification
            int err = rdma_recv_notification(ctxm, ctx);
            if (err != 0)
                return manager_ret_null(ctx, "Failed to receive notification - rdma_manager_listen_thread");
        }
    }

    pthread_exit(NULL);
}

/** CLIENT - SERVER */

int rdma_manager_server_setup(rdma_context_manager_t *ctxm)
{
    struct addrinfo *res;
    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM};

    char port[6];
    snprintf(port, sizeof(port), "%u", ctxm->rdma_port);

    if (getaddrinfo(NULL, port, &hints, &res))
        return manager_ret_err(NULL, "getaddrinfo");

    struct rdma_event_channel *ec = rdma_create_event_channel();
    if (!ec)
        return manager_ret_err(NULL, "rdma_create_event_channel");

    struct rdma_cm_id *listener;
    if (rdma_create_id(ec, &listener, NULL, RDMA_PS_TCP))
        return manager_ret_err(NULL, "rdma_create_id");

    if (rdma_bind_addr(listener, res->ai_addr))
        return manager_ret_err(NULL, "rdma_bind_addr");
    freeaddrinfo(res);

    if (rdma_listen(listener, 10))
        return manager_ret_err(NULL, "rdma_listen");

    ctxm->server_ec = ec;
    ctxm->listener = listener;

    return 0;
}

void *rdma_manager_server_thread(void *arg)
{
    rdma_context_manager_t *manager = (rdma_context_manager_t *)arg;
    printf("Server thread running\n");

    int fd = manager->server_ec->fd;

    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN};

    while (manager->stop_threads == FALSE)
    {
        int ret = poll(&pfd, 1, 1000);

        if (ret < 0)
        {
            perror("poll");
            continue;
        }
        else if (ret == 0)
        {
            if (manager->stop_threads == TRUE)
                break;
            continue; // timeout, no new connection
        }

        struct rdma_cm_event *event;
        if (rdma_get_cm_event(manager->server_ec, &event))
        {
            perror("rdma_get_cm_event");
            continue;
        }

        if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
        {
            // add new context
            int free_ctx_id = rdma_manager_get_free_context_id(manager);
            if (free_ctx_id < 0)
                return manager_ret_null(NULL, "Failed to get free context - rdma_manager_server_thread");

            rdma_context_t *client_ctx = &manager->ctxs[free_ctx_id];

            if (rdma_setup_context(client_ctx) != 0)
                return manager_ret_null(NULL, "Failed to setup context - rdma_manager_server_thread");

            client_ctx->conn = event->id;
            client_ctx->is_server = TRUE;
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&event->id->route.addr.dst_addr; // TODO: understand this
            client_ctx->remote_ip = addr_in->sin_addr.s_addr;                                    // get the IP address of the client

            rdma_ack_cm_event(event);

            if (rdma_server_handle_new_client(client_ctx, manager->server_ec) != 0)
                return manager_ret_null(NULL, "Failed to handle new client - rdma_manager_server_thread");

            // if the notification thread is not running, start it
            if (manager->notification_thread == 0)
            {
                // create a thread to listen for notifications
                pthread_t thread;
                if (pthread_create(&thread, NULL, rdma_manager_listen_thread, manager) != 0)
                    return manager_ret_null(NULL, "Failed to create thread - rdma_manager_server_thread");
                manager->notification_thread = thread;
            }

            // if the flush thread is not running, start it
            if (manager->flush_thread == 0)
            {
                // create a thread to flush the buffer
                pthread_t thread;
                if (pthread_create(&thread, NULL, rdma_manager_flush_thread, manager) != 0)
                    return manager_ret_null(NULL, "Failed to create thread - rdma_manager_server_thread");
                manager->flush_thread = thread;
            }
        }
        else
        {
            rdma_ack_cm_event(event); // ignore other events
        }
    }

    return NULL;
}

/** COMMUNICATION */

void *rdma_manager_writer_thread(void *arg)
{
    writer_thread_arg_t *param = (writer_thread_arg_t *)arg;
    rdma_context_manager_t *ctxm = param->ctxm;
    client_sk_t *sk_to_monitor = param->sk_to_monitor;
    int n = param->n;

    if (sk_to_monitor == NULL || n <= 0 || ctxm == NULL)
        return manager_ret_null(NULL, "Invalid arguments - rdma_manager_writer_thread");

    fd_set read_fds, temp_fds;
    ssize_t bytes_received;

    // Initialize the file descriptor set
    FD_ZERO(&read_fds);

    for (int i = 0; i < n; i++)
        if (sk_to_monitor[i].fd >= 0)
            FD_SET(sk_to_monitor[i].fd, &read_fds);

    // Set the maximum file descriptor
    int max_fd = sk_to_monitor[0].fd;
    for (int i = 0; i < n; i++)
        if (sk_to_monitor[i].fd > max_fd)
            max_fd = sk_to_monitor[i].fd;

    int k = 1;
    while (atomic_load(&ctxm->stop_threads) == FALSE)
    {
        temp_fds = read_fds;

        int activity = select(max_fd + 1, &temp_fds, NULL, NULL, NULL);
        if (activity == -1)
        {
            if (errno == EINTR)
            {
                printf("Select interrupted by signal\n");
                break;
            }
            perror("select error");
            break;
        }

        // Handle data on client sockets
        for (int fd = 0; fd <= max_fd; fd++)
        {
            if (FD_ISSET(fd, &temp_fds))
            {
                // printf(".");
                //  retrieve the proxy socket id
                int j = 0;
                for (; j < n; j++)
                    if (sk_to_monitor[j].fd == fd)
                        break;
                if (j == n)
                {
                    printf("Socket not found in the list - writer_thread\n");
                    continue;
                }

                struct sock_id app = get_app_sk_from_proxy_sk(ctxm->bpf_ctx, sk_to_monitor[j].sk_id);
                if (app.sip == 0)
                {
                    printf("No app socket found - writer_thread\n");
                    continue;
                }

                // get the context
                rdma_context_t *ctx = NULL;
                for (int ctx_idx = 0; ctx_idx < ctxm->ctx_count; ctx_idx++)
                {
                    if (ctxm->ctxs[ctx_idx].remote_ip == app.dip)
                    {
                        ctx = &ctxm->ctxs[ctx_idx];
                        break;
                    }
                }

                if (ctx == NULL)
                {
                    printf("Context not found - writer_thread\n");
                    continue;
                }

                if (atomic_load(&ctx->is_ready) == FALSE)
                {
                    pthread_mutex_lock(&ctx->mtx_tx);
                    while (atomic_load(&ctx->is_ready) == FALSE)
                    {
                        pthread_cond_wait(&ctx->cond_tx, &ctx->mtx_tx);
                    }
                    pthread_mutex_unlock(&ctx->mtx_tx);
                }

                while (1)
                {
                    char dummy;
                    int test = recv(fd, &dummy, 1, MSG_PEEK);
                    if (test > 0)
                    {
                        // there is data to read
                        if (rdma_write_msg(ctx, fd, app) != 0)
                        {
                            printf("Client disconnected or error occurred - writer_thread\n");
                            FD_CLR(fd, &read_fds);
                            close(fd);
                            continue;
                        }
                    }
                    else if (test == 0)
                    {
                        printf("0\n");
                        // connection closed
                        break;
                    }
                    else
                    {
                        perror("recv error");
                        break; // no more data to read
                    }
                }
            }
        }
    }

    printf("Writer thread exiting\n");
    free(param->sk_to_monitor);
    param->sk_to_monitor = NULL;
    free(param);
    param = NULL;

    pthread_exit(NULL);
}

/**
 * Arguments:
 * - ctxm: context manager
 * - ctx: context
 * - start_read_index: start read index
 * - end_read_index: end read index
 */
void read_thread(void *arg)
{
    thread_pool_arg_t *param = (thread_pool_arg_t *)arg;

    if (!param->ctxm || !param->ctx)
        return manager_ret_void(NULL, "Context or context manager is NULL - read_thread");

    if (rdma_read_msg(param->ctx, param->ctxm->bpf_ctx, param->ctxm->client_sks, param->start_read_index, param->end_read_index) != 0)
        return manager_ret_void(NULL, "Failed to read slice - read_thread");

    return;
}

/**
 * Arguments:
 * - ctx: context
 */
void flush_thread(void *arg)
{
    thread_pool_arg_t *param = (thread_pool_arg_t *)arg;

    if (!param->ctx)
        return manager_ret_void(NULL, "Context is NULL - flush_thread");

    // read the data from the remote buffer
    rdma_ringbuffer_t *rb = (param->ctx->is_server == TRUE) ? param->ctx->ringbuffer_server : param->ctx->ringbuffer_client;
    if (rb == NULL)
        return manager_ret_void(NULL, "Ring buffer is NULL - flush_thread");

    if (rdma_flush_buffer(param->ctx, rb) != 0)
        return manager_ret_void(NULL, "Failed to flush - flush_thread");

    return;
}

/**
 * Arguments:
 * - ctxm: context manager
 */
void *rdma_manager_polling_thread(void *arg)
{
    thread_pool_arg_t *param = (thread_pool_arg_t *)arg;
    printf("Polling thread running\n");

    rdma_context_manager_t *ctxm = param->ctxm;
    if (ctxm == NULL)
        return manager_ret_null(NULL, "Context manager is NULL - rdma_manager_polling_thread");

    int i;
    int non_polling = 0;
    int ctx_active = 0;
    rdma_ringbuffer_t *rb_local = NULL;
    rdma_ringbuffer_t *rb_remote = NULL;
    rdma_context_t *ctx = NULL;
    while (ctxm->stop_threads == FALSE)
    {
        for (i = 0; i < ctxm->ctx_count; i++)
        {
            ctx = &ctxm->ctxs[i];
            if (atomic_load(&ctx->is_ready) == FALSE)
                continue;

            ctx_active++;
            rb_local = (ctx->is_server == TRUE) ? ctx->ringbuffer_server : ctx->ringbuffer_client;
            rb_remote = (ctx->is_server == TRUE) ? ctx->ringbuffer_client : ctx->ringbuffer_server;

            // count the number of non-polling buffers
            if (!(atomic_load(&rb_local->flags.flags) & RING_BUFFER_POLLING))
                non_polling++;

            // check if there are any messages to read
            uint32_t remote_w = atomic_load(&rb_remote->remote_write_index);
            uint32_t local_r = atomic_load(&rb_remote->local_read_index);
            if (remote_w != local_r)
            {
                // set the local read index to avoid reading the same data again
                uint32_t start_read_index = local_r;
                atomic_store(&rb_remote->local_read_index, remote_w);

                uint32_t end_read_index = remote_w;

                /*thread_pool_arg_t *arg2 = malloc(sizeof(thread_pool_arg_t));
                if (arg2 == NULL)
                    return manager_ret_null(NULL, "Failed to allocate memory for thread pool arg - rdma_manager_polling_thread");
                arg2->ctxm = param->ctxm;
                arg2->ctx = ctx;
                arg2->start_read_index = start_read_index;
                arg2->end_read_index = end_read_index;
                if (thread_pool_add(param->ctxm->pool, read_thread, arg2) != 0)
                {
                    free(arg2);
                    return manager_ret_null(NULL, "Failed to add task to thread pool - rdma_manager_polling_thread");
                }*/

                int n_msg = end_read_index - start_read_index;
                // TODO: check if n_msg is negative

                uint32_t idx = start_read_index;
                while (idx < end_read_index)
                {
                    thread_pool_arg_t *arg2 = malloc(sizeof(thread_pool_arg_t));
                    if (arg2 == NULL)
                        return manager_ret_null(NULL, "Failed to allocate memory for thread pool arg - rdma_manager_polling_thread");

                    arg2->ctxm = param->ctxm;
                    arg2->ctx = ctx;
                    arg2->start_read_index = idx;

                    int count = 0;
                    while (idx < end_read_index)
                    {
                        int iterator = idx % MAX_N_MSG_PER_BUFFER;
                        rdma_msg_t *msg = &rb_remote->data[iterator];

                        if (msg->number_of_slots <= 0)
                        {
                            free(arg2);
                            return manager_ret_null(NULL, "Invalid message slot count");
                        }

                        count += msg->number_of_slots;
                        idx += msg->number_of_slots;

                        if (count >= FLUSH_THRESHOLD_N)
                            break;
                    }

                    arg2->end_read_index = idx;

                    if (thread_pool_add(param->ctxm->pool, read_thread, arg2) != 0)
                    {
                        free(arg2);
                        return manager_ret_null(NULL, "Failed to add task to thread pool - rdma_manager_polling_thread");
                    }
                }
            }
        }

        if (non_polling == ctx_active)
        {
            // all buffers are non-polling, stop the thread
            printf("All buffers are non-polling, stopping polling thread\n");
            break;
        }
        non_polling = 0;
        ctx_active = 0;
    }

    printf("Polling thread exiting\n");
    free(param);

    return NULL;
}

/**
 * Arguments:
 * - ctxm: context manager
 */
void *rdma_manager_flush_thread(void *arg)
{
    printf("Flush thread running\n");

    rdma_context_manager_t *ctxm = (rdma_context_manager_t *)arg;

    if (!ctxm)
        return manager_ret_null(NULL, "Context manager is NULL - rdma_manager_polling_thread");

    while (ctxm->stop_threads == FALSE)
    {
        for (int i = 0; i < ctxm->ctx_count; i++)
        {
            rdma_context_t *ctx = &ctxm->ctxs[i];
            if (atomic_load(&ctx->is_ready) == FALSE || ctx->conn == NULL)
                continue;

            uint64_t now = get_time_ms();

            if (now - ctx->last_flush_ns >= FLUSH_INTERVAL_MS)
            {
                //  post a new work request
                //  launch a thread
                thread_pool_arg_t *arg2 = malloc(sizeof(thread_pool_arg_t));
                if (arg2 == NULL)
                    return manager_ret_null(NULL, "Failed to allocate memory for thread pool arg - rdma_manager_flush_thread");

                arg2->ctxm = ctxm;
                arg2->ctx = ctx;

                // add the task to the thread pool
                if (thread_pool_add(ctxm->pool, flush_thread, arg2) != 0)
                {
                    free(arg);
                    free(arg2);
                    arg = NULL;
                    arg2 = NULL;
                    return manager_ret_null(NULL, "Failed to add task to thread pool - rdma_manager_polling_thread");
                }
            }
        }
        // sleep for a while
        struct timespec ts;
        ts.tv_sec = FLUSH_INTERVAL_MS / 1000;
        ts.tv_nsec = (FLUSH_INTERVAL_MS % 1000) * 1000000; // ms -> ns
        nanosleep(&ts, NULL);
    }
}

/** POOL */

void *worker(void *arg)
{
    thread_pool_t *pool = (thread_pool_t *)arg;
    while (1)
    {
        pthread_mutex_lock(&pool->lock);
        while (pool->head == NULL && !pool->stop) // wait for a task
        {
            pthread_cond_wait(&pool->cond, &pool->lock);
        }
        if (pool->stop && pool->head == NULL) // no more tasks and pool is stopping
        {
            pthread_mutex_unlock(&pool->lock);
            break;
        }
        task_t *task = pool->head;
        if (task) // task found
        {
            pool->head = task->next;
            if (pool->head == NULL)
                pool->tail = NULL;
        }
        pthread_mutex_unlock(&pool->lock);
        if (task) // execute the task
        {
            task->function(task->arg);
            free(task->arg);
            task->arg = NULL;
            free(task);
            task = NULL;
        }
    }
    return NULL;
}

thread_pool_t *thread_pool_create(int num_threads)
{
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (!pool)
        return NULL;
    pool->thread_count = num_threads;
    pool->stop = 0;
    pool->head = pool->tail = NULL;
    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->cond, NULL);
    pool->threads = malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads)
    {
        free(pool);
        pool = NULL;
        return NULL;
    }
    for (int i = 0; i < num_threads; ++i)
    {
        if (pthread_create(&pool->threads[i], NULL, worker, pool) != 0)
        {
            printf("Failed to create thread %d\n", i);
            free(pool->threads);
            pool->threads = NULL;
            free(pool);
            pool = NULL;
            return NULL;
        }
    }
    printf("Thread pool created with %d threads\n", num_threads);
    return pool;
}

int thread_pool_add(thread_pool_t *pool, void (*function)(void *), void *arg)
{
    task_t *task = malloc(sizeof(task_t));
    if (!task)
        return -1;
    task->function = function;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&pool->lock);
    if (pool->tail)
    {
        pool->tail->next = task;
        pool->tail = task;
    }
    else
    {
        pool->head = pool->tail = task;
    }

    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
    return 0;
}

void thread_pool_destroy(thread_pool_t *pool)
{
    pthread_mutex_lock(&pool->lock);
    pool->stop = 1;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->lock);

    for (int i = 0; i < pool->thread_count; ++i)
    {
        pthread_join(pool->threads[i], NULL);
    }

    while (pool->head)
    {
        task_t *tmp = pool->head;
        pool->head = pool->head->next;
        free(tmp);
        tmp = NULL;
    }

    free(pool->threads);
    pool->threads = NULL;
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->cond);
    free(pool);
    pool = NULL;
}
