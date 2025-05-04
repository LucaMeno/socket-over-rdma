#define _POSIX_C_SOURCE 200112L

#include "rdma_manager.h"

// PRIVATE FUNCTIONS
int rdma_manager_get_context_id(rdma_context_manager_t *ctxm, uint32_t remote_ip);

void *rdma_manager_listen_thread(void *arg);
void *rdma_manager_server_thread(void *arg);
void send_thread(void *arg);
void rdma_manager_connect_thread(void *arg);

int rdma_manager_server_setup(rdma_context_manager_t *ctxm);
int rdma_manager_init(rdma_context_manager_t *ctxm, uint16_t rdma_port, client_sk_t *proxy_sks, bpf_context_t *bpf_ctx);
int rdma_manager_get_free_context_id(rdma_context_manager_t *ctxm);

/** THREAD POOL */

void *worker(void *arg);
thread_pool_t *thread_pool_create(int num_threads);
int thread_pool_add(thread_pool_t *pool, void (*function)(void *), void *arg);
void thread_pool_destroy(thread_pool_t *pool);

/** MISC */

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

    printf("Listener created\n");

    // start the server thread
    pthread_t thread;
    if (pthread_create(&thread, NULL, rdma_manager_server_thread, ctxm) != 0)
        return manager_ret_err(NULL, "Failed to create thread - rdma_manager_start_server");
    ctxm->server_thread = thread;

    return 0;
}

int rdma_manager_connect(rdma_context_manager_t *ctxm, struct sock_id original_socket, int proxy_sk_fd)
{
    // allocate the param for the thread
    thread_pool_arg_t *arg = malloc(sizeof(thread_pool_arg_t));
    if (arg == NULL)
        return manager_ret_err(NULL, "Failed to allocate memory for thread pool arg - rdma_manager_connect");

    arg->ctxm = ctxm;
    arg->original_socket = original_socket;
    arg->fd = proxy_sk_fd;

    // add the task to the thread pool
    if (thread_pool_add(ctxm->pool, rdma_manager_connect_thread, arg) != 0)
    {
        free(arg);
        return manager_ret_err(NULL, "Failed to add task to thread pool - rdma_manager_connect");
    }

    return 0;
}

void rdma_manager_connect_thread(void *arg)
{
    thread_pool_arg_t *targ = (thread_pool_arg_t *)arg;
    rdma_context_manager_t *ctxm = targ->ctxm;
    struct sock_id original_socket = targ->original_socket;
    int proxy_sk_fd = targ->fd;

    // get the context
    int ctx_id = rdma_manager_get_context_id(ctxm, original_socket.dip);

    if (ctx_id < 0) // no previus connection to the given node, create a new one
    {
        ctx_id = rdma_manager_get_free_context_id(ctxm);
        if (ctx_id < 0)
            return manager_ret_void(NULL, "Failed to get free context - rdma_manager_connect");

        // init the new context
        rdma_setup_context(&ctxm->ctxs[ctx_id]);
        ctxm->ctxs[ctx_id].remote_ip = original_socket.dip;

        // since the context is new, we need to connect to the corresponding server
        if (rdma_client_setup(&ctxm->ctxs[ctx_id], original_socket.dip, ctxm->rdma_port) != 0)
            return manager_ret_void(NULL, "Failed to setup client - rdma_get_slice");

        if (rdma_client_connect(&ctxm->ctxs[ctx_id]) != 0)
            return manager_ret_void(NULL, "Failed to connect client - rdma_get_slice");

        // if the notification thread is not running, start it
        if (ctxm->notification_thread == 0)
        {
            // create a thread to listen for notifications
            pthread_t thread;
            if (pthread_create(&thread, NULL, rdma_manager_listen_thread, ctxm) != 0)
                return manager_ret_void(NULL, "Failed to create thread - rdma_maanger_listen_notification");
            ctxm->notification_thread = thread;
        }
    }
}

int rdma_manager_init(rdma_context_manager_t *ctxm, uint16_t rdma_port, client_sk_t *proxy_sks, bpf_context_t *bpf_ctx)
{
    ctxm->ctxs = malloc(INITIAL_CONTEXT_NUMBER * sizeof(rdma_context_t));
    for (int i = 0; i < INITIAL_CONTEXT_NUMBER; i++)
    {
        ctxm->ctxs[i].context_id = i;
        rdma_setup_context(&ctxm->ctxs[i]);
    }
    ctxm->ctx_count = INITIAL_CONTEXT_NUMBER;
    ctxm->rdma_port = rdma_port;
    ctxm->server_thread = 0;
    ctxm->notification_thread = 0;
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

    for (int i = 0; i < ctxm->ctx_count; i++)
        rdma_context_close(&ctxm->ctxs[i]);
    free(ctxm->ctxs);
    ctxm->ctxs = NULL;
    ctxm->ctx_count = 0;
    ctxm->rdma_port = 0;
    ctxm->client_sks = NULL;
    ctxm->bpf_ctx = NULL;

    // destroy the thread pool
    thread_pool_destroy(ctxm->pool);
    ctxm->pool = NULL;

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

    if (ctxm->notification_thread)
    {
        pthread_join(ctxm->notification_thread, NULL);
        ctxm->notification_thread = 0;
    }

    if (ctxm->server_thread)
    {
        // TODO: stop the server thread
        pthread_join(ctxm->server_thread, NULL);
        ctxm->server_thread = 0;
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

int rdma_recv_notification(rdma_context_t *ctx, bpf_context_t *bpf_ctx, client_sk_t *client_sks)
{
    notification_t *notification = (notification_t *)ctx->buffer;
    int code; // enum rdma_communication_code
    printf("------------------------------------------------------------\n");
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
        printf("S: My address: %p, my rkey: %u\n", (void *)ctx->buffer, ctx->mr->rkey);
        printf("S: Remote address: %p, Remote rkey: %u\n", (void *)ctx->remote_addr, ctx->remote_rkey);

        ctx->ringbuffer_server = (rdma_ringbuffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE);
        ctx->ringbuffer_server->write_index = 0;
        ctx->ringbuffer_server->read_index = 0;
        ctx->ringbuffer_server->flags.is_polling = FALSE;

        ctx->ringbuffer_client = (rdma_ringbuffer_t *)(ctx->buffer + NOTIFICATION_OFFSET_SIZE + RING_BUFFER_OFFSET_SIZE); // skip the notification header and the server buffer
        ctx->ringbuffer_client->write_index = 0;
        ctx->ringbuffer_client->read_index = 0;
        ctx->ringbuffer_client->flags.is_polling = FALSE;

        break;

    case RDMA_DATA_READY:

        if (rdma_read_msg(ctx, bpf_ctx, client_sks) != 0)
            return manager_ret_err(ctx, "Failed to read message - rdma_recv_notification");
        break;

    default:
        printf("Unknown notification code\n");
        break;
    }

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
            int err = rdma_recv_notification(ctx, ctxm->bpf_ctx, ctxm->client_sks);
            if (err != 0)
                return manager_ret_null(ctx, "Failed to receive notification - rdma_manager_listen_thread");

            printf("Posted recv\n");
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

    while (!manager->stop_threads)
    {
        printf("Waiting for new connection...\n");
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
            printf("Client IP: %u\n", client_ctx->remote_ip);

            rdma_ack_cm_event(event);

            if (rdma_server_handle_new_client(client_ctx, manager->server_ec) != 0)
                return manager_ret_null(NULL, "Failed to handle new client - rdma_manager_server_thread");

            // if the notification thread is not running, start it
            if (manager->notification_thread == 0)
            {
                // create a thread to listen for notifications
                pthread_t thread;
                if (pthread_create(&thread, NULL, rdma_manager_listen_thread, manager) != 0)
                    return manager_ret_null(NULL, "Failed to create thread - rdma_maanger_listen_notification");
                manager->notification_thread = thread;
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

int rdma_manager_send(rdma_context_manager_t *ctxm, char *tx_data, int tx_size, struct sock_id original_socket)
{
    // prepare the arguments for the thread
    thread_pool_arg_t *arg = malloc(sizeof(thread_pool_arg_t));
    if (arg == NULL)
        return manager_ret_err(NULL, "Failed to allocate memory for thread pool argument - sk_send");

    arg->ctxm = ctxm;
    arg->original_socket = original_socket;
    arg->tx_data = tx_data;
    arg->tx_size = tx_size;

    // add the task to the thread pool
    if (thread_pool_add(ctxm->pool, send_thread, arg) != 0)
    {
        free(arg);
        arg = NULL;
        return manager_ret_err(NULL, "Failed to add task to thread pool - sk_send");
    }
    printf("Task added to thread pool\n");
    return 0;
}

void send_thread(void *arg)
{
    thread_pool_arg_t *param = (thread_pool_arg_t *)arg;

    if (param->ctxm->ctx_count == 0)
    {
        printf("No context available\n");
        return;
    }

    printf("Sending data to %u:%u\n", param->original_socket.dip, param->original_socket.dport);

    // get the context
    rdma_context_t *ctx = NULL;
    for (int i = 0; i < param->ctxm->ctx_count; i++)
    {
        if (param->ctxm->ctxs[i].remote_ip == param->original_socket.dip)
        {
            ctx = &param->ctxm->ctxs[i];
            break;
        }
    }

    if (ctx == NULL)
    {
        printf("Context not found\n");
        return;
    }

    rdma_msg_t msg;
    /*const char *tmp = "CIAOO";
    strcpy(msg.msg, tmp);
    msg.msg_size = sizeof(tmp);*/
    msg.original_sk_id = param->original_socket;
    msg.msg_size = param->tx_size;
    // TODO: avoid this copy
    memcpy(msg.msg, param->tx_data, msg.msg_size);

    // write the data to the remote buffer
    if (rdma_write_msg(ctx, &msg) != 0)
        return manager_ret_void(NULL, "Failed to write slice - send_thread");

    /* rdma_ringbuffer_t *buffer_to_read = (ctx->is_server == TRUE) ? ctx->ringbuffer_client : ctx->ringbuffer_server;

     // check if the other side is polling
     if (buffer_to_read->flags.is_polling == FALSE)
     {
         printf("Other side is not polling\n");

     } else {
         printf("Other side is polling\n");
     }*/

    rdma_send_data_ready(ctx);

    return;
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
        pthread_create(&pool->threads[i], NULL, worker, pool);
    }
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
    thread_pool_arg_t *arg2 = (thread_pool_arg_t *)arg;

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
