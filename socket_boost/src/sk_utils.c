

#include "sk_utils.h"

int shared = 0;
pthread_mutex_t mutex;
pthread_cond_t cond_var;

int sk_ret_err(sk_context_t *sk_ctx, const char *msg)

{
    perror(msg);
    printf("Cleaning up resources...\n");
    if (sk_ctx)
        cleanup_socket(sk_ctx);
    return -1;
}
int setup_sockets(sk_context_t *sk_ctx, __u16 server_port, __u32 server_ip)
{
    sk_ctx->server_port = server_port;
    sk_ctx->server_ip = server_ip;

    // Init condition variable and mutex
    if (pthread_mutex_init(&mutex, NULL) != 0 || pthread_cond_init(&cond_var, NULL) != 0)
        return sk_ret_err(sk_ctx, "Failed to initialize sync primitives");

    int opt = 1;
    sk_ctx->server_sk_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sk_ctx->server_sk_fd < 0)
        return sk_ret_err(sk_ctx, "Failed to create server socket");

    setsockopt(sk_ctx->server_sk_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(sk_ctx->server_port);

    if (bind(sk_ctx->server_sk_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
        return sk_ret_err(sk_ctx, "Failed to bind server socket");

    if (listen(sk_ctx->server_sk_fd, NUMBER_OF_SOCKETS) != 0)
        return sk_ret_err(sk_ctx, "Failed to listen on server socket");

    struct in_addr ip_addr;
    ip_addr.s_addr = sk_ctx->server_ip; // già in network byte order
    printf("Server listening on %s:%d\n", inet_ntoa(ip_addr), sk_ctx->server_port);
    printf("Launching client threads...\n");

    // Create client threads
    pthread_t t[NUMBER_OF_SOCKETS];
    client_thread_arg_t client_ids[NUMBER_OF_SOCKETS];

    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
    {
        client_ids[i].client_id = i;
        client_ids[i].sk_ctx = sk_ctx;

        if (pthread_create(&t[i], NULL, client_thread, (void *)&client_ids[i]) != 0)
            return sk_ret_err(sk_ctx, "Failed to create client thread");
    }

    // Accept connections from client threads
    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
    {
        int tmp_fd = accept(sk_ctx->server_sk_fd, NULL, NULL);
        if (tmp_fd < 0)
            return sk_ret_err(sk_ctx, "Failed to accept connection");

        set_socket_nonblocking(tmp_fd);
    }

    // Set the server socket to non-blocking
    set_socket_nonblocking(sk_ctx->server_sk_fd);

    printf("All clients connected (%d)\n", NUMBER_OF_SOCKETS);
    return 0;
}

void *client_thread(void *arg)
{
    sleep(2); // Give server time to set up

    client_thread_arg_t *client_arg = (client_thread_arg_t *)arg;
    int client_id = client_arg->client_id;
    sk_context_t *sk_ctx = client_arg->sk_ctx;

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
        return (void *)(intptr_t)sk_ret_err(sk_ctx, "Client: Failed to create socket");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(sk_ctx->server_port);
    server_addr.sin_addr.s_addr = sk_ctx->server_ip;

    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
        return (void *)(intptr_t)sk_ret_err(sk_ctx, "Client: Failed to connect to server");

    // Get client IP and port
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    if (getsockname(client_fd, (struct sockaddr *)&client_addr, &addr_len) != 0)
        return (void *)(intptr_t)sk_ret_err(sk_ctx, "Client: Failed to get socket info");

    sk_ctx->client_sk_fd[client_id].sk_id.sip = client_addr.sin_addr.s_addr;
    sk_ctx->client_sk_fd[client_id].sk_id.sport = ntohs(client_addr.sin_port);
    sk_ctx->client_sk_fd[client_id].fd = client_fd;
    sk_ctx->client_sk_fd[client_id].sk_id.dip = sk_ctx->server_ip;
    sk_ctx->client_sk_fd[client_id].sk_id.dport = sk_ctx->server_port;

    // Wait for condition variable
    pthread_mutex_lock(&mutex);
    while (shared == 0)
        pthread_cond_wait(&cond_var, &mutex);
    pthread_mutex_unlock(&mutex);

    return NULL;
}

int set_socket_nonblocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0)
        return sk_ret_err(NULL, "fcntl(F_GETFL)");

    int ret = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
        return sk_ret_err(NULL, "fcntl(F_SETFL)");

    return 0;
}

int cleanup_socket(sk_context_t *sk_ctx)
{
    // Notify all threads to exit
    pthread_mutex_lock(&mutex);
    shared = 1;
    pthread_cond_broadcast(&cond_var);
    pthread_mutex_unlock(&mutex);

    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        if (sk_ctx->client_sk_fd->fd >= 0)
            close(sk_ctx->client_sk_fd->fd);

    if (sk_ctx->server_sk_fd >= 0)
        close(sk_ctx->server_sk_fd);

    // Destroy the mutex and condition variable
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond_var);

    return 0;
}
