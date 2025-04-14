#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <sys/select.h>
#include "common.h"
#include "scap.h"

/**
 * Socket control
 */

#define BUFFER_SIZE 2048
#define SRV_PORT 5555
#define SERVER_IP "127.0.0.1"
#define TARGET_PORT 7777
#define NUMBER_OF_SOCKETS 16
/*
struct client_sk_t
{
    int fd;
    __u16 port;
    __u32 ip;
};*/

struct client_sk_t client_sk_fd[NUMBER_OF_SOCKETS];
int server_sk_fd;

void setup_sockets();
void *client_thread(void *arg);
void set_socket_nonblocking(int sockfd);
void wait_for_msg();
void cleanup_socket();

/**
 * thread control
 */

int shared = 0;
pthread_mutex_t mutex;
pthread_cond_t cond_var;

/**
 * Error handling
 */

volatile sig_atomic_t STOP = false;

void handle_signal(int signal);
void check_error(int result, const char *msg);
void check_fd(int fd, const char *msg);
void check_obj(void *obj, const char *msg);
void error_and_exit(const char *msg);
void wrap_close(int fd);

int main()
{
    signal(SIGINT, handle_signal);

    bpf_context_t bpfctx = {0};
    int err;

    err = setup_bpf(&bpfctx);
    check_error(err, "");
    printf("eBPF program setup complete\n");

    // TODO: scale this to multiple ports
    __u16 ports_to_set[1] = {TARGET_PORT};
    int n = sizeof(ports_to_set) / sizeof(ports_to_set[0]);

    err = set_target_ports(&bpfctx, ports_to_set, n, SRV_PORT);
    check_error(err, "");
    printf("Target ports set\n");

    err = run_bpf(&bpfctx);
    check_error(err, "");
    printf("eBPF program attached to socket\n");

    setup_sockets();
    printf("Sockets setup complete\n");

    struct sock_id skids[NUMBER_OF_SOCKETS];

    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
    {
        skids[i].sip = client_sk_fd[i].ip;
        skids[i].dip = inet_addr(SERVER_IP);
        skids[i].sport = client_sk_fd[i].port;
        skids[i].dport = SRV_PORT;
    }

    push_sock_to_map(&bpfctx, skids, NUMBER_OF_SOCKETS, client_sk_fd);
    printf("Map updated\n");

    printf("Waiting for messages, press Ctrl+C to exit...\n");
    wait_for_msg(&bpfctx);

    cleanup_socket();
    printf("Socket closed\n");

    err = cleanup_bpf(&bpfctx);
    check_error(err, "");
    printf("Successfully detached eBPF program\n");

    return 0;
}

void setup_sockets()
{
    // setup the CV
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond_var, NULL);

    int opt = 1;
    server_sk_fd = socket(AF_INET, SOCK_STREAM, 0);
    check_fd(server_sk_fd, "Failed to create socket");

    setsockopt(server_sk_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(SRV_PORT)};

    int err = bind(server_sk_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    check_fd(err, "Failed to bind socket");

    err = listen(server_sk_fd, NUMBER_OF_SOCKETS);
    check_fd(err, "Failed to listen on socket");

    printf("Server listening on %s:%d\n", SERVER_IP, SRV_PORT);
    printf("Launching client threads...\n");

    // Create client threads
    pthread_t t[NUMBER_OF_SOCKETS];
    int client_ids[NUMBER_OF_SOCKETS];
    int ret = 0;

    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
    {
        client_ids[i] = i;
        ret = pthread_create(&t[i], NULL, client_thread, (void *)&client_ids[i]) != 0;
        check_error(ret, "Failed to create client thread");
    }

    // accept connections from clients threads
    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
    {
        int tmp_fd = accept(server_sk_fd, NULL, NULL);
        check_fd(tmp_fd, "Failed to accept connection");

        // set the socket to non-blocking
        set_socket_nonblocking(client_sk_fd[i].fd);
    }

    // Set the server socket to non-blocking
    set_socket_nonblocking(server_sk_fd);

    printf("All clients connected (%d)\n", NUMBER_OF_SOCKETS);
}

void wait_for_msg(bpf_context_t *ctx)
{
    char buffer[BUFFER_SIZE];
    fd_set read_fds, temp_fds;
    ssize_t bytes_received;

    // Initialize the file descriptor set
    FD_ZERO(&read_fds);
    FD_SET(server_sk_fd, &read_fds);

    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        if (client_sk_fd[i].fd != -1)
            FD_SET(client_sk_fd[i].fd, &read_fds);

    // Set the maximum file descriptor
    int max_fd = server_sk_fd;
    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        if (client_sk_fd[i].fd > max_fd)
            max_fd = client_sk_fd[i].fd;

    int k = 1;
    while (!STOP)
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
        for (int i = 0; i <= max_fd; i++)
        {
            if (i != server_sk_fd && FD_ISSET(i, &temp_fds))
            {
                bytes_received = recv(i, buffer, sizeof(buffer) - 1, 0);
                if (bytes_received <= 0)
                {
                    if (bytes_received == 0)
                        printf("Client %d disconnected\n", i);
                    else
                        perror("recv error");

                    close(i);
                    FD_CLR(i, &read_fds);
                }
                else
                {
                    buffer[bytes_received] = '\0';
                    printf("-----------------------------------------------------------------------(%d)\n", k);
                    k++;
                    printf("Rx from fd:\t%d\n", i);
                    printf("Msg text: \t%s\n", buffer);

                    // get the socket info
                    int j = 0;
                    for (; j < NUMBER_OF_SOCKETS; j++)
                        if (client_sk_fd[j].fd == i)
                            break;

                    if (j == NUMBER_OF_SOCKETS)
                    {
                        error_and_exit("Socket not found in client_sk_fd");
                    }

                    // create the key for the socket_association map
                    struct sock_id sk_id_key = {client_sk_fd[j].ip,   // src IP
                                                inet_addr(SERVER_IP), // dest IP
                                                client_sk_fd[j].port, // src port
                                                SRV_PORT};            // dest port

                    struct association_t sk_assoc_k = {0};
                    struct association_t sk_assoc_v = {0};

                    sk_assoc_k.proxy = sk_id_key;

                    int ret = bpf_map_lookup_elem(ctx->socket_association_fd, &sk_assoc_k, &sk_assoc_v);
                    check_error(ret, "Failed to lookup socket in socket_association_fd");

                    char src_ip_proxy[INET_ADDRSTRLEN],
                        dst_ip_proxy[INET_ADDRSTRLEN],
                        src_ip_app[INET_ADDRSTRLEN],
                        dst_ip_app[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &sk_assoc_k.proxy.sip, src_ip_proxy, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &sk_assoc_k.proxy.dip, dst_ip_proxy, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &sk_assoc_v.app.sip, src_ip_app, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &sk_assoc_v.app.dip, dst_ip_app, INET_ADDRSTRLEN);

                    printf("Rx Sk info:\t[SRC: %s:%u, DST: %s:%u]\n", src_ip_proxy, sk_assoc_k.proxy.sport, dst_ip_proxy, sk_assoc_k.proxy.dport);

                    printf("Original sk:\t[SRC: %s:%u, DST: %s:%u]\n", src_ip_app, sk_assoc_v.app.sport, dst_ip_app, sk_assoc_v.app.dport);

                    // respond to the client with the same message
                    ssize_t sent_size = send(i, buffer, bytes_received, 0);
                    if (sent_size < 0)
                    {
                        perror("send");
                    }
                    else
                    {
                        printf("Response:\tsent\n");
                    }
                }
            }
        }
    }
}

void *client_thread(void *arg)
{
    sleep(2); // Wait for the server to be ready

    int index = *(int *)arg;

    int client_fd;
    struct sockaddr_in server_addr;

    // Create socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    check_fd(client_fd, "Client: Failed to create socket");

    // Set up the server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SRV_PORT);

    int err = inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    if (err != 1)
    {
        error_and_exit("Client: Invalid address or address not supported");
    }

    // Connect to the server
    err = connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    check_error(err, "Client: Connection failed");

    // get the port number
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int ret = getsockname(client_fd, (struct sockaddr *)&client_addr, &addr_len);
    check_fd(ret, "getsockname failed");
    client_sk_fd[index].port = ntohs(client_addr.sin_port);

    // get the socket address
    struct sockaddr_in addr = {0};
    socklen_t len = sizeof(addr);
    err = getsockname(client_fd, (struct sockaddr *)&addr, &len);
    check_fd(err, "Failed to get socket name");
    client_sk_fd[index].ip = addr.sin_addr.s_addr;

    client_sk_fd[index].fd = client_fd;

    // wait on the condition variable
    pthread_mutex_lock(&mutex);
    while (shared == 0)
        pthread_cond_wait(&cond_var, &mutex);
    pthread_mutex_unlock(&mutex);

    return NULL;
}

void set_socket_nonblocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    check_fd(flags, "fcntl(F_GETFL)");

    int ret = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    check_fd(ret, "fcntl(F_SETFL)");
}

void cleanup_socket()
{
    // Notify all threads to exit
    pthread_mutex_lock(&mutex);
    shared = 1;
    pthread_cond_broadcast(&cond_var);
    pthread_mutex_unlock(&mutex);

    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        if (client_sk_fd[i].fd >= 0)
            close(client_sk_fd[i].fd);
    if (server_sk_fd >= 0)
        close(server_sk_fd);

    // Destroy the mutex and condition variable
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond_var);
}

void handle_signal(int signal)
{
    STOP = true;
}

/**
 * error if result is not 0
 */
void check_error(int result, const char *msg)
{
    if (result != 0)
    {
        error_and_exit(msg);
    }
}

/**
 * error if fd is negative
 */
void check_fd(int fd, const char *msg)
{
    if (fd < 0)
    {
        error_and_exit(msg);
    }
}

/**
 * error if obj is NULL
 */
void check_obj(void *obj, const char *msg)
{
    if (!obj)
    {
        error_and_exit(msg);
    }
}

void error_and_exit(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    perror("Error details");
    printf("Cleaning up resources...\n");
    cleanup_socket();
    // cleanup_bpf();
    exit(EXIT_FAILURE);
}
