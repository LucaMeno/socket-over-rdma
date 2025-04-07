#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/select.h>
#include "common.h"

#define CGROUP_PATH "/sys/fs/cgroup"
#define MAP_PATH "/sys/fs/bpf/mysoc"
#define BUFFER_SIZE 2048
#define SRV_PORT 5555
#define SERVER_IP "127.0.0.1"
#define TARGET_PORT 7777
#define NUMBER_OF_SOCKETS 64

struct client_sk_t
{
    int fd;
    __u16 port;
    __u32 ip;
};

struct client_sk_t client_sk_fd[NUMBER_OF_SOCKETS];
int server_sk_fd;

volatile sig_atomic_t stop = false;

int shared = 0;
pthread_mutex_t mutex;
pthread_cond_t cond_var;

struct bpf_object *obj;
int prog_fd_sockops, prog_fd_sk_msg;
int intercepted_sk_fd, free_sk_fd, target_ports_fd, socket_association_fd, server_port_fd;
struct bpf_program *prog_tcp_destroy_sock;
struct bpf_link *tcp_destroy_link;
int cgroup_fd;

void handle_signal(int signal);
void check_error(int result, const char *msg);
void check_fd(int fd, const char *msg);
void check_obj(void *obj, const char *msg);
void error_and_exit(const char *msg);
void wrap_close(int fd);

void setup_bpf();
void run_bpf();
void cleanup_bpf();

void setup_sockets();
void cleanup_socket();
void *client_thread(void *arg);
void set_target_ports();
void wait_for_msg();
void set_socket_nonblocking(int sockfd);

void push_sock_to_map();

int main()
{
    signal(SIGINT, handle_signal);

    setup_bpf();
    printf("eBPF program setup complete\n");

    set_target_ports();
    printf("Target ports set\n");

    run_bpf();
    printf("eBPF program attached to socket\n");

    setup_sockets();
    printf("Sockets setup complete\n");

    push_sock_to_map();
    printf("Map updated\n");

    printf("Waiting for messages, press Ctrl+C to exit...\n");
    wait_for_msg();

    cleanup_socket();
    printf("Socket closed\n");

    cleanup_bpf();
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

void wait_for_msg()
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

    while (!stop)
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
            perror("select");
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
                        perror("recv");

                    close(i);
                    FD_CLR(i, &read_fds);
                }
                else
                {
                    buffer[bytes_received] = '\0';
                    printf("--------------------------------\n");
                    printf("Received message from %d: %s\n", i, buffer);

                    int j = 0;
                    for (; j < NUMBER_OF_SOCKETS; j++)
                    {
                        if (client_sk_fd[j].fd == i)
                            break;
                    }
                    printf("Client %d IP: %u, Port: %u\n", j, client_sk_fd[j].ip, client_sk_fd[j].port);

                    // respond to the client with the same message
                    ssize_t sent_size = send(i, buffer, bytes_received, 0);
                    if (sent_size < 0)
                    {
                        perror("send");
                    }
                    else
                    {
                        printf("Resp sent.\n");
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

void set_target_ports()
{
    // TODO: scale this to multiple ports
    int ports_to_set[1] = {TARGET_PORT};
    int n = sizeof(ports_to_set) / sizeof(ports_to_set[0]);
    int val = 1;

    // set the target ports
    for (int i = 0; i < n; i++)
    {
        int err = bpf_map_update_elem(target_ports_fd, &ports_to_set[i], &val, BPF_ANY);
        check_error(err, "Failed to update target_ports map");
    }

    // set the server port
    int k = 0;
    __u16 p = SRV_PORT;
    int err = bpf_map_update_elem(server_port_fd, &k, &p, BPF_ANY);
    check_error(err, "Failed to update server_port map");
}

void push_sock_to_map()
{
    int err = 0;
    for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
    {
        struct sock_id sk_id = {0};
        sk_id.ip = client_sk_fd[i].ip;
        sk_id.sport = client_sk_fd[i].port;
        sk_id.dport = SRV_PORT;

        // push the socket to the free_sockets map
        err = bpf_map_update_elem(free_sk_fd, NULL, &sk_id, BPF_ANY);
        check_error(err, "Failed to update free_sockets map");

        // add the socket to the intercepted_sockets map
        int err = bpf_map_update_elem(intercepted_sk_fd, &sk_id, &client_sk_fd[i].fd, BPF_ANY);
        check_error(err, "Failed to add socket to intercepted_sockets map");
    }
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
    stop = true;
}

void cleanup_bpf()
{
    int err = 0;

    // Detach sk_msg_prog from sockmap
    if (intercepted_sk_fd > 0)
    {
        err = bpf_prog_detach2(prog_fd_sk_msg, intercepted_sk_fd, BPF_SK_MSG_VERDICT);
        if (err != 0)
        {
            perror("Failed to detach sk_msg_prog from sockmap");
        }
    }

    // Detach sockops_prog from cgroup
    if (cgroup_fd > 0)
    {
        err = bpf_prog_detach2(prog_fd_sockops, cgroup_fd, BPF_CGROUP_SOCK_OPS);
        if (err != 0)
        {
            perror("Failed to detach sockops_prog from cgroup");
        }
    }

    // Detach tcp_destroy_sock_prog from tracepoint
    if (tcp_destroy_link != NULL)
    {
        err = bpf_link__destroy(tcp_destroy_link);
        if (err != 0)
        {
            perror("Failed to detach tcp_destroy_sock_prog from tracepoint");
        }
    }

    // Close all file descriptors
    wrap_close(intercepted_sk_fd);
    wrap_close(free_sk_fd);
    wrap_close(socket_association_fd);
    wrap_close(target_ports_fd);
    wrap_close(cgroup_fd);
    wrap_close(prog_fd_sockops);
    wrap_close(prog_fd_sk_msg);

    // Destroy BPF object
    bpf_object__close(obj);
}

void wrap_close(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
}

void setup_bpf()
{
    // open the BPF object file
    obj = bpf_object__open_file("scap.bpf.o", NULL);
    check_obj(obj, "Failed to open BPF object");

    // load the BPF object file into the kernel
    int err = bpf_object__load(obj);
    check_error(err, "Failed to load BPF object");

    struct bpf_map *intercepted_sockets, *socket_association, *target_ports, *server_port, *free_sk;

    // find the maps in the object file
    intercepted_sockets = bpf_object__find_map_by_name(obj, "intercepted_sockets");
    check_obj(intercepted_sockets, "Failed to find the intercepted_sockets map");
    free_sk = bpf_object__find_map_by_name(obj, "free_sockets");
    check_obj(free_sk, "Failed to find the free_sk map");
    socket_association = bpf_object__find_map_by_name(obj, "socket_association");
    check_obj(socket_association, "Failed to find the socket_association map");
    target_ports = bpf_object__find_map_by_name(obj, "target_ports");
    check_obj(target_ports, "Failed to find the target_ports map");
    server_port = bpf_object__find_map_by_name(obj, "server_port");
    check_obj(server_port, "Failed to find the server_port map");

    // get the file descriptor for the map
    intercepted_sk_fd = bpf_map__fd(intercepted_sockets);
    check_fd(intercepted_sk_fd, "Failed to get intercepted_sockets fd");
    free_sk_fd = bpf_map__fd(free_sk);
    check_fd(free_sk_fd, "Failed to get free_sockets fd");
    socket_association_fd = bpf_map__fd(socket_association);
    check_fd(socket_association_fd, "Failed to get socket_association fd");
    target_ports_fd = bpf_map__fd(target_ports);
    check_fd(target_ports_fd, "Failed to get target_ports fd");
    server_port_fd = bpf_map__fd(server_port);
    check_fd(server_port_fd, "Failed to get server_port fd");

    struct bpf_program *prog_sockops, *prog_sk_msg;

    // find the programs in the object file
    prog_sockops = bpf_object__find_program_by_name(obj, "sockops_prog");
    prog_fd_sockops = bpf_program__fd(prog_sockops);

    prog_sk_msg = bpf_object__find_program_by_name(obj, "sk_msg_prog");
    prog_fd_sk_msg = bpf_program__fd(prog_sk_msg);

    // get the file descriptor for the cgroup
    cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    check_fd(cgroup_fd, "Failed to open cgroup");

    prog_tcp_destroy_sock = bpf_object__find_program_by_name(obj, "tcp_destroy_sock_prog");
    check_obj(prog_tcp_destroy_sock, "Failed to find tcp_destroy_sock_prog");
}

void run_bpf()
{
    int err = 0;

    // attach sockops_prog to the cgroup
    err = bpf_prog_attach(prog_fd_sockops, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
    check_error(err, "Failed to attach sockops_prog to cgroup");

    // Attach sk_msg_prog to the sockmap
    err = bpf_prog_attach(prog_fd_sk_msg, intercepted_sk_fd, BPF_SK_MSG_VERDICT, 0);
    check_error(err, "Failed to attach sk_msg_prog to sockmap");

    // Attach tcp_destroy_sock_prog to the tracepoint
    tcp_destroy_link = bpf_program__attach_tracepoint(prog_tcp_destroy_sock, "tcp", "tcp_destroy_sock");
    check_obj(tcp_destroy_link, "Failed to attach tcp_destroy_sock_prog to tracepoint");
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
    cleanup_bpf();
    exit(EXIT_FAILURE);
}