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
#include "common.h"

#define CGROUP_PATH "/sys/fs/cgroup"
#define MAP_PATH "/sys/fs/bpf/mysoc"
#define BUFFER_SIZE 2048
#define SRV_PORT 5559
#define SERVER_IP "127.0.0.1"

volatile sig_atomic_t stop = false;

void handle_signal(int signal);
void check_error(int result, const char *msg);
void check_fd(int fd, const char *msg);
void check_obj(void *obj, const char *msg);
void error_and_exit(const char *msg);

struct bpf_object *obj;
int prog_fd_sockops, prog_fd_sk_msg;
int sockmap_fd, mysoc_fd, userMsg_fd, targetport_fd;
int cgroup_fd;
struct bpf_map *userMsg;

void setup_bpf();
void run_bpf();
void cleanup_bpf();

int sock = -1, client_sock = -1;

void setup_socket();
void cleanup_socket();
void set_mysocket_map(int fd);
void set_target_port(__u16 target_port, __u16 server_port);
void *client_thread(void *arg);
void run_client();

void print_msg(struct msg_header *msg);

int main(int argc, char **argv)
{

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <target_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    __u16 target_port = atoi(argv[1]);

    signal(SIGINT, handle_signal);

    setup_bpf();
    printf("eBPF program setup complete\n");

    set_target_port(target_port, SRV_PORT);
    printf("Target port set to %u\n", target_port);

    run_bpf();
    printf("eBPF program attached to socket\n");

    setup_socket();
    printf("Server socket created\n");

    run_client();

    printf("Waiting for client on port %d...\n", SRV_PORT);
    client_sock = accept(sock, NULL, NULL);
    check_fd(client_sock, "Accept failed");

    printf("Client connected.\n");

    set_mysocket_map(client_sock);
    printf("Maps updated\n");

    printf("Waiting for messages, press Ctrl+C to exit...\n");

    char buffer[BUFFER_SIZE];
    while (!stop)
    {
        printf("--------------------------------\n");
        ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0 || bytes_received >= sizeof(buffer) - 1)
        {
            printf("Error receiving message or message too long\n");
            break;
        }
        buffer[bytes_received] = '\0';
        printf("Received message: %s\n", buffer);

        // retrieve the message from the userMsg map
        struct msg_header msg = {0};
        int ret = bpf_map__lookup_and_delete_elem(userMsg, NULL, 0, &msg, sizeof(msg), 0); // pop
        if (ret != 0)
        {
            printf("No message data available\n");
        }
        else
        {
            print_msg(&msg);
        }

        // send the message back to the client
        ssize_t bytes_sent = send(client_sock, buffer, sizeof(buffer) - 1, 0);
        check_fd(bytes_sent, "Failed to send message");
    }

    cleanup_socket();
    printf("Socket closed\n");

    cleanup_bpf();
    printf("Successfully detached eBPF program\n");

    return 0;
}

void print_msg(struct msg_header *msg)
{

    char laddr[INET_ADDRSTRLEN], raddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &msg->laddr.in, laddr, sizeof(laddr));
    inet_ntop(AF_INET, &msg->raddr.in, raddr, sizeof(raddr));

    printf("Data: size=%u, laddr=%s:%u, raddr=%s:%u\n",
           msg->size,
           laddr,
           ntohs(msg->lport),
           raddr,
           ntohs(msg->rport));
}

void *client_thread(void *arg)
{
    sleep(3); // Wait for the server to be ready

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

    /*if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)
    {
        perror("Client: Invalid address or address not supported");
        close(client_fd);
        exit(1);
    }*/

    // Connect to the server
    err = connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    check_error(err, "Client: Connection failed");
    /*
    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Client: Connection failed");
        close(client_fd);
        exit(1);
    }*/

    while (!stop)
    {
        /*char buffer[BUFFER_SIZE];
        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0)
        {
            printf("Client: Server disconnected or error receiving message\n");
            break;
        }
        buffer[bytes_received] = '\0'; // Null-terminate the string
        printf("Client: Received: %s\n", buffer);*/
    }

    close(client_fd);
    return NULL;
}

void run_client()
{
    pthread_t client_thread_id;
    int err = pthread_create(&client_thread_id, NULL, client_thread, NULL);
    check_error(err, "Failed to create client thread");
    printf("Client thread created\n");
    // pthread_join(client_thread_id, NULL);
}

void setup_socket()
{
    int opt = 1;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    check_fd(sock, "Failed to create socket");

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(SRV_PORT)};

    int err = bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    check_fd(err, "Failed to bind socket");

    err = listen(sock, 5);
    check_fd(err, "Failed to listen on socket");
}

void cleanup_socket()
{
    if (client_sock == -1 && sock == -1)
        return;
    if (client_sock >= 0)
        close(client_sock);
    if (sock >= 0)
        close(sock);
}

void set_mysocket_map(int fd)
{
    int key = 0;
    int err = 0;

    // set mysocket as the one to send the intercepted messages
    err = bpf_map_update_elem(mysoc_fd, &key, &fd, BPF_ANY);
    check_error(err, "Failed to update mysoc map");

    printf("listening socket registered in mysoc map\n");

    // add mysocket to the sockmap to intercept the responses
    struct sock_descriptor desc = {0};

    struct sockaddr_in addr = {0};
    socklen_t len = sizeof(addr);
    err = getsockname(fd, (struct sockaddr *)&addr, &len);
    check_fd(err, "Failed to get socket name");

    struct sockaddr_in sa;
    socklen_t sa_len = sizeof(sa);
    err = getpeername(fd, (struct sockaddr *)&sa, &sa_len);
    check_fd(err, "Failed to get peer name");

    desc.ip = addr.sin_addr.s_addr;
    desc.sport = SRV_PORT;
    desc.dport = ntohs(sa.sin_port);

    // add the socket to the sockmap
    __u64 val = (__u64)client_sock;
    err = bpf_map_update_elem(sockmap_fd, &desc, &val, BPF_ANY);
    check_error(err, "Failed to update sockmap");

    printf("Resp sk registed: ip=%u, sport=%u, dport=%u\n",
           desc.ip,
           desc.sport,
           desc.dport);
}

void set_target_port(__u16 target_port, __u16 server_port)
{
    int key = 0;
    int err = 0;
    err = bpf_map_update_elem(targetport_fd, &key, &target_port, BPF_ANY);
    check_error(err, "Failed to update target_port map");

    // set the server port
    key = 1;
    err = bpf_map_update_elem(targetport_fd, &key, &server_port, BPF_ANY);
    check_error(err, "Failed to update server port map");
}

void handle_signal(int signal)
{
    stop = true;
}

void cleanup_bpf()
{
    int err = 0;

    // Detach sk_msg_prog from sockmap
    if (sockmap_fd > 0)
    {
        err = bpf_prog_detach2(prog_fd_sk_msg, sockmap_fd, BPF_SK_MSG_VERDICT);
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

    // Close all file descriptors
    if (cgroup_fd > 0)
        close(cgroup_fd);

    if (sockmap_fd > 0)
        close(sockmap_fd);

    if (mysoc_fd > 0)
        close(mysoc_fd);

    if (prog_fd_sockops > 0)
        close(prog_fd_sockops);

    if (prog_fd_sk_msg > 0)
        close(prog_fd_sk_msg);

    if (userMsg_fd > 0)
        close(userMsg_fd);

    // Destroy BPF object
    bpf_object__close(obj);
}

void setup_bpf()
{
    // open the BPF object file
    obj = bpf_object__open_file("scap.bpf.o", NULL);
    check_obj(obj, "Failed to open BPF object");

    // load the BPF object file into the kernel
    int err = bpf_object__load(obj);
    check_error(err, "Failed to load BPF object");

    struct bpf_map *sockmap, *mysoc, *targetport;

    // find the maps in the object file
    sockmap = bpf_object__find_map_by_name(obj, "sockmap");
    check_obj(sockmap, "Failed to find the sockmap");
    mysoc = bpf_object__find_map_by_name(obj, "mysoc");
    check_obj(mysoc, "Failed to find the mysoc map");
    userMsg = bpf_object__find_map_by_name(obj, "userMsg");
    check_obj(userMsg, "Failed to find the userMsg map");
    targetport = bpf_object__find_map_by_name(obj, "targetport");
    check_obj(targetport, "Failed to find the targetport map");

    // get the file descriptor for the map
    sockmap_fd = bpf_map__fd(sockmap);
    check_fd(sockmap_fd, "Failed to get sockmap fd");
    mysoc_fd = bpf_map__fd(mysoc);
    check_fd(mysoc_fd, "Failed to get mysoc fd");
    userMsg_fd = bpf_map__fd(userMsg);
    check_fd(userMsg_fd, "Failed to get userMsg fd");
    targetport_fd = bpf_map__fd(targetport);
    check_fd(targetport_fd, "Failed to get targetport fd");

    struct bpf_program *prog_sockops, *prog_sk_msg;

    // find the programs in the object file
    prog_sockops = bpf_object__find_program_by_name(obj, "sockops_prog");
    prog_fd_sockops = bpf_program__fd(prog_sockops);

    prog_sk_msg = bpf_object__find_program_by_name(obj, "sk_msg_prog");
    prog_fd_sk_msg = bpf_program__fd(prog_sk_msg);

    // get the file descriptor for the cgroup
    cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    check_fd(cgroup_fd, "Failed to open cgroup");
}

void run_bpf()
{
    int err = 0;

    // attach sockops_prog to the cgroup
    err = bpf_prog_attach(prog_fd_sockops, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
    check_error(err, "Failed to attach sockops_prog to cgroup");

    // Attach sk_msg_prog to the sockmap
    err = bpf_prog_attach(prog_fd_sk_msg, sockmap_fd, BPF_SK_MSG_VERDICT, 0);
    check_error(err, "Failed to attach sk_msg_prog to sockmap");
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