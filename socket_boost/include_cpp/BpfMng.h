
#pragma once

#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <vector>
#include <cstdint>

#include <common.h>
#include <SocketMng.h>
#include <config.h>

using RawCallback = int (*)(void *, std::size_t);

namespace bpf
{
    typedef struct
    {
        void *ctx;
        int (*handle_event)(void *ctx, void *data, size_t len);
    } EventHandler;

    class BpfMng
    {
    public:
        struct bpf_object *obj;

        // PROGS
        int prog_fd_sockops;
        int prog_fd_sk_msg;
        int cgroup_fd;
        const struct bpf_program *prog_tcp_destroy_sock;
        struct bpf_link *tcp_destroy_link;

        // MAPS
        int intercepted_sk_fd;
        int free_sk_fd;
        int target_ports_fd;
        int socket_association_fd;
        int server_port_fd;
        int target_ip_fd;
        int ring_buffer_fd;
        struct ring_buffer *rb;
        int sock_proxyfd_association_fd;

        pthread_t thread_pool_rb;
        int stop_threads;
        EventHandler new_sk_event_handler;

        BpfMng() = default;
        ~BpfMng()
        {
            destroy();
        }

        void init(EventHandler event_handler);
        void run();
        void destroy();
        void set_target_ports(const std::vector<uint16_t> &target_ports, uint16_t server_port);
        void set_target_ip(const std::vector<uint32_t> &target_ip);
        void push_sock_to_map(const std::vector<sk::client_sk_t> &client_sks);

        struct sock_id get_proxy_sk_from_app_sk(struct sock_id app_sk);
        struct sock_id get_app_sk_from_proxy_fd(const std::vector<sk::client_sk_t> &client_sks, int target_fd);
        struct sock_id get_app_sk_from_proxy_sk(struct sock_id proxy_sk);
        int get_proxy_fd_from_app_sk(struct sock_id app_sk);
        void add_app_sk_to_proxy_fd(struct sock_id app_sk, int proxy_fd);

    private:
        const char *CGROUP_PATH = "/sys/fs/cgroup";
        const char *PATH_TO_BPF_OBJ_FILE = "obj/scap.bpf.o";
        const int POOL_RB_INTERVAL = 100; // milliseconds

        void thread_poll_rb();
        void wrap_close(int fd);
    };
} // namespace bpf
