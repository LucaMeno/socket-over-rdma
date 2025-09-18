
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
#include <Logger.h>

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

        pthread_t thread_pool_rb;
        bool stop_threads;
        EventHandler new_sk_event_handler;

        BpfMng();
        ~BpfMng();

        void init(EventHandler event_handler, const std::vector<uint16_t> &target_ports_to_set, uint16_t proxy_port, const std::vector<sk::client_sk_t> &client_sks);

        struct sock_id getProxySkFromAppSk(struct sock_id app_sk);
        struct sock_id getAppSkFromProxyFd(const std::vector<sk::client_sk_t> &client_sks, int target_fd);
        struct sock_id getAppSkFromProxySk(struct sock_id proxy_sk);

    private:
        Logger logger{"BpfMng"};
        std::thread rb_thread;

        void threadPollRb();
        void wrapClose(int fd);
        void setTargetPort(const std::vector<uint16_t> &target_ports, uint16_t server_port);
        void setTargetIp(const std::vector<uint32_t> &target_ip);
        void pushSockToMap(const std::vector<sk::client_sk_t> &client_sks);
    };
} // namespace bpf
