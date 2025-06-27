#pragma once

#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <stdexcept>
#include <vector>
#include <iostream>

#include <common.h>
#include <config.h>

constexpr int NUMBER_OF_SOCKETS = 16;

namespace sk
{
    typedef struct
    {
        int fd;
        struct sock_id sk_id;
    } client_sk_t;

    class SocketMng
    {
    public:
        std::vector<client_sk_t> client_sk_fd;
        int server_sk_fd;
        __u16 server_port;
        __u32 server_ip;

        SocketMng()
        {
            client_sk_fd.resize(NUMBER_OF_SOCKETS);
            server_sk_fd = -1;
            server_port = 0;
            server_ip = 0;
        }

        ~SocketMng()
        {
            destroy();
        }

        void init(uint16_t port, uint32_t ip);
        void destroy();
        int get_proxy_fd_from_sockid(struct sock_id sk_id);

    private:
        int shared = 0;
        std::mutex mutex;
        std::condition_variable cond_var;
        std::vector<std::thread> client_threads;

        void set_socket_nonblocking(int sockfd);
        void clientThread(int client_id);
    };

}