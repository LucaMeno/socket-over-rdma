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
        uint16_t server_port;
        uint32_t server_ip;

        SocketMng(uint16_t port, uint32_t ip);
        ~SocketMng();

        int getProxyFdFromSockid(struct sock_id sk_id);

    private:
        int shared = 0;
        std::mutex mutex;
        std::condition_variable cond_var;
        std::vector<std::thread> client_threads;

        void setSocketNonblocking(int sockfd);
        void clientThread(int client_id);
    };

}