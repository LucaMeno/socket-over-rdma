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
#include <sstream>

#include <common.h>
#include <Config.hpp>

#include "Logger.h"

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

        SocketMng();
        ~SocketMng();

        void init(uint16_t port, uint32_t ip);
        int getProxyFdFromSockid(struct sock_id sk_id);

        static std::string getPrintableSkId(const struct sock_id &sockid)
        {
            char sip_str[INET_ADDRSTRLEN];
            char dip_str[INET_ADDRSTRLEN];

            if (!inet_ntop(AF_INET, &sockid.sip, sip_str, sizeof(sip_str)))
                return "<invalid sip>";
            if (!inet_ntop(AF_INET, &sockid.dip, dip_str, sizeof(dip_str)))
                return "<invalid dip>";

            std::ostringstream oss;
            oss << '[' << sip_str << ':' << sockid.sport
                << "->" << dip_str << ':' << sockid.dport << ']';
            return oss.str();
        }

        static bool areSkEqual(const struct sock_id &sk1, const struct sock_id &sk2)
        {
            return sk1.sip == sk2.sip &&
                   sk1.dip == sk2.dip &&
                   sk1.sport == sk2.sport &&
                   sk1.dport == sk2.dport;
        }

        static bool isSkIdValid(const struct sock_id &sk)
        {
            return sk.sip != 0 &&
                   sk.dip != 0 &&
                   sk.sport != 0 &&
                   sk.dport != 0;
        }

    private:
        int shared = 0;
        std::mutex mutex;
        std::condition_variable cond_var;
        std::vector<std::thread> client_threads;

        Logger logger{"SocketMng"};

        void setSocketNonblocking(int sockfd);
        void clientThread(int client_id);
    };

}