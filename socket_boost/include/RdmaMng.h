
#pragma once

#include <cstdint>
#include <atomic>
#include <vector>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <thread>
#include <condition_variable>
#include <memory>
#include <poll.h>
#include <iostream>
#include <stdexcept>
#include <format>
#include <functional>
#include <sys/epoll.h>

#include "RdmaContext.h"
#include "BpfMng.h"
#include "SocketMng.h"
#include "common.h"
#include "Logger.h"

namespace rdmaMng
{
    struct ThreadContext
    {
        int fd;
        sock_id proxy;
        sock_id app;
        rdma::RdmaContext *ctx;

        ThreadContext(sock_id p, sock_id a, int f, rdma::RdmaContext *c) : proxy(p), app(a), fd(f), ctx(c) {}
        ThreadContext(sock_id p, int f) : proxy(p), app({0, 0, 0, 0}), fd(f), ctx(nullptr) {}
        ThreadContext() : proxy({0, 0, 0, 0}), app({0, 0, 0, 0}), fd(-1), ctx(nullptr) {}

        std::string toString() const
        {
            std::ostringstream oss;
            oss << "FD: " << fd
                << " | Proxy: " << sk::SocketMng::getPrintableSkId(proxy)
                << " | App: " << sk::SocketMng::getPrintableSkId(app)
                << " | Ctx: " << (ctx ? "ok" : "nullptr");
            return oss.str();
        }
    };

    class RdmaMng
    {

    public:
        RdmaMng(uint16_t proxy_port, uint32_t proxy_ip, uint16_t rdma_port, const std::vector<uint16_t> &target_ports_to_set);
        ~RdmaMng();

        static int wrapper(void *ctx, void *data, size_t len)
        {
            auto *self = static_cast<RdmaMng *>(ctx);
            return self->bpfEventHandler(data, len);
        }


    private:
        std::vector<std::unique_ptr<rdma::RdmaContext>> ctxs; // vector of active RDMA contexts
        uint16_t rdma_port;                                   // port used for RDMA
        bpf::BpfMng bpf_ctx;                                  // reference to the BPF manager
        sk::SocketMng sk_ctx;                                 // reference to the socket manager
        std::thread notification_thread;                      // thread for the notification
        std::thread server_thread;                            // thread for the server
        std::vector<std::thread> writer_threads;              // threads for writing to the circular buffer
        std::vector<std::thread> reader_threads;              // threads for writing to the circular buffer
        std::atomic<bool> stop_threads;                       // flag to stop the threads

        std::mutex mtx_reader_thread;
        std::condition_variable cv_reader_thread;
        std::vector<struct sock_id> ready_sockets_to_read;

        std::unordered_map<int, std::atomic<sock_id_t>> fd_sk_asoc_map; // map of fd to sock_id association

        std::mutex mtx_ctx_access;

        Logger logger{"RdmaMng"};

        // Background thread functions
        void launchBackgroundThreads();
        void listenThread();
        void serverThread();
        void writerThread(std::vector<ThreadContext> tcs);
        void readerThread(ThreadContext tc);

        // Utils
        int getFreeContextId();
        rdma::RdmaContext *getContextByIp(uint32_t remote_ip);
        void startPolling(rdma::RdmaContext &ctx);
        void stopPolling(rdma::RdmaContext &ctx);
        void parseNotification(rdma::RdmaContext &ctx);
        std::vector<int> waitOnSelect(const std::vector<int> &fds);

        void fillThreadContext(ThreadContext &tc);
        void setFdSkAssociation(int fd, sock_id_t sk_id);
        bool isFdValid(int fd);

        int bpfEventHandler(void *data, size_t len);
        void connect(struct sock_id original_socket);
        void wakeReaderThread();
        void run();
    };
}
