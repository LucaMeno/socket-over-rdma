
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

#include "RdmaContext.h"
#include "ThreadPool.h"
#include "BpfMng.h"
#include "SocketMng.h"
#include "common.h"

namespace rdmaMng
{
    struct WriterThreadData
    {
        sock_id app;
        rdma::RdmaContext *ctx;

        WriterThreadData(sock_id a, rdma::RdmaContext *c) : app(a), ctx(c) {}
        WriterThreadData() : app({0}), ctx(nullptr) {}
    };

    class RdmaMng
    {

    public:
        RdmaMng(uint16_t proxy_port, uint32_t proxy_ip, uint16_t rdma_port, const std::vector<uint16_t> &target_ports_to_set);
        ~RdmaMng();

        void run();
        void connect(struct sock_id original_socket, int proxy_sk_fd);

        static int wrapper(void *ctx, void *data, size_t len)
        {
            auto *self = static_cast<RdmaMng *>(ctx);
            return self->onNewSocket(data, len);
        }

        int onNewSocket(void *data, size_t len)
        {
            struct userspace_data_t *user_data = (struct userspace_data_t *)data;

            std::cout << "New : ["
                      << user_data->association.app.sip << ":"
                      << user_data->association.app.sport << " -> "
                      << user_data->association.app.dip << ":"
                      << user_data->association.app.dport << "] <-> ["
                      << user_data->association.proxy.sip << ":"
                      << user_data->association.proxy.sport << " -> "
                      << user_data->association.proxy.dip << ":"
                      << user_data->association.proxy.dport << "]"
                      << std::endl;

            // start the RDMA connection
            // only the client start the connection
            if (user_data->sockops_op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
            {
                int ret;
                int proxy_fd = sk_ctx.getProxyFdFromSockid(user_data->association.proxy);

                if (proxy_fd < 0)
                {
                    std::cerr << "Error: Proxy fd not found for association: "
                              << user_data->association.proxy.sip << ":"
                              << user_data->association.proxy.sport << std::endl;
                    throw std::runtime_error("Proxy fd not found");
                }

                std::cout << "Proxy fd: " << proxy_fd << std::endl;
                std::cout << "App socket: " << user_data->association.app.sip << ":" << user_data->association.app.sport << std::endl;

                connect(user_data->association.app, proxy_fd);
            }

            return 0;
        }

    private:
        std::vector<std::unique_ptr<rdma::RdmaContext>> ctxs; // vector of active RDMA contexts
        uint16_t rdma_port;                                   // port used for RDMA
        std::unique_ptr<ThreadPool> thPool;                   // thread pool
        bpf::BpfMng bpf_ctx;                                  // reference to the BPF manager
        sk::SocketMng sk_ctx;                                 // reference to the socket manager
        std::thread notification_thread;                      // thread for the notification
        std::thread server_thread;                            // thread for the server
        std::thread polling_thread;                           // thread for polling the circular buffer
        std::thread flush_thread;                             // thread for flushing the circular buffer
        std::vector<std::thread> writer_threads;              // threads for writing to the circular buffer
        std::mutex mtx_polling;                               // mutex for polling thread
        std::condition_variable cond_polling;                 // condition variable for polling
        bool is_polling_thread_running;                       // flag to indicate if the polling thread is running
        std::atomic<bool> stop_threads;                       // flag to stop the threads

        // Background thread functions
        void launchBackbroundThread();
        void listenThread();
        void serverThread();
        void pollingThread();
        void flushThread();
        void writerThread(std::vector<sk::client_sk_t> sk_to_monitor);

        // Thread worker functions (pool)
        void flushThreadWorker(rdma::RdmaContext &ctx);

        // Utils
        int getFreeContextId();
        rdma::RdmaContext *getContextByIp(uint32_t remote_ip);
        void startPolling(rdma::RdmaContext &ctx);
        void stopPolling(rdma::RdmaContext &ctx);
        void parseNotification(rdma::RdmaContext &ctx);
        int consumeRingbuffer(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb_remote);
        std::vector<int> waitOnSelect(const std::vector<int> &fds);

        WriterThreadData populateWriterThreadData(std::vector<sk::client_sk_t> &sockets, int fd);
    };

}
