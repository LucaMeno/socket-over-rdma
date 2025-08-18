
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
            return self->bpfEventHandler(data, len);
        }

        int bpfEventHandler(void *data, size_t len)
        {
            struct userspace_data_t *user_data = (struct userspace_data_t *)data;

            // Lambda for logging
            auto logSocketEvent = [this](const std::string &prefix,
                                         struct sock_id &app,
                                         struct sock_id &proxy,
                                         const std::string &role,
                                         int fd)
            {
                std::cout << prefix << " "
                          << sk_ctx.get_printable_sockid(&app) << " <-> "
                          << sk_ctx.get_printable_sockid(&proxy) << " - "
                          << role << " - fd: " << fd
                          << std::endl;
            };

            switch (user_data->event_type)
            {
            case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            {
                int ret;
                int proxy_fd = sk_ctx.getProxyFdFromSockid(user_data->association.proxy);
                connect(user_data->association.app, proxy_fd);

                logSocketEvent("NEW", user_data->association.app, user_data->association.proxy, "CLIENT", proxy_fd);

                break;
            }
            case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            {
                logSocketEvent("NEW", user_data->association.app, user_data->association.proxy, "SERVER", -1);
                // server side, do not connect the RDMA context
                break;
            }
            case REMOVE_SOCKET:
            {
                int ret;
                int proxy_fd = sk_ctx.getProxyFdFromSockid(user_data->association.proxy);

                {
                    std::unique_lock<std::mutex> lock(mtx_sk_removal_tx);
                    sk_to_remove_tx.push_back(proxy_fd);
                }
                remove_sk_tx.store(true, std::memory_order_release);

                {
                    std::unique_lock<std::mutex> lock(mtx_sk_removal_rx);
                    struct sock_id swapped;
                    swapped.sip = user_data->association.app.dip;
                    swapped.dip = user_data->association.app.sip;
                    swapped.dport = user_data->association.app.sport;
                    swapped.sport = user_data->association.app.dport;
                    sk_to_remove_rx.push_back(swapped);
                }
                remove_sk_rx.store(true, std::memory_order_release);

                logSocketEvent("REMOVE", user_data->association.app, user_data->association.proxy, "ND", proxy_fd);
                break;
            }
            default:
                std::cerr << "Unknown event type: " << user_data->event_type << std::endl;
                return -1; // Unknown event type
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

        std::mutex mtx_sk_removal_tx;
        std::vector<int> sk_to_remove_tx;
        std::atomic<bool> remove_sk_tx;

        std::mutex mtx_sk_removal_rx;
        std::vector<struct sock_id> sk_to_remove_rx;
        std::atomic<bool> remove_sk_rx;

        // Background thread functions
        void launchBackgroundThreads();
        void listenThread();
        void serverThread();
        void pollingThread();
        void flushThread();
        void writerThread(std::vector<sk::client_sk_t> sk_to_monitor);

        // Thread worker functions (pool)
        void flushThreadWorker(rdma::RdmaContext &ctx, bool updateRemoteIndex);
        void readThreadWorker(rdma::RdmaContext &ctx, uint32_t start_read_index, uint32_t end_read_index);

        // Utils
        int getFreeContextId();
        rdma::RdmaContext *getContextByIp(uint32_t remote_ip);
        void startPolling(rdma::RdmaContext &ctx);
        void stopPolling(rdma::RdmaContext &ctx);
        void parseNotification(rdma::RdmaContext &ctx);
        int consumeRingbuffer(rdma::RdmaContext &ctx);
        std::vector<int> waitOnSelect(const std::vector<int> &fds);

        WriterThreadData populateWriterThreadData(std::vector<sk::client_sk_t> &sockets, int fd);
    };
}
