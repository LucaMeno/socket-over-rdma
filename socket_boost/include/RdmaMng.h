
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

    struct ReaderThreadData
    {
        sock_id proxy_sk;
        sock_id app_sk;
        int dest_fd;
        std::atomic<bool> keep_run;
    };

    class RdmaMng
    {

    public:
        RdmaMng(uint16_t proxy_port, uint32_t proxy_ip, uint16_t rdma_port, const std::vector<uint16_t> &target_ports_to_set);
        ~RdmaMng();

        void run();
        void connect(struct sock_id original_socket);
        void onSocketOpen(sock_id_t proxy_sk, sock_id_t app_sk);
        void onSocketClose(sock_id_t proxy_sk, sock_id_t app_sk);

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
                                         const std::string &role)
            {
                std::cout << "[eBPF event] - "
                          << prefix << " "
                          << sk_ctx.get_printable_sockid(&app) << " <-> "
                          << sk_ctx.get_printable_sockid(&proxy) << " - "
                          << role
                          << std::endl;
            };

            switch (user_data->event_type)
            {
            case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            {
                logSocketEvent("NEW", user_data->association.app, user_data->association.proxy, "CLIENT");
                connect(user_data->association.app);
                onSocketOpen(user_data->association.proxy, user_data->association.app);
                break;
            }
            case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            {
                logSocketEvent("NEW", user_data->association.app, user_data->association.proxy, "SERVER");
                // server side, do not connect the RDMA contexts
                onSocketOpen(user_data->association.proxy, user_data->association.app);
                break;
            }
            case REMOVE_SOCKET:
            {
                logSocketEvent("REMOVE", user_data->association.app, user_data->association.proxy, "ND");
                onSocketClose(user_data->association.proxy, user_data->association.app);
                break;
            }
            default:
                std::cerr << "Unknown event type: " << user_data->event_type << std::endl;
                return -1; // Unknown event type
            }

            return 0;
        }

    private:
        std::mutex mtx_ctxs;
        std::vector<std::unique_ptr<rdma::RdmaContext>> ctxs; // vector of active RDMA contexts
        uint16_t rdma_port;                                   // port used for RDMA
        std::unique_ptr<ThreadPool> thPool;                   // thread pool
        bpf::BpfMng bpf_ctx;                                  // reference to the BPF manager
        sk::SocketMng sk_ctx;                                 // reference to the socket manager
        std::thread notification_thread;                      // thread for the notification
        std::thread server_thread;                            // thread for the server
        std::thread flush_thread;                             // thread for flushing the circular buffer
        std::vector<std::thread> writer_threads;              // threads for writing to the circular buffer
        std::atomic<bool> stop_threads;                       // flag to stop the threads

        std::mutex mtx_sk_removal_tx;
        std::vector<int> sk_to_remove_tx;
        std::atomic<bool> remove_sk_tx;

        std::mutex mtx_sk_removal_rx;
        std::vector<struct sock_id> sk_to_remove_rx;
        std::atomic<bool> remove_sk_rx;

        ReaderThreadData readThParams[Config::N_READER_THREADS]; // Array of flags to indicate if the reader threads are running
        std::condition_variable cond_wait_for_sk;
        std::mutex mtx_wait_for_sk;
        std::vector<std::thread> reader_th_master;
        std::vector<std::thread> reader_th_workers;

        void readThreadWorker2(ReaderThreadData &params);
        void launchReaderThWorker(sock_id_t proxy_sk, sock_id_t app_sk);
        void readThreadMaster(rdma::RdmaContext &ctx);
        void updateRemoteReadIdxWorker(rdma::RdmaContext &ctx);
        void launchReaderThMaster(rdma::RdmaContext &ctx);

        // Background thread functions
        void launchBackgroundThreads(rdma::RdmaContext &ctx);
        void listenThread();
        void serverThread();
        void flushThread();
        void writerThread(std::vector<sk::client_sk_t> sk_to_monitor);

        // Thread worker functions (pool)
        void flushThreadWorker(rdma::RdmaContext &ctx, bool updateRemoteIndex);

        // Utils
        int getFreeContextId();
        rdma::RdmaContext *getContextByIp(uint32_t remote_ip);
        void startPolling(rdma::RdmaContext &ctx);
        void stopPolling(rdma::RdmaContext &ctx);
        void parseNotification(rdma::RdmaContext &ctx);
        std::vector<int> waitOnSelect(const std::vector<int> &fds);

        WriterThreadData populateWriterThreadData(std::vector<sk::client_sk_t> &sockets, int fd);
    };
}
