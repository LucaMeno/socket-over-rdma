
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

#include "RdmaContext.h"
#include "ThreadPool.h"
#include "BpfMng.h"
#include "SocketMng.h"
#include "common.h"

namespace rdmaMng
{
    class RdmaMng
    {
        const int N_WRITER_THREADS = NUMBER_OF_SOCKETS; // 1 thread per proxy socket
        const int TIME_STOP_SELECT_SEC = 5;             // 5 seconds
        const int FLUSH_INTERVAL_MS = 100;              // ms

    public:
        RdmaMng(uint16_t srv_port, std::vector<sk::client_sk_t> &proxy_sks, bpf::BpfMng &bpf);
        ~RdmaMng();

        void run();
        void connect(struct sock_id original_socket, int proxy_sk_fd);

    private:
        std::vector<std::unique_ptr<rdma::RdmaContext>> ctxs; // vector of active RDMA contexts
        uint16_t rdma_port;                                   // port used for RDMA
        std::unique_ptr<ThreadPool> thPool;                   // thread pool
        std::vector<sk::client_sk_t> &client_sks;             // vector of client sockets to monitor
        bpf::BpfMng &bpf_ctx;                                 // reference to the BPF manager
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
        void addFlushRingbufferJob(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb);
        void flushThreadWorker(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb, uint32_t start_idx, uint32_t end_idx);

        // Utils
        int getFreeContextId();
        rdma::RdmaContext *getContextByIp(uint32_t remote_ip);
        void startPolling(rdma::RdmaContext &ctx);
        void stopPolling(rdma::RdmaContext &ctx);
        void parseNotification(rdma::RdmaContext &ctx);
        int consumeRingbuffer(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb_remote);
        std::vector<int> waitOnSelect(const std::vector<int> &fds);
    };

}
