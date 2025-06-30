
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

        // Initialize the RDMA manager
        void destroy();

        void rdma_manager_run();

        void rdma_manager_connect(struct sock_id original_socket, int proxy_sk_fd);

    private:
        std::vector<std::unique_ptr<rdma::RdmaContext>> ctxs; // vector of active RDMA contexts
        uint16_t rdma_port;                                   // port used for RDMA
        std::unique_ptr<ThreadPool> thPool;
        std::vector<sk::client_sk_t> &client_sks;

        bpf::BpfMng &bpf_ctx;

        std::thread notification_thread;         // thread for the notification
        std::thread server_thread;               // thread for the server
        std::thread polling_thread;              // thread for polling the circular buffer
        std::thread flush_thread;                // thread for flushing the circular buffer
        std::vector<std::thread> writer_threads; // threads for writing to the circular buffer

        std::mutex mtx_polling;
        std::condition_variable cond_polling; // condition variable for polling
        bool is_polling_thread_running;       // flag to indicate if the polling thread is running

        std::atomic<bool> stop_threads; // flag to stop the threads

        void rdma_manager_launch_background_threads();
        void rdma_manager_listen_thread();
        void rdma_manager_server_thread();
        void rdma_manager_polling_thread();
        void rdma_manager_flush_thread();
        void rdma_manager_writer_thread(std::vector<sk::client_sk_t> sk_to_monitor);

        void flush_thread_worker(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb, uint32_t start_idx, uint32_t end_idx);

        int rdma_manager_get_free_context_id();

        void rdma_manager_start_polling(rdma::RdmaContext &ctx);
        void rdma_manager_stop_polling(rdma::RdmaContext &ctx);
        void rdma_parse_notification(rdma::RdmaContext &ctx);
        int rdma_manager_consume_ringbuffer(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb_remote);
        void rdma_manager_flush_buffer(rdma::RdmaContext &ctx, rdma::rdma_ringbuffer_t &rb);

        rdma::RdmaContext *rdma_manager_get_context_by_ip(uint32_t remote_ip);

        std::vector<int> waitOnSelect(const std::vector<int> &fds);
    };

}
