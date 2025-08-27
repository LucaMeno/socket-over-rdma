
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
#include <fcntl.h>

#include "RdmaTransfer.h"
#include "ThreadPool.h"

namespace Manager
{
    class Manager
    {

    public:
        Manager();
        ~Manager();

        void client(uint32_t ip);
        void server();
        void run(int fd);

    private:
        rdmat::RdmaTransfer *ctx;

        std::atomic<bool> stop_threads; // flag to stop the threads

        uint16_t rdma_port;                 // port used for RDMA
        std::unique_ptr<ThreadPool> thPool; // thread pool
        std::thread reading_thread;         // thread for polling the circular buffer
        std::thread flush_thread;           // thread for flushing the circular buffer
        std::thread writer_threads;         // threads for writing to the circular buffer


        // Background thread functions
        void readerThread(int fd);
        void flushThread();
        void writerThread(int fd);

        std::vector<int> waitOnSelect(const std::vector<int> &fds);
    };
}
