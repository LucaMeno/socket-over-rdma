
#include "Manager.h"

using namespace std;
using namespace rdmat;

namespace Manager
{
    Manager::Manager()
    {
        stop_threads.store(false);

        // setup the pool
        thPool = make_unique<ThreadPool>(RdmaTestConf::N_THREAD_POOL_THREADS);

        cout << "==================  RdmaTestConfURATION ==================" << endl;

        cout << "RdmaTestConfuration:" << endl;
        cout << " RDMA port: " << rdma_port << endl;
        cout << " RDMA TCP port: " << RdmaTestConf::RDMA_TCP_PORT << endl;
        cout << " MAX_PAYLOAD_SIZE: " << (RdmaTestConf::MAX_PAYLOAD_SIZE / 1024) << "kB" << endl;
        cout << " MAX_MSG_BUFFER: " << (RdmaTestConf::MAX_MSG_BUFFER / 1024) << "k" << endl;
        cout << " N_THREAD_POOL_THREADS: " << RdmaTestConf::N_THREAD_POOL_THREADS << endl;
        cout << " Q pairs: " << RdmaTestConf::QP_N << endl;

        cout << endl
             << "=======================================================" << endl;
    }

    Manager::~Manager()
    {
        stop_threads.store(true, memory_order_release);
    }

    void Manager::run(int fd)
    {
        if (fd < 0 || ctx == nullptr)
            throw runtime_error("Invalid socket fd or ctx in run");

        reading_thread = thread(&Manager::readerThread, this, fd);
        flush_thread = thread(&Manager::flushThread, this);
        writer_threads = thread(&Manager::writerThread, this, fd);
    }

    void Manager::writerThread(int fd)
    {
        if (fd < 0 || ctx == nullptr)
            throw runtime_error("Invalid socket fd or ctx in writer thread");

        try
        {
            while (!stop_threads.load())
            {
                vector<int> ready_fd = waitOnSelect({fd});

                for (size_t i = 0; i < ready_fd.size(); ++i)
                {
                    int fd = ready_fd[i];

                    sock_id_t tmp = {0};
                    int ret = ctx->writeMsg(fd, tmp);

                    if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                        throw runtime_error("Connection closed - writerThread err: " + std::to_string(ret) + " errno: " + std::to_string(errno));
                }
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in writerThread: " << e.what() << endl;
            perror("   - Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    void Manager::readerThread(int fd)
    {
        if (fd < 0 || ctx == nullptr)
            throw runtime_error("Invalid socket fd or ctx in reader thread");

        cout << "Reader thread started" << endl;
        try
        {

            while (true)
            {
                uint32_t remote_w = ctx->buffer_to_read->remote_write_index.load();
                uint32_t local_r = ctx->buffer_to_read->local_read_index;

                if (remote_w != local_r)
                {
                    // set the local read index to avoid reading the same data again
                    uint32_t start_read_index = local_r;
                    uint32_t end_read_index = remote_w;

                    ctx->buffer_to_read->local_read_index = remote_w; // reset the local write index

                    thPool->enqueue([this, start_read_index, end_read_index, fd]()
                                    { readThreadWorker(start_read_index, end_read_index, fd); });

                    thPool->enqueue([this, end_read_index]()
                                    { ctx->updateRemoteReadIndex(end_read_index); });
                }
                if (stop_threads.load())
                    return;
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in pollingThread2: " << e.what() << endl;
            perror("Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    void Manager::readThreadWorker(uint32_t start_read_index, uint32_t end_read_index, int fd)
    {
        try
        {
            while (ctx->buffer_to_read->remote_read_index.load() != start_read_index)
                if (ctx->stop.load())
                    return; // Exit if stop is set

            int ret = ctx->readMsg(start_read_index, end_read_index, fd);
            if (ret != 0)
                cerr << "Error reading messages: " << ret << endl;

            ctx->buffer_to_read->remote_read_index.store(end_read_index, memory_order_release);

            unique_lock<mutex> commit_lock(ctx->mtx_rx_commit);
            ctx->updateRemoteReadIndex(end_read_index);
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in readThreadWorker: " << e.what() << endl;
            perror("Details");
        }
    }

    void Manager::client(uint32_t ip, uint16_t port)
    {
        if (ctx == nullptr)
            ctx = new rdmat::RdmaTransfer();

        ctx->remote_ip = ip;

        ctx->clientConnect(ip, port);
    }

    void Manager::server(uint16_t port)
    {
        cout << "Server thread started" << endl;
        try
        {
            while (stop_threads.load() == false)
            {
                ctx = new rdmat::RdmaTransfer();
                serverConnection_t sc = ctx->serverSetup();

                vector<int> fds = {sc.fd};
                while (stop_threads.load() == false && waitOnSelect(fds).empty())
                    ;

                if (stop_threads.load() == true)
                    return; // Exit if stop_threads is set

                ctx->serverHandleNewClient(sc);
            }
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in serverThread: " << e.what() << endl;
            perror("Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    void Manager::flushThread()
    {
        if (ctx == nullptr)
            throw runtime_error("Invalid ctx in flush thread");

        cout << "[Startup] -- Flush thread started" << endl;

        while (stop_threads.load() == false)
        {
            auto data = ctx->getPollingBatch(); // copy
            ctx->last_flush_ms = ctx->getTimeMS();
            thPool->enqueue([this, data]() { // lambda has its own copy
                if (ctx->postWrBatch(data))
                    ctx->updateRemoteWriteIndex();
            });
        }

        cout << "[Shutdown] Flush thread stopped" << endl;
    }

    vector<int> Manager::waitOnSelect(const vector<int> &fds)
    {
        if (fds.empty())
            return {}; // Nothing to watch.

        // Create epoll instance
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1)
            throw std::runtime_error("epoll_create1() failed");

        // Register all fds
        for (int fd : fds)
        {
            if (fd < 0)
                continue;

            struct epoll_event ev = {};
            ev.events = EPOLLIN;
            ev.data.fd = fd;

            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1)
                throw std::runtime_error("epoll_ctl failed for fd " + std::to_string(fd));
        }

        std::vector<int> result;
        const int MAX_EVENTS = 256;
        struct epoll_event events[MAX_EVENTS];

        while (!stop_threads.load())
        {
            int timeout_ms = RdmaTestConf::TIME_STOP_SELECT_SEC * 1000;
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout_ms);

            if (nfds < 0)
            {
                throw std::runtime_error("epoll_wait() failed");
            }
            else if (nfds > 0)
            {
                result.reserve(nfds);
                for (int i = 0; i < nfds; ++i)
                    result.push_back(events[i].data.fd);
                break;
            }

            // If timeout with 0 fds, loop again (or exit on stop_threads)
        }

        close(epoll_fd);
        return result;
    }
};