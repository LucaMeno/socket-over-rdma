
#include "Manager.h"

using namespace std;
using namespace rdmat;

namespace Manager
{
    Manager::Manager()
    {
        ctx = nullptr;
        stop_threads.store(false);

        cout << "==================  RdmaTestConfURATION ==================" << endl;

        cout << "RdmaTestConfuration:" << endl;
        cout << " RDMA port: " << rdma_port << endl;
        cout << " RDMA TCP port: " << RdmaTestConf::RDMA_TCP_PORT << endl;
        cout << " MAX_PAYLOAD_SIZE: " << (RdmaTestConf::MAX_PAYLOAD_SIZE / 1024) << "kB" << endl;
        cout << " MAX_MSG_BUFFER: " << (RdmaTestConf::MAX_MSG_BUFFER / 1024) << "k" << endl;
        cout << " Q pairs: " << RdmaTestConf::QP_N << endl;

        cout << endl
             << "=======================================================" << endl;
    }

    Manager::~Manager()
    {
        stop_threads.store(true, memory_order_release);
        if (reading_thread.joinable())
            reading_thread.join();
        for (size_t i = 0; i < RdmaTestConf::QP_N - 1; i++)
            if (flush_thread[i].joinable())
                flush_thread[i].join();
        if (writer_threads.joinable())
            writer_threads.join();
        if (update_idx_thread.joinable())
            update_idx_thread.join();
    }

    void Manager::run(int fd)
    {
        if (fd < 0 || ctx == nullptr)
            throw runtime_error("Invalid socket fd or ctx in run");

        reading_thread = thread(&Manager::readerThread, this, fd);
        pthread_setname_np(reading_thread.native_handle(), "READING_TH");
        for (size_t i = 0; i < RdmaTestConf::QP_N - 1; i++)
        {
            flush_thread[i] = thread(&Manager::flushThread, this);
            pthread_setname_np(flush_thread[i].native_handle(), ("FLUSH_TH" + to_string(i)).c_str());
        }
        writer_threads = thread(&Manager::writerThread, this, fd);
        pthread_setname_np(writer_threads.native_handle(), "WRITER_TH");
        update_idx_thread = thread(&Manager::updateIdxThread, this);
        pthread_setname_np(update_idx_thread.native_handle(), "UPD_IDX_TH");
    }

    void Manager::writerThread(int fd)
    {
        if (fd < 0 || ctx == nullptr)
            throw runtime_error("Invalid socket fd or ctx in writer thread");
        try
        {
            while (!stop_threads.load())
            {
                waitOnSelect({fd});
                sock_id_t tmp = {0};
                int ret = ctx->writeMsg(fd, tmp);
                if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    throw runtime_error("Error in writeMsg, ret: " + to_string(ret));
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
            ctx->readMsgLoop(fd);
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in pollingThread2: " << e.what() << endl;
            perror("Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    void Manager::client(uint32_t ip)
    {
        if (ctx == nullptr)
            ctx = new rdmat::RdmaTransfer();

        try
        {
            ctx->remote_ip = ip;
            ctx->clientConnect(ip);
        }
        catch (const std::exception &e)
        {
            cerr << "Exception in client: " << e.what() << endl;
            perror("Details");
            throw; // Re-throw the exception to be handled by the caller
        }
    }

    void Manager::server()
    {
        cout << "Server thread started" << endl;
        try
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
            ctx->flushThread();
        }

        cout << "[Shutdown] Flush thread stopped" << endl;
    }

    void Manager::updateIdxThread()
    {
        if (ctx == nullptr)
            throw runtime_error("Invalid ctx in updateIdx thread");

        cout << "[Startup] -- UpdateIdx thread started" << endl;

        while (stop_threads.load() == false)
        {
            ctx->updateRemoteReadIndex();
        }

        cout << "[Shutdown] UpdateIdx thread stopped" << endl;
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