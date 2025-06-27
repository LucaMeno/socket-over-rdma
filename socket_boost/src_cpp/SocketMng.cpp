#include <SocketMng.h>

using namespace std;

namespace sk
{
    void SocketMng::init(uint16_t port, uint32_t ip)
    {
        server_port = port;
        server_ip = ip;

        server_sk_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_sk_fd < 0)
        {
            throw std::runtime_error("Failed to create server socket");
        }

        int opt = 1;
        if (setsockopt(server_sk_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
        {
            throw std::runtime_error("Failed to set socket options");
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        server_addr.sin_port = htons(server_port);

        if (bind(server_sk_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) != 0)
        {
            throw std::runtime_error("Failed to bind server socket");
        }

        if (listen(server_sk_fd, NUMBER_OF_SOCKETS) != 0)
        {
            throw std::runtime_error("Failed to listen on server socket");
        }

        in_addr ip_addr{};
        ip_addr.s_addr = server_ip;
        std::cout << "Server listening on " << inet_ntoa(ip_addr) << ":" << server_port << "\n";
        std::cout << "Launching client threads...\n";

        for (int i = 0; i < NUMBER_OF_SOCKETS; ++i)
        {
            client_threads.emplace_back(&SocketMng::clientThread, this, i);
        }

        for (int i = 0; i < NUMBER_OF_SOCKETS; ++i)
        {
            int tmp_fd = accept(server_sk_fd, nullptr, nullptr);
            if (tmp_fd < 0)
            {
                throw std::runtime_error("Failed to accept connection");
            }
            set_socket_nonblocking(tmp_fd);
        }

        set_socket_nonblocking(server_sk_fd);

        for (auto &thread : client_threads)
        {
            thread.detach();
        }

        std::cout << "All clients connected (" << NUMBER_OF_SOCKETS << ")\n";
    }

    void SocketMng::destroy()
    {
        std::cout << "Destroying SocketMng...\n";

        // Notify all threads to exit
        unique_lock<std::mutex> lock(mutex);
        shared = 1;
        cond_var.notify_all();
        lock.unlock();

        for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        {
            if (client_sk_fd[i].fd >= 0)
                close(client_sk_fd[i].fd);
            if (client_threads[i].joinable())
                client_threads[i].join();
        }

        if (server_sk_fd >= 0)
            close(server_sk_fd);
    }

    void SocketMng::set_socket_nonblocking(int sockfd)
    {
        int flags = fcntl(sockfd, F_GETFL, 0);
        if (flags < 0)
        {
            throw std::runtime_error("fcntl(F_GETFL) failed");
        }

        if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            throw std::runtime_error("fcntl(F_SETFL) failed");
        }
    }

    void SocketMng::clientThread(int client_id)
    {
        this_thread::sleep_for(chrono::seconds(2));

        int client_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client_fd < 0)
            throw runtime_error("Failed to create client socket");

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        server_addr.sin_addr.s_addr = server_ip;

        if (connect(client_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) != 0)
        {
            close(client_fd);
            throw runtime_error("Failed to connect to server");
        }

        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        if (getsockname(client_fd, reinterpret_cast<sockaddr *>(&client_addr), &addr_len) != 0)
        {
            close(client_fd);
            throw runtime_error("Failed to get client socket address");
        }

        client_sk_fd[client_id].sk_id.sip = client_addr.sin_addr.s_addr;
        client_sk_fd[client_id].sk_id.sport = ntohs(client_addr.sin_port);
        client_sk_fd[client_id].fd = client_fd;
        client_sk_fd[client_id].sk_id.dip = server_ip;
        client_sk_fd[client_id].sk_id.dport = server_port;

        set_socket_nonblocking(client_fd);

        unique_lock<std::mutex> lock(mutex);
        cond_var.wait(lock, [this]()
                      { return shared == 1; });
    }

    int SocketMng::get_proxy_fd_from_sockid(struct sock_id sk_id)
    {
        for (int i = 0; i < NUMBER_OF_SOCKETS; i++)
        {
            if (client_sk_fd[i].sk_id.sport == sk_id.sport &&
                client_sk_fd[i].sk_id.sip == sk_id.sip &&
                client_sk_fd[i].sk_id.dport == sk_id.dport &&
                client_sk_fd[i].sk_id.dip == sk_id.dip)
            {
                return client_sk_fd[i].fd;
            }
        }
        throw std::runtime_error("Socket not found");
    }
}
