
#include <Manager.h>
#include <signal.h>
#include <optional>
#include <thread>
#include <future>
#include <pthread.h>

int STOP = false;

using namespace std;

void server_thread();
int server_local();
ssize_t recv_all_test_rdma(int socket, void *buffer, size_t length);

void handle_signal(int signal)
{
    STOP = true;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <dev_idx> <GID>\n";
        return 1;
    }

    int dev_idx = std::atoi(argv[1]);
    int gid = std::atoi(argv[2]);

    RdmaTestConf::setDevIdx(dev_idx);
    RdmaTestConf::setRdmaDevGidIdx(gid);
    signal(SIGINT, handle_signal);
    signal(SIGTSTP, handle_signal);

    Manager::Manager manager;

    manager.server();

    thread server_th(server_thread);
    pthread_setname_np(server_th.native_handle(), "SERVER_RX");
    int fd = server_local();
    cout << "FD: " << fd << endl;

    manager.run(fd);

    cout << "Waiting for messages, press Ctrl+C to exit..." << endl;
    cout << "-----------------------------------------------------------" << endl;
    while (!STOP)
        pause(); // wait for signal
    cout << "-----------------------------------------------------------" << endl;

    return 0;
}

void server_thread()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return;
    }

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT);
    if (inet_pton(AF_INET, LOCALHOST, &srv.sin_addr) <= 0)
    {
        perror("inet_pton");
        return;
    }

    if (connect(sock, reinterpret_cast<sockaddr *>(&srv), sizeof(srv)) < 0)
    {
        perror("connect");
        return;
    }

    char start_buf[16] = {};
    recv(sock, start_buf, sizeof(start_buf), 0);
    send(sock, start_buf, sizeof(start_buf), 0);

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1)
    {
        std::cerr << " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Errore F_GETFL\n";
        return;
    }

    if (flags & O_NONBLOCK)
        cout << "Socket is already non-blocking\n";
    else
        cout << "Socket is blocking, setting to non-blocking\n";

    flags |= O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) == -1)
    {
        std::cerr << " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Errore F_SETFL\n";
        return;
    }

    char *buf = new char[BUFFER_SIZE_BYTES];
    uint64_t tot_bytes = 0;

    uint64_t quantity_of_data_to_rx = static_cast<uint64_t>(DEFAULT_TOTAL_GB * BYTES_PER_GB);

    int i = 0;
    bool is_first = true;
    uint64_t counter = 0;
    uint64_t local_counter_test;

    auto t0 = std::chrono::high_resolution_clock::now();
    while (true)
    {
        ssize_t n;

        if (quantity_of_data_to_rx == 0)
            break;

        n = recv_all_test_rdma(sock, buf, BUFFER_SIZE_BYTES);
        if (n <= 0)
        {
            if (n < 0)
                perror("recv - srv");
            break;
        }

        tot_bytes += static_cast<uint64_t>(n);
        quantity_of_data_to_rx -= static_cast<uint64_t>(n);

        if (CHECK_INTEGRITY)
        {
            memcpy(&local_counter_test, buf, sizeof(local_counter_test));
            if (is_first && local_counter_test != counter)
            {
                is_first = false;
                cerr << "------------------- Data mismatch: expected " << counter
                     << ", got " << local_counter_test << "\n";
            }
            ++counter;
        }

        if (tot_bytes >= BYTES_PER_GB * i)
        {
            ++i;
            cout << "Recv " << (tot_bytes / BYTES_PER_GB) << " GB so far\n";
        }
    }

    cout << "EXIT" << std::endl;

    auto t1 = std::chrono::high_resolution_clock::now();

    double sec = std::chrono::duration<double>(t1 - t0).count();
    double gbyte = tot_bytes / static_cast<double>(BYTES_PER_GB);
    double gbps = gbyte / sec;
    gbps *= 8; // Convert to Gb/s

    std::cout << "Rx " << gbyte << " GB in " << sec << " s (" << gbps << " Gb/s)\n";

    send(sock, ACK_MESSAGE, std::strlen(ACK_MESSAGE), 0);

    std::cout << "ACK sent\n";

    // wait for the client to finish
    char ack[16] = {};
    recv(sock, ack, sizeof(ack) - 1, 0);

    close(sock);
    delete[] buf;
    return;
}

int server_local()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        perror("bind");
        return -1;
    }

    listen(server_fd, 1);
    std::cout << "Srv waiting on " << PORT << " …\n";

    socklen_t len = sizeof(addr);
    int client_fd = accept(server_fd, reinterpret_cast<sockaddr *>(&addr), &len);
    if (client_fd < 0)
    {
        perror("accept");
        return -1;
    }
    std::cout << "local Client connected, waiting for data…\n";
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags == -1)
    {
        std::cerr << "Errore F_GETFL\n";
        return -1;
    }

    flags |= O_NONBLOCK;

    if (fcntl(client_fd, F_SETFL, flags) == -1)
    {
        std::cerr << "Errore F_SETFL\n";
        return -1;
    }

    return client_fd;
}

ssize_t recv_all_test_rdma(int socket, void *buffer, size_t length)
{
    size_t total_received = 0;

    while (total_received < length)
    {
        ssize_t bytes = recv(socket, (char *)buffer + total_received, length - total_received, 0);
        if (bytes < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                cerr << "Error receiving data: " << strerror(errno) << "\n";
                return -1; // error
            }
            continue; // try again
        }
        else if (bytes == 0)
        {
            cerr << "Connection closed by peer\n";
            return total_received; // partial receive
        }

        total_received += bytes;
    }
    return total_received;
}