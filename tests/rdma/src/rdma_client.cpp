
#include <Manager.h>
#include <signal.h>
#include <optional>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>

int STOP = false;

using namespace std;
uint32_t ipToUint32(const std::string &ip);
void client_thread();
int send_all_2(int socket, void *buffer, size_t length);
int server_local();

void handle_signal(int signal)
{
    STOP = true;
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <ip> <dev_idx> <GID>\n";
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTSTP, handle_signal);

    std::string ip = argv[1];
    uint32_t ipNum = ipToUint32(ip);

    int dev_idx = std::atoi(argv[2]);
    int gid = std::atoi(argv[3]);

    RdmaTestConf::setDevIdx(dev_idx);
    RdmaTestConf::setRdmaDevGidIdx(gid);

    Manager::Manager manager;
    manager.client(ipNum);

    thread client_thr(client_thread);
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

void client_thread()
{
    double gb_to_send = DEFAULT_TOTAL_GB;
    uint64_t total_bytes = static_cast<uint64_t>(gb_to_send * BYTES_PER_GB);
    if (total_bytes == 0)
    {
        std::cerr << "GB > 0\n";
        return;
    }

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

    this_thread::sleep_for(chrono::seconds(1));
    char start_buf[16] = {};

    send(sock, start_buf, sizeof(start_buf), 0); // Notify server that client is ready
    cout << "Waiting for server to be ready...\n";
    recv(sock, start_buf, sizeof(start_buf), 0); // Wait for server to be ready

    this_thread::sleep_for(chrono::seconds(1));

    char *buf = new char[BUFFER_SIZE_BYTES];
    std::memset(buf, 0, BUFFER_SIZE_BYTES);

    cout << "Waiting for user input to start sending data...\n";
    std::cin.get();

    std::cout << "Sending " << gb_to_send << " GB…\n";

    uint64_t sent_bytes = 0;
    auto t0 = std::chrono::high_resolution_clock::now();

    uint64_t counter = 0;
    uint64_t remaining = total_bytes;

    while (remaining > 0)
    {
        if (CHECK_INTEGRITY)
        {
            memcpy(buf, &counter, sizeof(counter));
            counter++;
        }

        int n = send_all_2(sock, buf, BUFFER_SIZE_BYTES);

        // this_thread::sleep_for(std::chrono::milliseconds(5));

        if (n == 0)
        {
            std::cerr << "Connection closed by peer\n";
            break;
        }

        sent_bytes += static_cast<uint64_t>(BUFFER_SIZE_BYTES);
        remaining -= static_cast<uint64_t>(BUFFER_SIZE_BYTES);

        if (sent_bytes % (BYTES_PER_GB) == 0)
            cout << "Sent " << (sent_bytes / BYTES_PER_GB) << " GB so far\n";
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double gbyte = sent_bytes / static_cast<double>(BYTES_PER_GB);
    double gbps = gbyte / sec;
    gbps *= 8; // Convert to Gb/s
    std::cout << "TX " << gbyte << " GB in " << sec << " s (" << gbps << " Gb/s)\n";

    std::cout << "Tx ended, waiting for ACK…\n";

    // shutdown(sock, SHUT_WR);

    char ack[16] = {};
    ssize_t ackn = recv(sock, ack, sizeof(ack) - 1, 0);

    t1 = std::chrono::high_resolution_clock::now();
    sec = std::chrono::duration<double>(t1 - t0).count();
    gbyte = sent_bytes / static_cast<double>(BYTES_PER_GB);
    gbps = gbyte / sec;
    gbps *= 8; // Convert to Gb/s

    if (ackn < 0)
    {
        perror("recv");
        std::cerr << "Error on ACK rx\n";
        close(sock);
        delete[] buf;
        return;
    }
    else if (std::string(ack).find(ACK_MESSAGE) != std::string::npos)
    {
        std::cout << "ACK\n";
        std::cout << "TX " << gbyte << " GB in " << sec << " s (" << gbps << " Gb/s)\n";
    }
    else
    {
        std::cerr << "ACK not received!\n";
    }

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

int send_all_2(int socket, void *buffer, size_t length)
{
    size_t tot_sent = 0;
    while (tot_sent < length)
    {
        ssize_t bytes = send(socket, (char *)buffer + tot_sent, length - tot_sent, 0);
        if (bytes < 0)
        {
            cerr << "Errno: " << errno << "\n";
            perror("send");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        else if (bytes == 0)
        {
            std::cerr << "Connection closed by peer\n";
            return 0; // connection closed
        }
        tot_sent += bytes;
    }
    return 1; // no error
}

uint32_t ipToUint32(const std::string &ip)
{
    std::stringstream ss(ip);
    std::string token;
    uint32_t result = 0;
    int shift = 24;

    while (std::getline(ss, token, '.'))
    {
        int octet = std::stoi(token);
        if (octet < 0 || octet > 255)
        {
            throw std::invalid_argument("Ottetto fuori dal range (0-255).");
        }
        result |= (octet << shift);
        shift -= 8;
    }

    // Ritorna in network byte order (quello che vuole in_addr.s_addr)
    return htonl(result);
}
