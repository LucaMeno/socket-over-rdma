#include <iostream>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include "testSockConf.h"

using namespace std;

ssize_t send_all(int socket, void *buffer, size_t length)
{
    size_t total_received = 0;
    while (total_received < length)
    {
        ssize_t bytes = send(socket, (char *)buffer + total_received, length - total_received, 0);
        if (bytes <= 0)
        {
            return bytes; // error or disconnect
        }
        total_received += bytes;
    }
    return total_received;
}

int main(int argc, char *argv[])
{
    double gb_to_send = (argc > 1) ? std::atof(argv[1]) : DEFAULT_TOTAL_GB;
    uint64_t total_bytes = static_cast<uint64_t>(gb_to_send * BYTES_PER_GB);
    if (total_bytes == 0)
    {
        std::cerr << "GB > 0\n";
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr) <= 0)
    {
        perror("inet_pton");
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr *>(&srv), sizeof(srv)) < 0)
    {
        perror("connect");
        return 1;
    }

    char *buf = new char[BUFFER_SIZE_BYTES];
    std::memset(buf, 'A', BUFFER_SIZE_BYTES);

    std::cout << "Sending " << gb_to_send << " GB…\n";

    uint64_t sent_bytes = 0;
    auto t0 = std::chrono::high_resolution_clock::now();

    uint64_t counter = 0;
    uint64_t remaining = total_bytes;
    while (remaining > 0)
    {
        memcpy(buf, &counter, sizeof(counter));
        ++counter;

        // size_t chunk = remaining < BUFFER_SIZE_BYTES ? remaining : BUFFER_SIZE_BYTES;
        ssize_t n = send_all(sock, buf, BUFFER_SIZE_BYTES);

        if (n < 0)
        {
            cerr << "Errno: " << errno << "\n";
            perror("send");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        else if (n == 0)
        {
            std::cerr << "Connection closed by peer\n";
            break;
        }

        sent_bytes += static_cast<uint64_t>(n);
        remaining -= static_cast<uint64_t>(n);

        if (sent_bytes % (BYTES_PER_GB) == 0)
        {
            cout << "Sent " << (sent_bytes / BYTES_PER_GB) << " GB so far\n";
        }
    }

    std::cout << "Tx ended, waiting for ACK…\n";

    // shutdown(sock, SHUT_WR);

    char ack[16] = {};
    ssize_t ackn = recv(sock, ack, sizeof(ack) - 1, 0);

    auto t1 = std::chrono::high_resolution_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double gbyte = sent_bytes / static_cast<double>(BYTES_PER_GB);
    double gbps = gbyte / sec;

    if (ackn > 0 && std::string(ack).find(ACK_MESSAGE) != std::string::npos)
    {
        std::cout << "ACK\n";
        std::cout << "TX " << gbyte << " GB in " << sec << " s (" << gbps << " GB/s)\n";
    }
    else
    {
        std::cerr << "ACK non ricevuto!\n";
    }

    close(sock);
    delete[] buf;
    return 0;
}
