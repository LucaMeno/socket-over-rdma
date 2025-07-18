#include <iostream>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include "testSockConf.h"

using namespace std;

struct retErr
{
    ssize_t writtenUpToNow;
    ssize_t err;
};

struct retErr send_all(int socket, void *buffer, size_t length)
{
    size_t total_received = 0;
    while (total_received < length)
    {
        ssize_t bytes = send(socket, (char *)buffer + total_received, length - total_received, 0);
        if (bytes <= 0)
        {
            struct retErr result;
            result.writtenUpToNow = total_received;
            result.err = bytes;
            return result; // error or disconnect
        }
        total_received += bytes;
    }
    struct retErr result;
    result.writtenUpToNow = total_received;
    result.err = 1; // no error
    return result;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <remote ip>\n";
        return 1;
    }

    double gb_to_send = DEFAULT_TOTAL_GB;
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
    if (inet_pton(AF_INET, argv[1], &srv.sin_addr) <= 0)
    {
        perror("inet_pton");
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr *>(&srv), sizeof(srv)) < 0)
    {
        perror("connect");
        return 1;
    }

    this_thread::sleep_for(chrono::seconds(1));
    char start_buf[16] = {};

    send(sock, start_buf, sizeof(start_buf), 0); // Notify server that client is ready
    recv(sock, start_buf, sizeof(start_buf), 0); // Wait for server to be ready

    this_thread::sleep_for(chrono::seconds(1));

    char *buf = new char[BUFFER_SIZE_BYTES];
    std::memset(buf, 'A', BUFFER_SIZE_BYTES);

    std::cout << "Sending " << gb_to_send << " GB…\n";

    uint64_t sent_bytes = 0;
    auto t0 = std::chrono::high_resolution_clock::now();

    uint64_t counter = 0;
    uint64_t remaining = total_bytes;

    uint64_t remaining_bytes = BUFFER_SIZE_BYTES;
    while (remaining > 0)
    {
        memcpy(buf, &counter, sizeof(counter));

        struct retErr n = send_all(sock, buf, remaining_bytes);

        if (n.err < 0)
        {
            cerr << "Errno: " << errno << "\n";
            perror("send");
            remaining_bytes -= n.writtenUpToNow;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        else if (n.err == 0)
        {
            std::cerr << "Connection closed by peer\n";
            break;
        }

        ++counter;
        remaining_bytes = BUFFER_SIZE_BYTES;

        sent_bytes += static_cast<uint64_t>(BUFFER_SIZE_BYTES);
        remaining -= static_cast<uint64_t>(BUFFER_SIZE_BYTES);

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
    gbps *= 8; // Convert to Gb/s

    if (ackn < 0)
    {
        perror("recv");
        std::cerr << "Error on ACK rx\n";
        close(sock);
        delete[] buf;
        return 1;
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
    return 0;
}
