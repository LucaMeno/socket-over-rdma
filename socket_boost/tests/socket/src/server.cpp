#include <iostream>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <random>
#include "testSockConf.h"

using namespace std;

ssize_t recv_all(int socket, void *buffer, size_t length)
{
    size_t total_received = 0;
    while (total_received < length)
    {
        ssize_t bytes = recv(socket, (char *)buffer + total_received, length - total_received, 0);
        if (bytes <= 0)
        {
            cerr << "Error receiving data: " << strerror(errno) << "\n";
            return bytes; // error or disconnect
        }
        total_received += bytes;
    }
    return total_received;
}

int main(int argc, char *argv[])
{
    if (argc > 2)
    {
        cout << "Usage: " << argv[0] << " <port>\n";
        return 0;
    }

    int port = (argc == 2) ? atoi(argv[1]) : PORT;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        perror("bind");
        return 1;
    }

    listen(server_fd, 1);
    std::cout << "Srv waiting on " << PORT << " …\n";

    socklen_t len = sizeof(addr);
    int client_fd = accept(server_fd, reinterpret_cast<sockaddr *>(&addr), &len);
    if (client_fd < 0)
    {
        perror("accept");
        return 1;
    }
    std::cout << "Client connected, waiting for data…\n";

    char start_buf[16] = {};

    recv(client_fd, start_buf, sizeof(start_buf), 0);
    send(client_fd, start_buf, sizeof(start_buf), 0);

    char *buf = new char[BUFFER_SIZE_BYTES];
    uint64_t tot_bytes = 0;

    uint64_t quantity_of_data_to_rx = static_cast<uint64_t>(DEFAULT_TOTAL_GB * BYTES_PER_GB);

    auto t0 = std::chrono::high_resolution_clock::now();
    int i = 0;
    uint64_t counter = 0;
    uint64_t counter_test;
    while (quantity_of_data_to_rx > 0)
    {
        ssize_t n = recv_all(client_fd, buf, BUFFER_SIZE_BYTES);
        if (n <= 0)
        {
            if (n < 0)
                perror("recv");
            break;
        }

        tot_bytes += static_cast<uint64_t>(n);
        quantity_of_data_to_rx -= static_cast<uint64_t>(n);

        // check if the data is valid
        memcpy(&counter_test, buf, sizeof(counter_test));
        if (counter_test != counter)
        {
            // std::cerr << "Data mismatch: expected " << counter << ", got " << counter_test << "\n";
        }
        ++counter;

        // waste time for testing purposes
        // std::this_thread::sleep_for(std::chrono::milliseconds(1));

        if (tot_bytes >= BYTES_PER_GB * i)
        {
            ++i;
            cout << "Recv " << (tot_bytes / BYTES_PER_GB) << " GB so far\n";
        }
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    double sec = std::chrono::duration<double>(t1 - t0).count();
    double gbyte = tot_bytes / static_cast<double>(BYTES_PER_GB);
    double gbps = gbyte / sec;
    gbps *= 8; // Convert to Gb/s

    std::cout << "Rx " << gbyte << " GB in " << sec << " s (" << gbps << " Gb/s)\n";

    send(client_fd, ACK_MESSAGE, std::strlen(ACK_MESSAGE), 0);

    std::cout << "ACK sent\n";

    // wait for the client to finish
    char ack[16] = {};
    recv(client_fd, ack, sizeof(ack) - 1, 0);

    close(client_fd);
    close(server_fd);
    delete[] buf;
    return 0;
}
