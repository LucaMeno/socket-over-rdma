#include <iostream>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <thread>
#include "testSockConf.h"

using namespace std;

struct retErr
{
    ssize_t writtenUpToNow;
    ssize_t err;
};

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

int main(int argc, char *argv[])
{
    if (argc != 2 && argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <remote ip> <port>\n";
        return 1;
    }

    uint16_t port = (argc == 3) ? static_cast<uint16_t>(atoi(argv[2])) : PORT;

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
    srv.sin_port = htons(port);
    if (inet_pton(AF_INET, argv[1], &srv.sin_addr) <= 0)
    {
        perror("inet_pton");
        return 1;
    }

    cout << "Connecting to " << argv[1] << ":" << port << "...\n";
    if (connect(sock, reinterpret_cast<sockaddr *>(&srv), sizeof(srv)) < 0)
    {
        perror("connect");
        return 1;
    }

    this_thread::sleep_for(chrono::seconds(1));
    char start_buf[16] = {};

    send(sock, start_buf, sizeof(start_buf), 0); // Notify server that client is ready
    cout << "Waiting for server to be ready...\n";
    recv(sock, start_buf, sizeof(start_buf), 0); // Wait for server to be ready

    this_thread::sleep_for(chrono::seconds(1));

    char *buf = new char[BUFFER_SIZE_BYTES];
    std::memset(buf, 0, BUFFER_SIZE_BYTES);

    // print the PID
    std::cout << "Client PID: " << getpid() << "\n";

    if (MEASURE_LATENCY)
    {
        if (WAIT_FOR_USER_INPUT)
        {
            std::cout << "Press ENTER to start measuring latency with " << LATENCY_ITERS << " iterations\n";
            std::cin.get();
        }

        char latency_buf[64] = {};
        memset(latency_buf, 0, sizeof(latency_buf));

        std::cout << "Measuring latency with " << LATENCY_ITERS << " iterations…\n";

        double total_rtt = 0.0;
        double min_rtt = std::numeric_limits<double>::max();
        double max_rtt = 0.0;

        ofstream csv_file("latency.csv", ios::out | ios::trunc);
        if (!csv_file.is_open())
            throw runtime_error("Failed to open latency.csv");

        cout << "----------------------------------------\n";
        cout << "n, RTT (us)\n";
        csv_file << "n,RTT (us)\n";

        for (int i = 0; i < LATENCY_ITERS; ++i)
        {
            // add timestamp to latency_buf
            auto now = std::chrono::high_resolution_clock::now();
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
            snprintf(latency_buf, sizeof(latency_buf), "%ld", ns);

            auto start = std::chrono::high_resolution_clock::now();
            int n = write(sock, latency_buf, strlen(latency_buf) + 1);

            if (n <= 0)
                throw runtime_error("Error writing latency data");

            n = read(sock, latency_buf, sizeof(latency_buf));
            if (n <= 0)
                throw runtime_error("Error reading latency data");

            auto end = std::chrono::high_resolution_clock::now();

            auto rtt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            total_rtt += rtt;
            min_rtt = std::min(min_rtt, static_cast<double>(rtt));
            max_rtt = std::max(max_rtt, static_cast<double>(rtt));

            std::cout << i << "," << rtt << std::endl;
            csv_file << i << "," << rtt << "\n";

            if (NS_BETWEEN_LATENCY_ITERS > 0)
                usleep(NS_BETWEEN_LATENCY_ITERS);
        }

        csv_file.close();

        double avg_rtt = total_rtt / LATENCY_ITERS;
        std::cout << "Latency results over " << LATENCY_ITERS << " iterations:\n";
        std::cout << "Average RTT: " << avg_rtt << " us\n";
        std::cout << "Minimum RTT: " << min_rtt << " us\n";
        std::cout << "Maximum RTT: " << max_rtt << " us\n";
        std::cout << "Average one-way latency: " << (avg_rtt / 2.0) << " us\n";
        std::cout << "----------------------------------------\n";
    }

    if (!MEASURE_THROUGHPUT)
    {
        std::cout << "Not measuring throughput, exiting.\n";
        close(sock);
        delete[] buf;
        return 0;
    }

    cout << "Ready to send " << gb_to_send << " GB of data\n";

    if (WAIT_FOR_USER_INPUT)
    {
        std::cout << "Press ENTER to start sending " << gb_to_send << " GB\n";
        std::cin.get();
    }

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
