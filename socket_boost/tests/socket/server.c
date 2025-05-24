
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "config.h"

ssize_t recv_all(int socket, void *buffer, size_t length) {
    size_t total_received = 0;
    while (total_received < length) {
        ssize_t bytes = recv(socket, (char *)buffer + total_received, length - total_received, 0);
        if (bytes <= 0) {
            return bytes; // error or disconnect
        }
        total_received += bytes;
    }
    return total_received;
}

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[TEST_BUFFER_SIZE];

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(TEST_SERVER_PORT);

    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for connections
    if (listen(server_fd, 3) < 0)
    {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    const char *local_ip = getenv("LOCAL_IP");
    if (local_ip == NULL)
    {
        fprintf(stderr, "LOCAL_IP environment variable not set.\n");
        return -1;
    }

    printf("Server is listening on %s:%d...\n", local_ip, TEST_SERVER_PORT);

    // Accept client connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("Client connected.\n");

    const char *msg_fixed = "Message CIAOOO iughyiubtfg1722896";

#ifdef SERVER_CHRONO
    struct timeval start, end;
#endif // SERVER_CHRONO

    int i = 0;
    uint32_t tot_len = 0;
    ssize_t bytes_received;
    while (1)
    {
        bytes_received = recv_all(new_socket, buffer, strlen(msg_fixed));
        //bytes_received = recv(new_socket, buffer, strlen(msg_fixed), 0);

        if (bytes_received <= 0)
        {
            printf("Client disconnected or error occurred.\n");
            break;
        }

        if(strcmp(buffer, msg_fixed) != 0)
        {
            printf("Received message %d: %.*s\n", i, (int)bytes_received, buffer);
        }

#ifdef SERVER_CHRONO
        if (i == 0)
        {
            gettimeofday(&start, NULL);
        }
#endif // SERVER_CHRONO

        tot_len += bytes_received;

        if (i % (N_OF_MSG_CS / 10) == 0)
        {
            printf("%d %%\n", (i * 100) / N_OF_MSG_CS);
        }
        i++;

        if (i == N_OF_MSG_CS)
        {
            break;
        }

#ifdef SERVER_SEND_RESP
        send(new_socket, buffer, TEST_BUFFER_SIZE, 0);
#endif
    }

#ifdef SERVER_CHRONO
    gettimeofday(&end, NULL);
    long seconds = end.tv_sec - start.tv_sec;
    long useconds = end.tv_usec - start.tv_usec;
    double total_time = seconds + useconds / 1e6;
    printf("Total time: %f seconds\n", total_time);
#endif // SERVER_CHRONO

    printf("Receved %d msg\n", i);

    printf("Total bytes received: %u/%u\n", tot_len, (u_int32_t)((u_int32_t)N_OF_MSG_CS * (u_int32_t)TEST_BUFFER_SIZE));

    printf("Total bytes received (in MB): %.2f\n", (float)tot_len / (1024 * 1024));

    printf("Total bytes received (in GB): %.2f\n", (float)tot_len / (1024 * 1024 * 1024));

    while (recv(new_socket, buffer, TEST_BUFFER_SIZE, 0) > 0)
    {
    }

    // Close the socket
    printf("Stopping server...\n");
    if (close(new_socket) < 0)
    {
        perror("Close failed");
    }
    if (close(server_fd) < 0)
    {
        perror("Close failed");
    }
    printf("Server stopped.\n");

    return 0;
}
