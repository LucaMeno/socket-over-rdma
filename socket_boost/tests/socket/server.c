
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[TEST_BUFFER_SIZE] = {0};

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

    ssize_t bytes_received;
    while (1)
    {
        bytes_received = read(new_socket, buffer, TEST_BUFFER_SIZE);
        if (bytes_received <= 0)
        {
            printf("Client disconnected or error occurred.\n");
            break;
        }

        printf("Received message: %s\n", buffer);

#ifdef SERVER_SEND_RESP
        send(new_socket, buffer, strlen(buffer), 0);
        printf("Response sent: %s\n", buffer);
#endif
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
