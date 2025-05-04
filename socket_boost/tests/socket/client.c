#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"

int main(int argc, char **argv)
{
    const char *remote_ip = getenv("REMOTE_IP");
    if (remote_ip == NULL)
    {
        fprintf(stderr, "remote_ip environment variable not set.\n");
        return -1;
    }

    int N;
    if (argc != 2)
        N = 0;
    else
        N = atoi(argv[1]);

    int sock = 0;
    struct sockaddr_in server_addr;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TEST_SERVER_PORT);

    // Convert IP address from text to binary form
    if (inet_pton(AF_INET, remote_ip, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address or Address not supported");
        exit(EXIT_FAILURE);
    }

    printf("Connecting to server %s:%d...\n", remote_ip, TEST_SERVER_PORT);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    int i = N;
    int gap = 1000000;
    char msg[TEST_BUFFER_SIZE] = {0};
    while (1)
    {
        if (i == N + gap)
        {
            break;
        }
        else if (i == 10)
        {
            break;
        }
        else
        {
            sprintf(msg, "%d", i);
        }
        i++;
        if (argc != 2)
        {
            // wait user input
            printf("Press Enter to continue...\n");
            getchar();
        }
        send(sock, msg, strlen(msg), 0);
        printf("Sent message: %s\n", msg);

#ifdef CLIENT_WAIT_RESP
        //  Receive response from server
        char buffer[TEST_BUFFER_SIZE];
        ssize_t len = recv(sock, buffer, TEST_BUFFER_SIZE - 1, 0);
        buffer[len] = '\0'; // Null-terminate the string
        printf("Received message: %s\n", buffer);
#ifdef CLIENT_CHECK_RESP
        if (strcmp(msg, buffer) != 0)
        {
            printf("Error: Received message does not match sent message\n");
            break;
        }
#endif
#endif
    }

    // Close the socket
    printf("Disconnected from server\n");
    if (close(sock) < 0)
    {
        perror("Socket close failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket closed\n");

    return 0;
}
