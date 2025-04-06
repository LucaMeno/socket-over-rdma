#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"

#define RESPONSE

int main(int argc, char **argv)
{
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
    server_addr.sin_port = htons(SERVER_PORT);

    // Convert IP address from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address or Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    int i = N;
    int gap = 100000;
    char msg[BUFFER_SIZE] = {0};
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
        send(sock, msg, strlen(msg), 0);
        printf("Sent message: %s\n", msg);

        // wait user input
        printf("Press Enter to continue...\n");
        getchar();

#ifdef RESPONSE
        //  Receive response from server
        char buffer[BUFFER_SIZE];
        ssize_t len = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        buffer[len] = '\0'; // Null-terminate the string
        printf("Received message: %s\n", buffer);
        if (strcmp(msg, buffer) != 0)
        {
            printf("Error: Received message does not match sent message\n");
            break;
        }
#endif
    }

    // Close the socket
    printf("Disconnected from server\n");
    if(close(sock) < 0)
    {
        perror("Socket close failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket closed\n");

    return 0;
}
