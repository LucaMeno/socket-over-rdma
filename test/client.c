#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"

int main()
{
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

    int i = 0;
    char msg[BUFFER_SIZE] = {0};
    while (1)
    {
        if (i == 100000)
        {
            sprintf(msg, "STOP");
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

        if (RESPONSE)
        {
            read(sock, msg, BUFFER_SIZE);
            printf("Received message: %s\n", msg);
        }
    }

    // Close the socket
    close(sock);
    printf("Disconnected from server\n");

    return 0;
}
