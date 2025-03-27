#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define PORT 7777
#define BUFFER_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in server_addr;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Convert IP address from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    int i = 0;
    char msg[BUFFER_SIZE] = {0};
    while(1) {
        if(i == 100000) {
            sprintf(msg, "STOP");
            break;
        } else {
            sprintf(msg, "%d", i);
        }
        i++;
        send(sock, msg, strlen(msg), 0);
        read(sock, msg, BUFFER_SIZE);
        if(atoi(msg) == i-1) {
            printf("%d ACK\n", i);
        } else {
            printf("Error: %d != %s\n", i, msg);
            break;
        }
        sleep(2);
    }

    // Close the socket
    close(sock);
    printf("Disconnected from server\n");

    return 0;
}
