#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include "config.h"

int main(int argc, char **argv)
{

    const char *remote_ip = getenv("REMOTE_IP");
    if (remote_ip == NULL)
    {
        fprintf(stderr, "REMOTE_IP environment variable not set.\n");
        return EXIT_FAILURE;
    }

    int N = (argc == 2) ? atoi(argv[1]) : 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_SERVER_PORT)};

    if (inet_pton(AF_INET, remote_ip, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address or address not supported");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("Connecting to server %s:%d...\n", remote_ip, TEST_SERVER_PORT);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("Connected to server\n");

    char msg_out[TEST_BUFFER_SIZE];
    char msg_in[TEST_BUFFER_SIZE];

    for (int j = 0; j < TEST_BUFFER_SIZE; j++)
        msg_out[j] = 'A';

    printf("MSG_SIZE: %d\n", TEST_BUFFER_SIZE);
    printf("# of messages: %d\n", N_OF_MSG_CS);

#ifdef WAIT_FOR_RDMA_CONN
    printf("Waiting for RDMA connection...\n");
    sleep(2);
#endif // WAIT_FOR_RDMA_CONN

#ifdef CLIENT_CHRONO
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif // CLIENT_CHRONO

    uint32_t tot_len = 0;
    int i = 0;
    while (1)
    {
        if (i == N_OF_MSG_CS)
            break;

        i++;

        if (argc != 2)
        {
            if (i == N_OF_MSG_CS)
                break;
            printf("%d - Press Enter to continue...\n", i);
            getchar();
        }

        strcpy(msg_out, "Message CIAOOO iughyiubtfg1722896");

        int len_sent = send(sock, msg_out, strlen(msg_out), 0);

        if (len_sent != strlen(msg_out))
        {
            perror("Send failed");
            break;
        }

        tot_len += len_sent;

        if (i % (N_OF_MSG_CS / 10) == 0)
        {
            printf("%d %%\n", (i * 100) / N_OF_MSG_CS);
        }

#ifdef C_S_RESPONSE
        ssize_t len_rcv = recv(sock, msg_in, TEST_BUFFER_SIZE, 0);
        if (len_rcv < 0)
        {
            perror("Receive failed");
            break;
        }

        if (len_rcv > 0)
        {
            if (memcmp(msg_out, msg_in, TEST_BUFFER_SIZE) != 0)
            {
                printf("Received message does not match sent message\n");
                break;
            }
        }
#endif // C_S_RESPONSE
    }

    printf("FINISHED\n");

    printf("Total bytes sent: %u\n", tot_len);
    printf("Total bytes sent (in MB): %.2f\n", (float)tot_len / (1024 * 1024));
    printf("Total bytes sent (in GB): %.2f\n", (float)tot_len / (1024 * 1024 * 1024));

#ifdef CLIENT_CHRONO
    gettimeofday(&end, NULL);
    long seconds = end.tv_sec - start.tv_sec;
    long useconds = end.tv_usec - start.tv_usec;
    double total_time = seconds + useconds / 1e6;
    printf("Total time: %f seconds\n", total_time);
#endif // CLIENT_CHRONO

    printf("Total throughput: %.2f MB/s\n", (float)tot_len / (1024 * 1024 * total_time));
    printf("Total throughput: %.2f GB/s\n", (float)tot_len / (1024 * 1024 * 1024 * total_time));

    printf("Press Enter to exit...\n");
    getchar();

    printf("Disconnected from server\n");
    if (close(sock) < 0)
    {
        perror("Socket close failed");
        return EXIT_FAILURE;
    }

    printf("Socket closed\n");

    return EXIT_SUCCESS;
}