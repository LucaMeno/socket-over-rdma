#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/select.h>
#include "config.h"

int sock;
char msg_out[TEST_BUFFER_SIZE];
char msg_in[TEST_BUFFER_SIZE];

void *socket_handler_thread(void *arg)
{
    int i = 0;
    ssize_t len_rcv;

    fd_set readfds;
    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        int activity = select(sock + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0)
        {
            perror("select error");
            break;
        }

        if (FD_ISSET(sock, &readfds))
        {
            i++;
            len_rcv = recv(sock, msg_in, TEST_BUFFER_SIZE, 0);
            if (len_rcv < 0)
            {
                perror("Receive failed");
                break;
            }

#ifdef CLIENT_CHECK_RESP
            if (len_rcv > 0)
            {
                if (memcmp(msg_out, msg_in, TEST_BUFFER_SIZE) != 0)
                {
                    printf("Received message does not match sent message\n");
                    break;
                }
            }
#endif // CLIENT_CHECK_RESP

            if (i == N_OF_MSG_CS)
            {
                break;
            }
        }
    }

    printf("Received %d messages\n", i);

    return NULL;
}

int main(int argc, char **argv)
{
    const char *remote_ip = getenv("REMOTE_IP");
    if (remote_ip == NULL)
    {
        fprintf(stderr, "REMOTE_IP environment variable not set.\n");
        return EXIT_FAILURE;
    }

    int N = (argc == 2) ? atoi(argv[1]) : 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
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

    // Initialize the message to send
    for (int j = 0; j < TEST_BUFFER_SIZE; j++)
        msg_out[j] = 'A';

    printf("MSG_SIZE: %d\n", TEST_BUFFER_SIZE);
    printf("# of messages: %d\n", N_OF_MSG_CS);

#ifdef WAIT_FOR_RDMA_CONN
    printf("Waiting for RDMA connection...\n");
    sleep(3);
#endif // WAIT_FOR_RDMA_CONN

#ifdef CLIENT_CHRONO
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif // CLIENT_CHRONO

    // Launch the handler thread to listen for responses
    pthread_t tid;
    if (pthread_create(&tid, NULL, socket_handler_thread, NULL) != 0)
    {
        perror("Failed to create thread");
        close(sock);
        return EXIT_FAILURE;
    }

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
            printf("Press Enter to continue...\n");
            getchar();
        }

        // Send message
        send(sock, msg_out, TEST_BUFFER_SIZE, 0);

        if (i % (N_OF_MSG_CS / 10) == 0)
        {
            printf("%d %%\n", (i * 100) / N_OF_MSG_CS);
        }
    }

    // Wait for the thread to finish
    pthread_join(tid, NULL);

    printf("FINISHED\n");

    printf("Disconnected from server\n");
    if (close(sock) < 0)
    {
        perror("Socket close failed");
        return EXIT_FAILURE;
    }

    printf("Socket closed\n");

#ifdef CLIENT_CHRONO
    gettimeofday(&end, NULL);
    long seconds = end.tv_sec - start.tv_sec;
    long useconds = end.tv_usec - start.tv_usec;
    double total_time = seconds + useconds / 1e6;
    printf("Total time: %f seconds\n", total_time);
#endif // CLIENT_CHRONO

    return EXIT_SUCCESS;
}
