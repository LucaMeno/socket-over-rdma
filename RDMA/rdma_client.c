

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "librdma/librdma.h"


#define PORT "7471"
#define SERVER_IP "192.168.109.132"
#define MSG_SIZE 256

void check_error(int err, const char *msg)
{
    if (err)
    {
        printf("%s\n", msg);
        perror("Error");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    struct rdma_context cctx = {0};

    int err;

    err = rdma_setup_client(&cctx, SERVER_IP, PORT);
    check_error(err, "Failed to setup client");
    printf("Client setup complete.\n");

    err = rdma_connect_server(&cctx);
    check_error(err, "Failed to connect to server");
    printf("Connected to server.\n");


    for (int i = 0; i < 5; i++)
    {
        snprintf(cctx.buffer, MSG_SIZE, "HELLO: %d", i);
        err = rdma_send(&cctx, MSG_SIZE);
        check_error(err, "Failed to send message");
        printf("Sent message: %s\n", cctx.buffer);
        sleep(1); // wait for the server to process
    }

    // disonnect and cleanup
    err = rdma_close(&cctx);
    check_error(err, "Failed to close connection");
    printf("Connection closed and resources cleaned up.\n");

    return 0;
}


