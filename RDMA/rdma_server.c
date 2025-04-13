
#include <stdio.h>
#include <stdlib.h>
#include "librdma/librdma.h"

#define PORT "7471"
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
    int err;
    rdma_context sctx = {};

    err = rdma_setup_server(&sctx, PORT);
    check_error(err, "Failed to setup server");
    printf("Server setup complete.\n");

    err = rdma_wait_for_client(&sctx);
    check_error(err, "Failed to wait for client");
    printf("Client connected.\n");

    // create a slice
    err = rdma_listen_notification(&sctx);
    check_error(err, "Failed to listen for notifications");

    // delete the slice
    err = rdma_listen_notification(&sctx);
    check_error(err, "Failed to send notification");

    err = rdma_close(&sctx);
    check_error(err, "Failed to close connection");
    printf("Connection closed and resources cleaned up.\n");

    return 0;
}