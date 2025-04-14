
#include <stdio.h>
#include <stdlib.h>
#include "librdma/librdma.h"

#define PORT "7471"

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

    err = rdma_server_setup(&sctx, PORT);
    check_error(err, "Failed to setup server");
    printf("Server setup complete.\n");

    err = rdma_server_wait_client_connection(&sctx);
    check_error(err, "Failed to wait for client");
    printf("Client connected.\n");

    
    printf("---------------------------------------------------------\n");

    // create a slice
    err = rdma_recv_notification(&sctx);
    check_error(err, "Failed to listen for notifications");

    
    printf("---------------------------------------------------------\n");

    // noification data ready
    err = rdma_recv_notification(&sctx);
    check_error(err, "Failed to listen for notifications");

    
    printf("---------------------------------------------------------\n");

    // delete the slice
    err = rdma_recv_notification(&sctx);
    check_error(err, "Failed to send notification");

    
    printf("---------------------------------------------------------\n");

    err = rdma_context_close(&sctx);
    check_error(err, "Failed to close connection");
    printf("Connection closed and resources cleaned up.\n");

    return 0;
}