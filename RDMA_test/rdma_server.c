
#include <stdio.h>
#include <stdlib.h>
#include "librdma/librdma.h"

#define PORT 7471

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

    rdma_context_manager_t ctx_mng = {};
    int err = rdma_manager_init(&ctx_mng, PORT);
    check_error(err, "Failed to initialize context manager");

    printf("Context manager initialized.\n");

    // start the server
    err = rdma_manager_run_server_th(&ctx_mng);
    check_error(err, "Failed to start server");

    printf("Server started.\n");

    printf("Listening for notifications...\n");

    // wait for the server thread to finish
    if (ctx_mng.server_thread != 0)
    {
        pthread_join(ctx_mng.server_thread, NULL);
        pthread_join(ctx_mng.notification_thread, NULL);
        printf("Server thread finished.\n");
    }

    printf("STOPPING SERVER\n");
    err = rdma_manager_destroy(&ctx_mng);

    return 0;
}