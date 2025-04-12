

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "librdma/librdma.h"

int main()
{
    struct rdma_context cctx;

    printf("Starting RDMA client...\n");
    setup_client(&cctx);
    printf("Connecting to server...\n");
    connect_to_server(&cctx);
    printf("Sending messages...\n");

    for (int i = 0; i < 20; i++)
    {
        snprintf(cctx.buffer, MSG_SIZE, "%s %d", MSG, i);
        send_rdma(&cctx, cctx.buffer, MSG_SIZE);
        sleep(1); // wait for the server to process
    }

    // disonnect and cleanup
    printf("Disconnecting...\n");
    cleanup_client(&cctx);

    return 0;
}


