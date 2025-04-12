
#include <stdio.h>
#include <stdlib.h>
#include "librdma/librdma.h"

int main()
{
    struct rdma_context sctx = {};

    printf("Starting RDMA server...\n");
    setup_server(&sctx);
    printf("Listening for incoming connections...\n");
    wait_for_client(&sctx);
    printf("[Server] Waiting for message...\n");
    wait_for_msg(&sctx);

    cleanup_server(&sctx);
    return 0;
}