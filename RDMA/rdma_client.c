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
    rdma_context cctx = {0};

    int err;

    err = rdma_setup_client(&cctx, SERVER_IP, PORT);
    check_error(err, "Failed to setup client");
    printf("Client setup complete.\n");

    err = rdma_connect_server(&cctx);
    check_error(err, "Failed to connect to server");
    printf("Connected to server.\n");

    // create a slice
    int slice_id = 0;
    cctx.free_ids[slice_id] = 1; // Mark the slice as used

    rdma_context_slice *slice = NULL;
    slice = (rdma_context_slice *)(cctx.buffer + sizeof(notification_t) +
                                   slice_id * SLICE_SIZE);

    // notify the server about the new slice
    notification_t *notification = (notification_t *)cctx.buffer;
    notification->code = RDMA_NEW_SLICE;
    notification->slice_id = slice_id;
    err = rdma_send_notification(&cctx);
    check_error(err, "Failed to send notification");

    sleep(2);

    // delete the slice
    notification->code = RDMA_DELETE_SLICE;
    notification->slice_id = slice_id;
    err = rdma_send_notification(&cctx);
    check_error(err, "Failed to send notification");

    // disonnect and cleanup
    err = rdma_close(&cctx);
    check_error(err, "Failed to close connection");
    printf("Connection closed and resources cleaned up.\n");

    return 0;
}
