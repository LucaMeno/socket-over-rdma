#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "librdma/librdma.h"

#define PORT "7471"
#define SERVER_IP "192.168.109.132"

#define UNUSED(x) (void)(x)

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

    printf("---------------------------------------------------------\n");

    // create a slice
    int slice_id = 0;
    cctx.is_id_free[slice_id] = FALSE; // Mark the slice as used

    rdma_context_slice *slice = cctx.slices + slice_id;

    // set the pointers to the buffers
    slice->slice_id = slice_id;
    slice->server_buffer = (transfer_buffer_t *)(cctx.buffer + NOTIFICATION_OFFSET_SIZE +
                                                 slice_id * SLICE_BUFFER_SIZE);
    slice->client_buffer = (transfer_buffer_t *)(cctx.buffer + NOTIFICATION_OFFSET_SIZE +
                                                 slice_id * SLICE_BUFFER_SIZE +
                                                 sizeof(transfer_buffer_t)); // skip the server buffer

    // notify the server about the new slice
    set_notification_for_server(&cctx, RDMA_NEW_SLICE, slice_id);
    slice->src_port = 12345;
    err = rdma_send_notification(&cctx);
    check_error(err, "Failed to send notification");

    printf("---------------------------------------------------------\n");

    // write
    char *data = "Hello, RDMA!";
    int data_size = strlen(data) + 1; // +1 for null terminator

    transfer_buffer_t *buffer_to_write = slice->client_buffer;
    buffer_to_write->buffer_size = data_size;
    buffer_to_write->flags = 0; // no flags
    memcpy(buffer_to_write->buffer, data, data_size);
    buffer_to_write->buffer[data_size] = '\0'; // null terminate the string

    err = rdma_write(&cctx, slice);
    check_error(err, "Failed to write data");

    printf("---------------------------------------------------------\n");

    // notify the server that data is ready
    set_notification_for_server(&cctx, RDMA_DATA_READY, slice_id);
    err = rdma_send_notification(&cctx);
    check_error(err, "Failed to send notification");

    printf("---------------------------------------------------------\n");

    // delete the slice
    set_notification_for_server(&cctx, RDMA_DELETE_SLICE, slice_id);
    err = rdma_send_notification(&cctx);
    check_error(err, "Failed to send notification");

    printf("---------------------------------------------------------\n");

    // disonnect and cleanup
    err = rdma_close(&cctx);
    check_error(err, "Failed to close connection");
    printf("Connection closed and resources cleaned up.\n");

    return 0;
}
