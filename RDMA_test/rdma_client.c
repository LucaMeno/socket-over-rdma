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

    err = rdma_client_setup(&cctx, SERVER_IP, PORT);
    check_error(err, "Failed to setup client");
    printf("Client setup complete.\n");

    err = rdma_client_connect(&cctx);
    check_error(err, "Failed to connect to server");
    printf("Connected to server.\n");

    printf("---------------------------------------------------------\n");

    // create a slice
    int slice_id = rdma_new_slice(&cctx);
    check_error(slice_id, "Failed to create slice");

    printf("---------------------------------------------------------\n");

    // write
    char *data = "Hello, TEST RDMA!";
    int data_size = strlen(data) + 1; // +1 for null terminator

    transfer_buffer_t *buffer_to_write = cctx.slices[slice_id].client_buffer;

    buffer_to_write->buffer_size = data_size;
    memcpy(buffer_to_write->buffer, data, data_size);
    buffer_to_write->buffer[data_size] = '\0'; // null terminate the string

    err = rdma_write_slice(&cctx, &cctx.slices[slice_id]);
    check_error(err, "Failed to write data");

    printf("---------------------------------------------------------\n");

    // notify the server that data is ready
    err = rdma_send_notification(&cctx, RDMA_DATA_READY, slice_id);
    check_error(err, "Failed to send notification");

    printf("---------------------------------------------------------\n");

    // delete the slice
    err = rdma_delete_slice(&cctx, slice_id);
    check_error(err, "Failed to delete slice");

    printf("---------------------------------------------------------\n");

    // disonnect and cleanup
    err = rdma_context_close(&cctx);
    check_error(err, "Failed to close connection");
    printf("Connection closed and resources cleaned up.\n");

    return 0;
}
