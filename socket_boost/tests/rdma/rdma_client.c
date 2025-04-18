#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "rdma_manager.h"

#define RDMA_PORT 7471
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
    // convert IP into u_int32_t
    struct in_addr addr;
    if (inet_pton(AF_INET, SERVER_IP, &addr) <= 0)
    {
        perror("inet_pton");
        return -1;
    }
    uint32_t ip = addr.s_addr;

    rdma_context_manager_t ctx_mng = {};
    int err = rdma_manager_init(&ctx_mng, RDMA_PORT);

    printf("Context maanger initialized.\n");

    rdma_context_slice_t *slice = NULL;
    uint16_t port = 10100;
    int fd = 20;
    slice = rdma_manager_get_slice(&ctx_mng, ip, port, fd);
    rdma_context_t *cctx = &ctx_mng.ctxs[rdma_manager_get_context_by_ip(&ctx_mng, ip)];

    // write
    char *data = "Hello, TEST RDMA!";
    int data_size = strlen(data) + 1; // +1 for null terminator

    transfer_buffer_t *buffer_to_write = slice->client_buffer;

    buffer_to_write->buffer_size = data_size;
    memcpy(buffer_to_write->buffer, data, data_size);
    buffer_to_write->buffer[data_size] = '\0'; // null terminate the string

    err = rdma_write_slice(cctx, slice);
    check_error(err, "Failed to write data");

    // notify the server that data is ready
    err = rdma_send_notification(cctx, RDMA_DATA_READY, slice->slice_offset, slice->client_port);
    check_error(err, "Failed to send notification");

    // delete the slice
    err = rdma_delete_slice_by_offset(cctx, slice->slice_offset);
    check_error(err, "Failed to delete slice");

    err = rdma_send_notification(cctx, RDMA_CLOSE_CONTEXT, -1, 0);

    // disonnect and cleanup

    rdma_manager_destroy(&ctx_mng);
    printf("Connection closed and resources cleaned up.\n");

    return 0;
}
