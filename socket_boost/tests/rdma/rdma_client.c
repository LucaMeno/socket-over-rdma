#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include "rdma_manager.h"
#include "config.h"

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
    /*const char *remote_ip = getenv("REMOTE_IP");
    if (remote_ip == NULL)
    {
        fprintf(stderr, "remote_ip environment variable not set.\n");
        return -1;
    }

    // convert IP into u_int32_t
    struct in_addr addr;
    if (inet_pton(AF_INET, remote_ip, &addr) <= 0)
    {
        perror("inet_pton");
        return -1;
    }
    uint32_t ip = addr.s_addr;

    rdma_context_manager_t ctx_mng = {};
    int err = rdma_manager_run(&ctx_mng, RDMA_PORT);
    check_error(err, "Failed to run RDMA manager");

    uint16_t port = 10100;
    int fd = 20;
    char *data = "Hello, TEST RDMA!";
    int data_size = strlen(data) + 1; // +1 for null terminator

    rdma_manager_send(&ctx_mng, ip, port, data, data_size, fd);

    // disonnect and cleanup

    sleep(7);
    printf("Disconnecting...\n");
    rdma_manager_destroy(&ctx_mng);
    printf("Connection closed and resources cleaned up.\n");*/

    return 0;
}
