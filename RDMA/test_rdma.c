#include <stdio.h>
#include <infiniband/verbs.h>

int main()
{
    struct ibv_device **dev_list;
    struct ibv_context *context;
    int num_devices, i;

    // Get the list of available RDMA devices
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list)
    {
        perror("Failed to get IB devices list");
        return 1;
    }

    printf("Found %d RDMA device(s)\n", num_devices);

    for (i = 0; i < num_devices; i++)
    {
        printf("Device %d: %s\n", i, ibv_get_device_name(dev_list[i]));

        // Open the device
        context = ibv_open_device(dev_list[i]);
        if (!context)
        {
            perror("Failed to open device");
            continue;
        }

        // Query the device attributes
        struct ibv_device_attr dev_attr;
        if (ibv_query_device(context, &dev_attr))
        {
            perror("Failed to query device");
        }
        else
        {
            printf("  Max QP: %d\n", dev_attr.max_qp); // Max Queue Pairs
            printf("  Max CQ: %d\n", dev_attr.max_cq); // Max Completion Queues
            printf("  Max MR Size: %llu\n", (unsigned long long)dev_attr.max_mr_size); // Max Memory Region Size
        }

        // Close the device
        ibv_close_device(context);
    }

    // Free the device list
    ibv_free_device_list(dev_list);

    return 0;
}
