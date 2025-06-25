
#include "rdma_common.h"


ibv_context *open_device()
{
    int num_devices = 0;
    ibv_device **device_list = ibv_get_device_list(&num_devices);
    if (!device_list || num_devices == 0)
    {
        std::cerr << "No RDMA devices found.\n";
        return nullptr;
    }

    for (int i = 0; i < num_devices; ++i)
    {
        std::cout << "Device " << i << ": " << ibv_get_device_name(device_list[i]) << "\n";
    }

    ibv_context *ctx = ibv_open_device(device_list[0]);
    ibv_free_device_list(device_list);
    return ctx;
}

uint32_t gen_psn()
{
    return lrand48() & 0xffffff;
}
