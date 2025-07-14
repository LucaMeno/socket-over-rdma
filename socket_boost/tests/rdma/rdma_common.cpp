

#include "rdma_common.h"

int is_ipv4_mapped_gid(union ibv_gid& gid)
{
    // RoCE v2 usa un indirizzo IPv6 routabile o IPv4-mappato ::ffff:ipv4
    // Se i primi 10 byte sono 0, i successivi 2 sono 0xffff, è un indirizzo IPv4-mappato (potrebbe essere RoCE v2)
    // Qui consideriamo RoCE v2 se è IPv4-mappato o IPv6 routabile (non link-local fe80::)

    const uint8_t *raw = gid.raw;

    // Check for IPv4-mapped IPv6: first 10 bytes zero, next 2 bytes 0xff
    bool ipv4_mapped = true;
    for (int i = 0; i < 10; ++i)
    {
        if (raw[i] != 0)
        {
            ipv4_mapped = false;
            break;
        }
    }
    if (ipv4_mapped && raw[10] == 0xff && raw[11] == 0xff)
    {
        // IPv4-mapped, quindi possibile RoCE v2
        return true;
    }

    // Controlla se è un indirizzo IPv6 routabile (non link-local fe80::)
    // fe80:: link-local in hex è: fe 80 in primo blocco
    if (!(raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80))
    {
        // Non è link-local -> potrebbe essere RoCE v2 IPv6 routabile
        return true;
    }

    // Altrimenti consideriamo RoCE v1
    return false;
}
int select_gid_index(struct ibv_context *ctx, uint8_t port_num)
{
    struct ibv_port_attr port_attr;
    if (ibv_query_port(ctx, port_num, &port_attr))
    {
        fprintf(stderr, "Failed to query port\n");
        return -1;
    }

    union ibv_gid gid;
    char gid_str[INET6_ADDRSTRLEN];

    for (int i = 0; i < port_attr.gid_tbl_len; ++i)
    {
        if (ibv_query_gid(ctx, port_num, i, &gid))
            continue;

        if (!inet_ntop(AF_INET6, &gid.raw, gid_str, sizeof(gid_str)))
            continue;

        if (is_ipv4_mapped_gid(gid))
        {
            printf("✅ Selected GID[%d] = %s (RoCE v2 IPv4-mapped)\n", i, gid_str);
            return i;
        }
        else
        {
            printf("ℹ️ Skipped GID[%d] = %s (not IPv4-mapped)\n", i, gid_str);
        }
    }

    fprintf(stderr, "❌ No suitable IPv4-mapped RoCE v2 GID found.\n");
    return -1;
}

ibv_context *open_device(int devIndex)
{
    int num_devices = 0;
    ibv_device **device_list = ibv_get_device_list(&num_devices);
    if (!device_list || num_devices == 0)
    {
        std::cerr << "No RDMA devices found.\n";
        return nullptr;
    }

    std::vector<bool> active_devices;
    int active_count = 0;

    for (int i = 0; i < num_devices; ++i)
    {
        ibv_context *ctx = ibv_open_device(device_list[i]);
        if (!ctx)
            continue;

        ibv_port_attr port_attr;
        if (ibv_query_port(ctx, 1, &port_attr) == 0)
        {
            if (port_attr.state == IBV_PORT_ACTIVE)
            {
                std::cout << "[" << i << "] device UP: " << ibv_get_device_name(device_list[i]) << "\n";
                active_devices.push_back(true);
                active_count++;
            }
            else
            {
                std::cout << "[" << i << "] device DOWN: " << ibv_get_device_name(device_list[i]) << "\n";
                active_devices.push_back(false);
            }
        }

        ibv_close_device(ctx);
    }

    if (active_count == 0)
    {
        std::cerr << "No active RDMA devices found.\n";
        ibv_free_device_list(device_list);
        return nullptr;
    }

    if (devIndex >= (int)active_devices.size())
    {
        std::cerr << "Invalid device index (only " << active_devices.size() << " active devices available).\n";
        ibv_free_device_list(device_list);
        throw std::runtime_error("Invalid device index");
    }

    if (!active_devices[devIndex])
    {
        std::cerr << "Selected device is not active, trying to use the first active device...\n";
        for (int i = 0; i < (int)active_devices.size(); ++i)
        {
            if (active_devices[i])
            {
                devIndex = i;
                break;
            }
        }
    }

    ibv_context *ctx = ibv_open_device(device_list[devIndex]);
    if (!ctx)
    {
        std::cerr << "Failed to open selected RDMA device.\n";
        ibv_free_device_list(device_list);
        return nullptr;
    }

    std::cout << "Using device " << devIndex << ": " << ibv_get_device_name(device_list[devIndex]) << "\n";
    ibv_free_device_list(device_list);
    return ctx;
}

uint32_t gen_psn()
{
    return lrand48() & 0xffffff;
}
