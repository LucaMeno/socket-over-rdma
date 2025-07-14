
#pragma once

#include <cstdint>
#include <vector>

class Config
{
public:
    inline static const uint16_t PROXY_PORT = 5555;
    inline static const uint16_t RDMA_SERVER_PORT = 7471;
    inline static const uint32_t RDMA_DEV_PORT = 1;         // Default port for RDMA device
    inline static const uint32_t DEFAULT_DEV_INDEX = 0;     // Default RDMA device index
    inline static const uint32_t DEFAULT_DEV_GID_INDEX = 0; // Default GID index for RDMA device

    inline static const char *SERVER_IP = "127.0.0.1";
    static std::vector<uint16_t> getTargetPorts()
    {
        return {TARGET_PORT_1, TARGET_PORT_2, TARGET_PORT_3};
    }

    static uint32_t getRdmaDevGidIdx()
    {
        return rdma_dev_gid_idx;
    }

    static void setRdmaDevGidIdx(uint32_t gidIdx)
    {
        rdma_dev_gid_idx = gidIdx;
    }

    static void setDevIdx(uint32_t devIdx)
    {
        rdma_dev_idx = devIdx;
    }

    static int getDevIdx()
    {
        return rdma_dev_idx;
    }

private:
    inline static const uint16_t TARGET_PORT_1 = 7777;
    inline static const uint16_t TARGET_PORT_2 = 8888;
    inline static const uint16_t TARGET_PORT_3 = 9999;
    inline static uint32_t rdma_dev_idx;
    inline static uint32_t rdma_dev_gid_idx = 0;
    Config() = default; // Prevent instantiation
};
