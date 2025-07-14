
#pragma once

#include <cstdint>
#include <vector>

class Config
{
public:
    inline static const uint16_t PROXY_PORT = 5555;
    inline static const uint16_t RDMA_SERVER_PORT = 7471;

    inline static const char *SERVER_IP = "127.0.0.1";
    static std::vector<uint16_t> getTargetPorts()
    {
        return {TARGET_PORT_1, TARGET_PORT_2, TARGET_PORT_3};
    }

    static void setServerNumber(uint32_t server_num)
    {
        serverNumber = server_num;
    }

    static int getDeviceIndex()
    {
        switch (serverNumber)
        {
        case 1:
            return 3;
        case 2:
            return 3;
        default:
            return 0;
        }
    }

private:
    inline static const uint16_t TARGET_PORT_1 = 7777;
    inline static const uint16_t TARGET_PORT_2 = 8888;
    inline static const uint16_t TARGET_PORT_3 = 9999;
    inline static uint32_t serverNumber;
    Config() = default; // Prevent instantiation
};
