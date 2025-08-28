
#pragma once

#include <cstdint>
#include <vector>

constexpr int PORT = 7777;
constexpr size_t BUFFER_SIZE_BYTES = 1024 * 1024; // 1 MB
constexpr double DEFAULT_TOTAL_GB = 50.0;         // GB di default
constexpr uint64_t BYTES_PER_GB = 1024ULL * 1024ULL * 1024ULL;
constexpr const char *ACK_MESSAGE = "OK";
constexpr const char *LOCALHOST = "127.0.0.1";

class RdmaTestConf
{
public:
    // CONFIG
    inline static const uint16_t PROXY_PORT = 5555;
    inline static const uint16_t RDMA_SERVER_PORT = 7471;
    inline static const uint32_t RDMA_DEV_PORT = 1;         // Default port for RDMA device
    inline static const uint32_t DEFAULT_DEV_INDEX = 0;     // Default RDMA device index
    inline static const uint32_t DEFAULT_DEV_GID_INDEX = 0; // Default GID index for RDMA device

    // RDMA context

    inline static const ibv_mtu RDMA_MTU = IBV_MTU_1024;

    inline static const int ALIGNMENT = 4096; // Size of a memory page

    inline static const char *RDMA_TCP_PORT = "7472";        // Default RDMA port for TCP parameters exchange
    inline static const int MAX_MSG_BUFFER = (2048);         // POWER OF 2!!!!!!!!!!!
    inline static const int TIME_TO_WAIT_IF_NO_SPACE_MS = 2; // ms
    inline static const int MAX_PAYLOAD_SIZE = (64 * 1024);  // 64 KB
    inline static const int QP_N = 16 + 1;                   // Number of QPs
    inline static const int DEFAULT_QP_IDX = 0;              // Default QP index

    inline static const int POLL_CQ_AFTER_WR = 32;
    inline static const int MAX_WR_PER_POST_PER_QP = 256;

    inline static const size_t MAX_SEND_WR = MAX_WR_PER_POST_PER_QP * POLL_CQ_AFTER_WR;
    inline static const size_t MAX_RECV_WR = 16;
    inline static const size_t MAX_SEND_SGE = 1;
    inline static const size_t MAX_RECV_SGE = 1;
    inline static const int MAX_CQ_ENTRIES = POLL_CQ_AFTER_WR; // Maximum number of entries in the completion queue

    inline static const int WORK_REQUEST_POOL_SIZE = MAX_MSG_BUFFER; // Capacity of the write queue POWER OF 2!!!!!!!!!!!
    // RDMA manager
    inline static const int TIME_STOP_SELECT_SEC = 5;
    inline static const int FLUSH_INTERVAL_MS = 100;
    inline static const int N_THREAD_POOL_THREADS = 24;

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
    RdmaTestConf() = default; // Prevent instantiation
};
