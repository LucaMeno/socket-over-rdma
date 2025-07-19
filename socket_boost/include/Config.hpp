
#pragma once

#include <cstdint>
#include <vector>

class Config
{
public:
    // CONFIG
    inline static const uint16_t PROXY_PORT = 5555;
    inline static const uint16_t RDMA_SERVER_PORT = 7471;
    inline static const uint32_t RDMA_DEV_PORT = 1;         // Default port for RDMA device
    inline static const uint32_t DEFAULT_DEV_INDEX = 0;     // Default RDMA device index
    inline static const uint32_t DEFAULT_DEV_GID_INDEX = 0; // Default GID index for RDMA device

    // BpfMng configuration
    inline static const char *BPF_CGROUP_PATH = "/sys/fs/cgroup";
    inline static const char *BPF_PATH_TO_BPF_OBJ_FILE = "obj/scap.bpf.o";
    inline static const int BPF_POOL_RB_INTERVAL = 100; // milliseconds

    // Socket manager
    inline static const int NUMBER_OF_SOCKETS = 16;

    // RDMA context
    inline static const size_t MAX_SEND_WR = 4096;
    inline static const size_t MAX_RECV_WR = 16;
    inline static const size_t MAX_SEND_SGE = 1;
    inline static const size_t MAX_RECV_SGE = 1;

    inline static const int MAX_CQ_ENTRIES = 2048; // Maximum number of entries in the completion queue

    inline static const char *RDMA_TCP_PORT = "7472";                        // Default RDMA port for TCP parameters exchange
    inline static const int MAX_MSG_BUFFER = (1024 * 8);                     // POWER OF 2!!!!!!!!!!!
    inline static const int TIME_TO_WAIT_IF_NO_SPACE_MS = 10;                // ms
    inline static const int MAX_PAYLOAD_SIZE = (64 * 1024);                  // 64 KB
    inline static const int QP_N = 4;                                        // Number of QPs
    inline static const size_t MAX_WR_PER_POST = 256;                       // Maximum number of work requests in a post (wr per flight)
    inline static const size_t BATCH_SIZE = MAX_PAYLOAD_SIZE;                // size of the batch to send in one go
    inline static const uint32_t TIME_BTW_DATA_READY_NOTIFICATIONS_MS = 500; // 500 ms
    inline static const int THRESHOLD_NOT_AUTOSCALER = MAX_WR_PER_POST;      // Threshold for flushing messages

    inline static const size_t MAX_WR_BEFORE_SIGNAL = 256; // Maximum number of work requests before signaling

    // RDMA manager
    inline static const int N_WRITER_THREADS = NUMBER_OF_SOCKETS; // 1 thread per proxy socket
    inline static const int TIME_STOP_SELECT_SEC = 5;             // 5 seconds
    inline static const int FLUSH_INTERVAL_MS = 10;               // ms
    inline static const int N_THREAD_POOL_THREADS = 16;

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
