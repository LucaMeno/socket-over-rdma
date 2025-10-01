
#pragma once

#include <cstdint>
#include <vector>

class Config
{
public:
    /* PROXY */
    inline static const uint16_t PROXY_PORT = 5555;    // Port where the proxy listens for proxy sockets
    inline static const char *SERVER_IP = "127.0.0.1"; // IP address of the server to which the proxy connects (localhost)

    /* SOCKET MANAGER*/
    inline static const int NUMBER_OF_SOCKETS = 6;

    /* eBPF MANAGER */
    inline static const char *BPF_CGROUP_PATH = "/sys/fs/cgroup";          // Path to the cgroup filesystem
    inline static const char *BPF_PATH_TO_BPF_OBJ_FILE = "obj/scap.bpf.o"; // Path to the compiled BPF object file
    inline static const int BPF_POOL_RB_INTERVAL = 100;                    // milliseconds

    /* RDMA MANAGER */
    inline static const int N_WRITER_THREADS = NUMBER_OF_SOCKETS; // 1 thread per proxy socket
    inline static const int N_READER_THREADS = NUMBER_OF_SOCKETS; // 1 thread per proxy socket FIXED
    inline static const int TIME_STOP_SELECT_SEC = 5;             // 5 seconds

    /* RDMA COMMUNICATION */
    inline static const int MAX_MSG_BUFFER = (256);                          // POWER OF 2!!!!!!!!!!!
    inline static const int MAX_PAYLOAD_SIZE = (128 * 1024);                 // 128 KB
    inline static const int QP_N = 2 + 1;                                    // Number of QPs
    inline static const int DEFAULT_QP_IDX = 0;                              // Default QP index
    inline static const uint32_t TIME_BTW_DATA_READY_NOTIFICATIONS_MS = 500; // 500 ms
    inline static const int N_OF_QUEUES = QP_N - 1;                          // Numbero of flush queue, exclude the default QP
    inline static const int POLL_CQ_AFTER_WR = 64;                           // Poll the CQ after this number of WR signaled posted
    inline static const int MAX_WR_PER_POST_PER_QP = 32;                     // Max WR per post per QP

    inline static const int FLUSH_INTERVAL_MS = 2;   // Flush interval in milliseconds
    inline static const int FLUSH_INTERVAL_NS = 150; // Flush interval in nanoseconds
    inline static const bool USE_NS = false;         // Use nanoseconds for flush interval

    inline static int IOVS_BATCH_SIZE = 32;
    inline static int N_RETRY_WRITE_MSG = 30;
    inline static int PRINT_NO_SPACE_EVERY = 1000000;

    /* RDMA CONFIG SETUP*/
    inline static const uint16_t RDMA_SERVER_PORT = 7471;   // Port where the RDMA server listens for incoming connections
    inline static const char *RDMA_TCP_PORT = "7472";       // Default RDMA port for TCP parameters exchange
    inline static const uint32_t RDMA_DEV_PORT = 1;         // Default port for RDMA device
    inline static const uint32_t DEFAULT_DEV_INDEX = 0;     // Default RDMA device index
    inline static const uint32_t DEFAULT_DEV_GID_INDEX = 0; // Default GID index for RDMA device
    inline static const int ALIGNMENT = 4096;               // Size of a memory page

    /* RDMA QP */
    inline static const size_t MAX_SEND_WR = MAX_WR_PER_POST_PER_QP * POLL_CQ_AFTER_WR;
    inline static const size_t MAX_RECV_WR = 16;
    inline static const size_t MAX_SEND_SGE = 1;
    inline static const size_t MAX_RECV_SGE = 1;
    inline static const int MAX_CQ_ENTRIES = POLL_CQ_AFTER_WR; // Maximum number of entries in the completion queue

    /* LOGGER */
    inline static const char *LOG_FILE = "rdma_proxy.log";
    inline static const char *LOG_FILE_ERR = "rdma_proxy_err.log";
    inline static const bool LOG_TO_FILE = false;
    inline static const bool LOG_TIME = false;
    inline static const bool PRINT_CLASS_NAME = false;
    /**
     * Log levels:
     * 0: DEBUG
     * 1: INFO (INIT, SHUTDOWN, CLEANUP, MAIN)
     * 2: CONN, DEV, CONF, SKOPS, EBPF
     * 5: WARNING
     * 6: ERROR
     */
    inline static const int LOG_LEVEL = 0;

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
