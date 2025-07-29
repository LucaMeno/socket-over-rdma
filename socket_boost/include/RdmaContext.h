#pragma once

#include <cstdint>
#include <atomic>
#include <thread>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <iostream>
#include <unordered_map>
#include <netdb.h>
#include <mutex>
#include <condition_variable>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <queue>

#include "BpfMng.h"
#include "SocketMng.h"
#include "Config.hpp"
#include "SockMap.hpp"
#include "IndexPool.hpp"

#define RING_IDX(i) ((i) & (Config::MAX_MSG_BUFFER - 1))

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t) * 5)
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))
#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

#define MSG_HEADER_SIZE (sizeof(rdma_msg_t) - sizeof(rdma_msg_t::msg))

namespace rdma
{
    struct conn_info
    {
        uint16_t lid;
        uint32_t qp_num[Config::QP_N];
        uint32_t rq_psn[Config::QP_N];
        uint32_t rkey;
        uint64_t addr;
        union ibv_gid gid;
    } __attribute__((packed));

    enum class CommunicationCode : int32_t
    {
        RDMA_DATA_READY = 10,
        RDMA_CLOSE_CONTEXT = 5,
        NONE = -1
    };

    typedef struct
    {
        CommunicationCode code; // code of the notification
    } notification_data_t;

    typedef struct
    {
        notification_data_t from_server; // notification from server
        notification_data_t from_client; // notification from client
    } notification_t;

    typedef struct
    {
        std::atomic<uint32_t> flags;
    } rdma_flag_t;

    enum class RingBufferFlag : int32_t
    {
        RING_BUFFER_EMPTY = 2,
        RING_BUFFER_POLLING = 4,
        RING_BUFFER_CAN_POLLING = 8
    };

    typedef struct
    {
        uint32_t msg_flags;                 // flags
        struct sock_id original_sk_id;      // id of the socket
        uint32_t msg_size;                  // size of the message
        uint32_t number_of_slots;           // number of slots
        char msg[Config::MAX_PAYLOAD_SIZE]; // message
    } rdma_msg_t;

    typedef struct
    {
        rdma_flag_t flags;
        std::atomic<uint32_t> remote_write_index;
        std::atomic<uint32_t> remote_read_index;
        std::atomic<uint32_t> local_write_index;
        std::atomic<uint32_t> local_read_index;
        rdma_msg_t data[Config::MAX_MSG_BUFFER];
    } rdma_ringbuffer_t;

    typedef struct
    {
        int fd;                           // file descriptor of the socket
        struct conn_info conn_info_local; // connection info
    } serverConnection_t;

    struct WorkRequest
    {
        ibv_send_wr wr;
        ibv_sge sge;
        uint32_t pre_idx;
        uint32_t new_idx;
    };

    class RdmaContext
    {
    public:
        ibv_context *ctx;
        ibv_pd *pd;
        ibv_mr *mr;

        ibv_qp *qps[Config::QP_N];      // queue pairs
        struct ibv_srq *srq;            // shared receive queue
        ibv_cq *send_cqs[Config::QP_N]; // send completion queues
        ibv_cq *recv_cq;                // receive completion queue

        char *buffer;
        uintptr_t remote_addr; // remote address of the buffer
        uint32_t remote_rkey;
        ibv_comp_channel *comp_channel;

        // Context id
        uint32_t remote_ip; // Remote IP

        bool is_server;             // TRUE if server, FALSE if client
        std::atomic<bool> is_ready; // TRUE if the context is ready
        std::atomic<bool> stop;     // TRUE if the context should stop

        std::mutex mtx_tx;               // used to wait for the context to be ready
        std::condition_variable cond_tx; // used to signal the context is ready

        uint64_t last_flush_ms;                    // last time the buffer was flushed, used to avoid flushing too often
        std::mutex mtx_commit_flush;               // used to commit the flush operation
        std::condition_variable cond_commit_flush; // used to signal the flush operation is committed
        std::atomic<uint32_t> n_msg_sent;          // counter for the number of messages sent, used to determinate the threshold for flushing
        std::atomic<uint32_t> flush_threshold;

        rdma_ringbuffer_t *ringbuffer_server; // Ring buffer for server
        rdma_ringbuffer_t *ringbuffer_client; // Ring buffer for client

        rdma_ringbuffer_t *buffer_to_write; // buffer to write data
        rdma_ringbuffer_t *buffer_to_read;  // buffer to read data

        std::unordered_map<sock_id_t, int> sockid_to_fd_map; // Map of sock_id to fd for fast access

        uint64_t last_notification_data_ready_ns; // Last time a notification was sent

        bool can_flush = false; // Flag to indicate if the context can flush
        std::queue<WorkRequest> work_reqs;
        std::mutex mtx_wrs;            // Mutex to protect the work requests queue

        RdmaContext();
        ~RdmaContext();

        serverConnection_t serverSetup();
        void serverHandleNewClient(serverConnection_t &sc);
        void clientConnect(uint32_t server_ip, uint16_t server_port);

        int writeMsg(int src_fd, struct sock_id original_socket);
        void readMsg(bpf::BpfMng &bpf_ctx, std::vector<sk::client_sk_t> &client_sks, uint32_t start_read_index, uint32_t end_read_index);
        void updateRemoteReadIndex(uint32_t r_idx);

        void setPollingStatus(uint32_t is_polling);

        const std::string getOpName(CommunicationCode code);
        uint64_t getTimeMS();
        void waitForContextToBeReady();

        void flushWrQueue();
        bool shouldFlushWrQueue();

    private:
        IndexPool idxPool;

        int tcpConnect(uint32_t ip);
        int tcpWaitForConnection();
        ibv_context *openDevice();
        uint32_t getPsn();
        void sendNotification(CommunicationCode code);
        void pollCqSend(ibv_cq *send_cq_to_poll);
        void parseMsg(bpf::BpfMng &bpf_ctx, std::vector<sk::client_sk_t> &client_sks, rdma_msg_t &msg);
        // void postWriteOp(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, bool signaled);
        void sendDataReady();
        conn_info rdmaSetupPreHs();
        void rdmaSetupPostHs(conn_info remote, conn_info local);
        void showDevices();
        void updateRemoteWriteIndex(uint32_t pre_index, uint32_t new_index);

        void enqueueWr(rdma_ringbuffer_t &ringbuffer, uint32_t start_idx, uint32_t end_idx, size_t data_size);
        void executeWrNow(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, bool signaled);
        void executeWrNow(WorkRequest wr, bool signaled);

        WorkRequest createWr(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, bool signaled);
    };

} // namespace rdma
