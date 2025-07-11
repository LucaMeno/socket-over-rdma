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

#include "BpfMng.h"
#include "SocketMng.h"
#include "config.h"
#include "SockMap.hpp"

#define RING_IDX(i) ((i) & (MAX_MSG_BUFFER - 1))

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t) * 5)
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))
#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

constexpr int MAX_MSG_BUFFER = (1024 * 8); // POWER OF 2!!!!!!!!!!!
constexpr int THRESHOLD_NOT_AUTOSCALER = 64;
constexpr int TIME_TO_WAIT_IF_NO_SPACE_MS = 10;
constexpr int MAX_PAYLOAD_SIZE = (128 * 1024);

constexpr int QP_N = 4;

namespace rdma
{
    struct conn_info
    {
        uint16_t lid;
        uint32_t qp_num[QP_N];
        uint32_t rq_psn[QP_N];
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
        uint32_t msg_flags;            // flags
        struct sock_id original_sk_id; // id of the socket
        uint32_t msg_size;             // size of the message
        uint32_t number_of_slots;      // number of slots
        char msg[MAX_PAYLOAD_SIZE];    // message
    } rdma_msg_t;

    typedef struct
    {
        rdma_flag_t flags;
        std::atomic<uint32_t> remote_write_index;
        std::atomic<uint32_t> remote_read_index;
        std::atomic<uint32_t> local_write_index;
        std::atomic<uint32_t> local_read_index;
        rdma_msg_t data[MAX_MSG_BUFFER];
    } rdma_ringbuffer_t;

    typedef struct
    {
        int fd;                           // file descriptor of the socket
        struct conn_info conn_info_local; // connection info
    } serverConnection_t;

    class RdmaContext
    {
        const char *TCP_PORT = "7471"; // Default RDMA port for TCP parameters exchange

    public:
        ibv_context *ctx;
        ibv_pd *pd;
        ibv_mr *mr;

        ibv_qp *qps[QP_N];
        struct ibv_srq *srq;
        ibv_cq *send_cqs[QP_N];
        ibv_cq *recv_cq;

        char *buffer;
        uintptr_t remote_addr;
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

        std::unordered_map<sock_id_t, int> sockid_to_fd_map; // Map of sock_id to fd for fast access

        std::mutex mtx_send_q; // Mutex to protect the send_q_index
        uint32_t send_q_index;

        // CLIENT - SERVER

        RdmaContext();
        ~RdmaContext();

        serverConnection_t serverSetup();
        void serverHandleNewClient(serverConnection_t &sc);
        void clientConnect(uint32_t server_ip, uint16_t server_port);

        // COMMUNICATION
        int writeMsg(int src_fd, struct sock_id original_socket);
        void readMsg(bpf::BpfMng &bpf_ctx, std::vector<sk::client_sk_t> &client_sks, uint32_t start_read_index, uint32_t end_read_index);
        void flushRingbuffer(rdma_ringbuffer_t &ringbuffer, uint32_t start_idx, uint32_t end_idx);
        void updateRemoteReadIndex(rdma_ringbuffer_t &ringbuffer, uint32_t r_idx);

        // POLLING
        void setPollingStatus(uint32_t is_polling);

        // UTILS
        const std::string getOpName(CommunicationCode code);
        uint64_t getTimeMS();
        void waitForContextToBeReady();

    private:
        int tcpConnect(uint32_t ip);
        int tcpWaitForConnection();
        ibv_context *openDevice();
        uint32_t getPsn();
        void sendNotification(CommunicationCode code);
        void pollCqSend(ibv_cq *send_cq_to_poll);
        void parseMsg(bpf::BpfMng &bpf_ctx, std::vector<sk::client_sk_t> &client_sks, rdma_msg_t &msg);
        void postWriteOp(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, bool signaled);
        void sendDataReady();
        conn_info rdmaSetupPreHs();
        void rdmaSetupPostHs(conn_info remote, conn_info local);
        uint32_t getNextSendQIndex();
    };

} // namespace rdma
