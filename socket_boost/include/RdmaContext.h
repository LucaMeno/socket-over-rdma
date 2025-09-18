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
#include <boost/lockfree/queue.hpp>

#include "BpfMng.h"
#include "SocketMng.h"
#include "Config.hpp"
#include "SockMap.hpp"
#include "ThreadPool.h"
#include "IndexCycle.h"

#define RING_IDX(i) ((i) & (Config::MAX_MSG_BUFFER - 1))

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t))
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))
#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

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
        uint32_t seq_number_head;
        uint32_t msg_flags;                 // flags
        struct sock_id original_sk_id;      // id of the socket
        uint32_t msg_size;                  // size of the message
        uint32_t number_of_slots;           // number of slots
        char msg[Config::MAX_PAYLOAD_SIZE]; // message
        uint32_t seq_number_tail;
    } rdma_msg_t;

    typedef struct
    {
        rdma_flag_t flags;
        std::atomic<uint32_t> remote_write_index;
        std::atomic<uint32_t> remote_read_index;
        uint32_t local_write_index;
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
    };

    class RdmaContext
    {

    public:
        // Context id
        uint32_t remote_ip;             // Remote IP address
        char *buffer;                   // pointer to the beginning of the memory region
        ibv_comp_channel *comp_channel; // completion channel
        ibv_cq *recv_cq;                // receive completion queue

        bool is_server;         // TRUE if server, FALSE if client
        std::atomic<bool> stop; // TRUE if the context should stop

        RdmaContext(bpf::BpfMng &bpf_ctx, std::vector<sk::client_sk_t> &client_sks);
        ~RdmaContext();

        /* CONNECTION HANDLER */
        serverConnection_t serverSetup();
        void serverHandleNewClient(serverConnection_t &sc);
        void clientConnect(uint32_t server_ip, uint16_t server_port);

        /** SEND */
        int writeMsg(int src_fd, struct sock_id original_socket, const std::function<bool()> &is_valid);
        int readMsgLoop(int target_fd, sock_id_t target_sk, const std::function<bool()> &is_valid);

        /* OTHERS */
        const std::string getOpName(CommunicationCode code);
        void waitForContextToBeReady();
        void setPollingStatus(uint32_t is_polling);
        void postReceive(int qpIdx, bool allQp);

    private:
        boost::lockfree::queue<uint32_t, boost::lockfree::capacity<Config::MAX_MSG_BUFFER>> msgs_idx_to_flush_queue[Config::N_OF_QUEUES];

        /* RDMA CONFIG */

        ibv_context *ctx;               // device context
        ibv_pd *pd;                     // protection domain
        ibv_mr *mr;                     // memory region
        ibv_qp *qps[Config::QP_N];      // queue pairs
        struct ibv_srq *srq;            // shared receive queue
        ibv_cq *send_cqs[Config::QP_N]; // send completion queues

        uintptr_t remote_addr; // remote address of the buffer
        uint32_t remote_rkey;  // remote key of the memory region

        std::atomic<bool> is_ready; // TRUE if the context is ready

        bpf::BpfMng &bpf_ctx;
        std::vector<sk::client_sk_t> &client_sks;

        // Used to cycle through the QPs for load balancing
        IndexCycle qp_index_repeater{Config::N_OF_QUEUES, Config::MAX_WR_PER_POST_PER_QP};

        // Offsets and remote addresses of the indexes in the remote memory region
        size_t local_remote_write_index_offset;
        uintptr_t remote_addr_write_index;
        size_t local_remote_read_index_offset;
        uintptr_t remote_addr_read_index;
        rdma_ringbuffer_t *ringbuffer_server; // Ring buffer for server
        rdma_ringbuffer_t *ringbuffer_client; // Ring buffer for client
        rdma_ringbuffer_t *buffer_to_write;   // buffer to write data
        rdma_ringbuffer_t *buffer_to_read;    // buffer to read data

        std::unordered_map<sock_id_t, int> sockid_to_fd_map; // Map of sock_id to fd for fast access

        // Counters for outgoing WRs to kwnow when to poll the CQ
        int outgoing_wrs[Config::QP_N]{0};

        // Threads
        std::thread flush_threads[Config::QP_N - 1];
        std::thread update_remote_r_thread;

        // Synchronization
        std::mutex mtx_tx;

        std::mutex mtx_ctx_ready;
        std::condition_variable cond_ctx_ready;

        uint64_t last_notification_data_ready_ns;

        std::atomic<uint32_t> seq_number_write{1}; // start from one since the shared mem is all 0 at the beginning
        std::atomic<uint32_t> seq_number_read{1};  // start from one since the shared mem is all 0 at the beginning

        /* TX */
        void flushThread(int id);

        void createWrAtIdx(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, WorkRequest *wr);
        void createWrAtIdxFromBufferIdx(uint32_t buffer_idx, WorkRequest *wr);
        void postWrBatchListOnQp(std::vector<WorkRequest *> &wr_batch, int qp_idx);

        /* RX */
        void updateRemoteReadIndexThread();

        /* CONNECTION */
        uint32_t getPsn();
        void showDevices();
        ibv_context *openDevice();
        int tcpConnect(uint32_t ip);
        int tcpWaitForConnection();
        conn_info rdmaSetupPreHs();
        void rdmaSetupPostHs(conn_info remote, conn_info local);

        /* UTILS */
        uint64_t getTimeMS();
        void signalContextReady();
        void pollCqSend(ibv_cq *send_cq_to_poll, int num_entry = 1);

        /* NOTIFICATIONS */
        void sendNotification(CommunicationCode code);
        void sendDataReady();
    };

} // namespace rdma
