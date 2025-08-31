

#pragma once

#include <cstdint>
#include <atomic>
#include <thread>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <iostream>
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
#include <fcntl.h>

#include "RdmaTestConf.hpp"
#include "ThreadPool.h"

#define RING_IDX(i) ((i) & (RdmaTestConf::MAX_MSG_BUFFER - 1))

#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t))
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))
#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

#define MSG_HEADER_SIZE (sizeof(rdma_msg_t) - sizeof(rdma_msg_t::msg))

namespace rdmat
{
    typedef struct sock_id sock_id_t;

    // key structure for the sockmap
    struct sock_id
    {
        __u32 sip;   // stored in NET order
        __u32 dip;   // stored in NET order
        __u16 sport; // stored in HOST byte
        __u16 dport; // stored in HOST byte
    };

    struct conn_info
    {
        uint16_t lid;
        uint32_t qp_num[RdmaTestConf::QP_N];
        uint32_t rq_psn[RdmaTestConf::QP_N];
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
        uint32_t msg_flags;                       // flags
        uint32_t seq_number_head;                 // sequence number
        struct sock_id original_sk_id;            // id of the socket
        uint32_t msg_size;                        // size of the message
        uint32_t number_of_slots;                 // number of slots
        char msg[RdmaTestConf::MAX_PAYLOAD_SIZE]; // message
        uint32_t seq_number_tail;                 // sequence number
    } rdma_msg_t;

    typedef struct
    {
        rdma_flag_t flags;
        std::atomic<uint32_t> remote_write_index;
        std::atomic<uint32_t> remote_read_index;
        uint32_t local_write_index;
        std::atomic<uint32_t> local_read_index;
        rdma_msg_t data[RdmaTestConf::MAX_MSG_BUFFER];
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

    struct WrBatch
    {
        std::vector<WorkRequest *> *wr_batch;
        std::vector<uint32_t> *indexes;

        WrBatch() : wr_batch(new std::vector<WorkRequest *>), indexes(new std::vector<uint32_t>) {}
    };

    const sock_id_t SOCK_TO_USE = {1, 2, 3, 4};

    class RdmaTransfer
    {

    public:
        boost::lockfree::queue<uint32_t, boost::lockfree::capacity<RdmaTestConf::WORK_REQUEST_POOL_SIZE>> wr_busy_idx_queue[RdmaTestConf::N_OF_QUEUES];
        int queue_idx{0};
        boost::lockfree::queue<uint32_t, boost::lockfree::capacity<RdmaTestConf::WORK_REQUEST_POOL_SIZE>> wr_available_idx_queue;
        WorkRequest wr_pool[RdmaTestConf::WORK_REQUEST_POOL_SIZE];

        ibv_context *ctx;
        ibv_pd *pd;
        ibv_mr *mr;

        ibv_qp *qps[RdmaTestConf::QP_N];      // queue pairs
        struct ibv_srq *srq;                  // shared receive queue
        ibv_cq *send_cqs[RdmaTestConf::QP_N]; // send completion queues
        ibv_cq *recv_cq;                      // receive completion queue

        char *buffer;
        uintptr_t remote_addr; // remote address of the buffer
        uint32_t remote_rkey;
        ibv_comp_channel *comp_channel;

        // Context id
        uint32_t remote_ip; // Remote IP

        bool is_server;         // TRUE if server, FALSE if client
        std::atomic<bool> stop; // TRUE if the context should stop

        std::mutex mtx_tx;               // used to wait for the context to be ready
        std::condition_variable cond_tx; // used to signal the context is ready

        std::mutex mtx_rx_read;
        std::mutex mtx_rx_commit;
        std::condition_variable cond_rx_read; // used to signal the read operation is done

        uint64_t last_flush_ms;                    // last time the buffer was flushed, used to avoid flushing too often
        std::mutex mtx_commit_flush;               // used to commit the flush operation
        std::condition_variable cond_commit_flush; // used to signal the flush operation is committed

        rdma_ringbuffer_t *ringbuffer_server; // Ring buffer for server
        rdma_ringbuffer_t *ringbuffer_client; // Ring buffer for client

        rdma_ringbuffer_t *buffer_to_write; // buffer to write data
        rdma_ringbuffer_t *buffer_to_read;  // buffer to read data

        uint64_t last_notification_data_ready_ns; // Last time a notification was sent

        std::atomic<int> outgoing_wrs[RdmaTestConf::QP_N]{0};

        WrBatch getPollingBatch();
        void postWrBatch(WrBatch dr);

        void flushThread();

        RdmaTransfer();
        ~RdmaTransfer();

        serverConnection_t serverSetup();
        void serverHandleNewClient(serverConnection_t &sc);
        void clientConnect(uint32_t server_ip);

        int writeMsg(int src_fd, struct sock_id original_socket);

        void readMsgLoop(int dest_fd);
        void updateRemoteReadIndex();

        uint64_t getTimeMS();

    private:
        std::unique_ptr<ThreadPool> thPoolTransfer; // thread pool
        std::mutex mtx_qp_idx;
        std::condition_variable cv_qp_idx;
        bool is_qp_idx_available[RdmaTestConf::QP_N] = {true};

        size_t local_remote_write_index_offset;
        uintptr_t remote_addr_write_index;
        size_t local_remote_read_index_offset;
        uintptr_t remote_addr_read_index;

        std::atomic<uint32_t> seq_number_write{1}; // start from one since the shared mem is all 0 at the beginning
        std::atomic<uint32_t> seq_number_read{1};  // start from one since the shared mem is all 0 at the beginning

        int tcpConnect(uint32_t ip);
        int tcpWaitForConnection();
        ibv_context *openDevice();
        uint32_t getPsn();
        void pollCqSend(ibv_cq *send_cq_to_poll, int num_entry = 1);

        void postWrBatchListOnQp(std::vector<WorkRequest *> &wr_batch, int qp_idx);

        conn_info rdmaSetupPreHs();
        void rdmaSetupPostHs(conn_info remote, conn_info local);
        void showDevices();
        void enqueueWr(uint32_t start_idx, uint32_t end_idx, size_t data_size);

        WorkRequest createWr(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, bool signaled);
        void createWrAtIdx(uintptr_t remote_addr, uintptr_t local_addr, size_t size_to_write, uint32_t idx);

        int getFreeQpIndex();
        std::vector<int> getFreeQpIndexes(int n);
        void releaseQpIndex(int index);
        void releaseQpIndexes(const std::vector<int> &indexes);

        int getQueueIdx();
    };

} // namespace rdma
