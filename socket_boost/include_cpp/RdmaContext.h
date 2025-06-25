#pragma once

#include <cstdint>
#include <atomic>
#include <pthread.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <iostream>
#include <unordered_map>

#include <BpfMng.h>
#include <SocketMng.h>
#include "config.h"

#define THRESHOLD_NOT_AUTOSCALER 256

// BUFFER CONFIGURATION
#define MAX_MSG_BUFFER (1024 * 8) // POWER OF 2!!!!!!!!!!!

#define MAX_PAYLOAD_SIZE (128 * 1024) // 128 KB

#define TIME_TO_WAIT_IF_NO_SPACE_MS 10

// READ
#define MSG_TO_READ_PER_THREAD 128

// SIZE OF STRUCTURES
#define NOTIFICATION_OFFSET_SIZE (sizeof(notification_t) * 5)
#define RING_BUFFER_OFFSET_SIZE (sizeof(rdma_ringbuffer_t))
#define MR_SIZE ((sizeof(rdma_ringbuffer_t) * 2) + NOTIFICATION_OFFSET_SIZE)

namespace rdma
{
    struct conn_info
    {
        uint16_t lid;
        uint32_t qp_num;
        uint32_t psn;
        uint32_t rkey;
        uint64_t addr;
        union ibv_gid gid; /* piena di zeri su InfiniBand pure */
    } __attribute__((packed));

    enum class CommunicationCode : int32_t
    {
        RDMA_DATA_READY = 10,
        EXCHANGE_REMOTE_INFO = 4,
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

    struct rdma_flag
    {
        std::atomic_uint flags;
    };

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
        rdma_flag flags;
        std::atomic_uint remote_write_index;
        std::atomic_uint remote_read_index;
        std::atomic_uint local_write_index;
        std::atomic_uint local_read_index;
        rdma_msg_t data[MAX_MSG_BUFFER];
    } rdma_ringbuffer_t;

    class RdmaContext
    {
    public:
        // RDMA
        struct rdma_event_channel *client_ec; // for client only
        struct rdma_cm_id *conn;              // Connection ID
        struct ibv_pd *pd;                    // Protection Domain
        struct ibv_mr *mr;                    // Memory Region
        struct ibv_qp *qp;                    // Queue Pair
        struct ibv_cq *send_cq;               // send completion queue
        struct ibv_cq *recv_cq;               // recv completion queue
        void *buffer;                         // Buffer to send
        size_t buffer_size;                   // Size of the buffer
        uintptr_t remote_addr;                // Remote address
        uint32_t remote_rkey;                 // Remote RKey

        struct ibv_comp_channel *comp_channel; // Completion channel

        // Context id
        __u32 remote_ip; // Remote IP

        int is_server;             // TRUE if server, FALSE if client
        std::atomic_uint is_ready; // TRUE if the context is ready

        pthread_mutex_t mtx_tx; // used to wait for the context to be ready
        pthread_cond_t cond_tx; // used to signal the context is ready

        uint64_t last_flush_ms; // last time the buffer was flushed, used to avoid flushing too often
        std::atomic_uint is_flushing;

        std::atomic_uint is_flush_thread_running; // TRUE if the flush thread is running, used to avoid multiple flush threads

        pthread_mutex_t mtx_commit_flush; // used to commit the flush operation
        pthread_cond_t cond_commit_flush; // used to signal the flush operation is committed

        std::atomic_uint n_msg_sent; // counter for the number of messages sent, used to determinate the threshold for flushing
        std::atomic_uint flush_threshold;
        uint64_t flush_threshold_set_time; // time when the flush threshold was set, used to determine if we should change the flush threshold
        uint32_t fulsh_index;
        pthread_mutex_t mtx;

        uint64_t time_start_polling; // time when the polling started, used to be able to stop the polling thread
        uint32_t loop_with_no_msg;   // number of loops with no messages, used to stop the polling thread if there are no messages for a while

        uint64_t time_last_recv; // time when the last message was sent, used to determine if we should poll
        uint32_t n_recv_msg;     // number of messages recv operations, used to determine if we should poll

        rdma_ringbuffer_t *ringbuffer_server; // Ring buffer for server
        rdma_ringbuffer_t *ringbuffer_client; // Ring buffer for client

        std::unordered_map<sock_id_t, int> sockid_to_fd_map; // Map of sock_id to fd for fast access

        // CLIENT - SERVER
        void serverSetup();
        void clientConnect(const char *server_ip, uint16_t server_port);

        // SETUP
        int rdma_context_destroy();
        int rdma_context_init();

        // COMMUNICATION
        int rdma_write_msg(int src_fd, struct sock_id original_socket);
        int rdma_read_msg(bpf_context_t *bpf_ctx, client_sk_t *client_sks, uint32_t start_read_index, uint32_t end_read_index);
        int rdma_flush_buffer(rdma_ringbuffer_t *ringbuffer);
        int rdma_send_data_ready();
        int rdma_update_remote_read_idx(rdma_ringbuffer_t *ringbuffer, uint32_t r_idx);
        int rdma_flush_buffer_2(rdma_ringbuffer_t *ringbuffer, uint32_t start_idx, uint32_t end_idx);

        // POLLING
        int rdma_set_polling_status(uint32_t is_polling);

        // UTILS
        const char *get_op_name(CommunicationCode code);
        uint64_t get_time_ms();
    };

} // namespace rdma
