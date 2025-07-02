
#ifndef CONFIG_H
#define CONFIG_H

#define TRUE true
#define FALSE false

// RDMA
#define RDMA_PORT 7471
#define RDMA_DEBUG_SR // sedn/recv
// #define RDMA_DEBUG_WRITE
//#define RDMA_DEBUG_FLUSH
//#define RDMA_DEBUG_READ
#define RDMA_DEBUG_INTERVAL 100
// #define RDMA_DEBUG_PARSE_MSG
// #define RDMA_DEBUG_WRITE_IN_MSG

// CS TEST
#define TEST_SERVER_PORT 7777
#define TEST_BUFFER_SIZE 2048 // size of the msg sent
//#define C_S_RESPONSE // server sends a response to the client and client waits for it
#define N_OF_MSG_CS (10000000)

#define CLIENT_CHRONO // client measures the time taken to send CLIENT_GAP messages
#define SERVER_CHRONO // server measures the time taken to receive CLIENT_GAP messages

#define WAIT_FOR_RDMA_CONN

// MAIN
#define PROXY_PORT 5555
#define SERVER_IP "127.0.0.1"
#define TARGET_PORT_1 7777
#define TARGET_PORT_2 8888
#define TARGET_PORT_3 9999
// #define PROXY_DEBUG

// SOCKET

// EBPF userspace

// EBPF
#define EBPF_DEBUG_SOCKET 1
#define EBPF_DEBUG_MSG
// #define INTERCEPT_EVERYTHING

#endif