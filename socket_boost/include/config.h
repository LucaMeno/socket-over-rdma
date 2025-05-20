
#ifndef CONFIG_H
#define CONFIG_H

#define TRUE 1
#define FALSE 0

// RDMA
#define RDMA_PORT 7471
#define RDMA_DEBUG_SR // sedn/recv
// #define RDMA_DEBUG_WRITE
//#define RDMA_DEBUG_FLUSH
//#define RDMA_DEBUG_READ
// #define RDMA_DEBUG_PARSE_MSG
// #define RDMA_DEBUG_WRITE_IN_MSG
// #define RDMA_DEBUG_WRITE_MSG

// CS TEST
#define TEST_SERVER_PORT 7777
#define TEST_BUFFER_SIZE 2048 // size of the msg sent

// #define SERVER_SEND_RESP // server sends a response to the client
// #define CLIENT_WAIT_RESP // client waits for a response from the server

// #define CLIENT_CHECK_RESP
#define N_OF_MSG_CS (10000000)
#define CLIENT_CHRONO // client measures the time taken to send CLIENT_GAP messages
#define SERVER_CHRONO // server measures the time taken to receive CLIENT_GAP messages

#define WAIT_FOR_RDMA_CONN

// MAIN
#define PROXY_PORT 5555
#define SERVER_IP "127.0.0.1"
#define TARGET_PORT TEST_SERVER_PORT
// #define PROXY_DEBUG

// SOCKET

// EBPF userspace

// EBPF
//#define EBPF_DEBUG_SOCKET
//#define EBPF_DEBUG_MSG
// #define INTERCEPT_EVERYTHING

#endif