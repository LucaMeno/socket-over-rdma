
#ifndef CONFIG_H
#define CONFIG_H

// #define REMOTE_IP "192.168.88.134"

#define TRUE 1
#define FALSE 0

// RDMA
#define RDMA_PORT 7471
#define RDMA_DEBUG_SR
// #define RDMA_DEBUG_WR

// CS TEST
#define TEST_SERVER_PORT 7777
#define TEST_BUFFER_SIZE 256 // size of the msg sent

#define SERVER_SEND_RESP // server sends a response to the client
#define CLIENT_WAIT_RESP // client waits for a response from the server

//#define CLIENT_CHECK_RESP
#define CLIENT_GAP 100000
#define CLIENT_CHRONO // client measures the time taken to send CLIENT_GAP messages

#define WAIT_FOR_RDMA_CONN

// MAIN
#define PROXY_PORT 5556
#define SERVER_IP "127.0.0.1"
#define TARGET_PORT TEST_SERVER_PORT
//#define PROXY_DEBUG

// SOCKET

// EBPF userspace

// EBPF
// #define EBPF_DEBUG_MODE
// #define INTERCEPT_EVERYTHING

#endif