
#ifndef CONFIG_H
#define CONFIG_H

//#define REMOTE_IP "192.168.88.134"


#define TRUE 1
#define FALSE 0

// RDMA
#define RDMA_PORT 7471
#define RDMA_DEBUG_SR
#define RDMA_DEBUG_WR


// CS TEST
#define TEST_SERVER_PORT 7777
#define TEST_BUFFER_SIZE 1024
#define SERVER_SEND_RESP
#define CLIENT_WAIT_RESP
//#define CLIENT_CHECK_RESP 1
#define CLIENT_GAP 10000
//#define CLIENT_SLOW_1
//#define CLIENT_SLOW_2
#define SEC_TO_WAIT 2
//#define CLIENT_CHRONO

// MAIN
#define PROXY_PORT 5556
#define SERVER_IP "127.0.0.1"
#define TARGET_PORT TEST_SERVER_PORT
#define PROXY_DEBUG

// SOCKET


// EBPF userspace

// EBPF
//#define EBPF_DEBUG_MODE
//#define INTERCEPT_EVERYTHING

#endif