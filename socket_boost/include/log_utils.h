
#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#define LOG_FILE "rdma_log.txt"
#define ERR_FILE "rdma_error.txt"

/*
typedef enum
{
    BPF,
    SK,
    RDMA_UTILS,
    RDMA_MANAGER
} log_type_t;

void* log_msg(log_type_t type, const char *format, ...);
*/

void log_info(const char *format, ...);

void log_error(const char *format, ...);

#endif // LOG_MANAGER_H