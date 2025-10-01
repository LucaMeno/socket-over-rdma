/* include/config.h */
#pragma once
#include <cstdint>

constexpr int PORT = 7777;
constexpr size_t BUFFER_SIZE_BYTES = 1024 * 1024; // 1 MB
constexpr double DEFAULT_TOTAL_GB = 100.0;        // GB di default
constexpr uint64_t BYTES_PER_GB = 1024ULL * 1024ULL * 1024ULL;
constexpr const char *ACK_MESSAGE = "OK";
constexpr bool CHECK_INTEGRITY = true;     // check data integrity
constexpr bool WAIT_FOR_USER_INPUT = true; // wait for user input

constexpr bool SERVER_SLOW = false; // simulate a slow server
constexpr int MS_TO_WAIT = 1;       // milliseconds to wait if SERVER_SLOW is true

constexpr bool MEASURE_THROUGHPUT = false;  // measure throughput
constexpr bool MEASURE_LATENCY = true;      // measure latency
constexpr int LATENCY_ITERS = 1000;          // number of iterations for latency measurement
constexpr int LATENCY_BUFFER_SIZE = 64;     // buffer size for latency measurement
constexpr int NS_BETWEEN_LATENCY_ITERS = 0; // nanoseconds between latency iterations