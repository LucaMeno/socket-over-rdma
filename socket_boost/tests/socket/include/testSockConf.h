/* include/config.h */
#pragma once
#include <cstdint>

constexpr int PORT = 7777;
constexpr size_t BUFFER_SIZE_BYTES = 1024 * 1024; // 1 MB
constexpr double DEFAULT_TOTAL_GB = 50.0;         // GB di default
constexpr uint64_t BYTES_PER_GB = 1024ULL * 1024ULL * 1024ULL;
constexpr const char *ACK_MESSAGE = "OK";

