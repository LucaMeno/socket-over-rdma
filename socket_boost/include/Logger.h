#pragma once

#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>
#include <cstring>

#include "Config.hpp"

enum class LogLevel
{
    DEBUG,
    WARNING,
    ERROR,
    INIT,
    SHUTDOWN,
    INFO,
    CLEANUP,
    MAIN,
    DEVICES,
    CONFIG,
    SOCKOPS,
    CONNECT,
    EBPF,
};

struct LogInfo
{
    const char *str;
    int numeric;
};

class Logger
{
private:
    std::ofstream logFile;
    std::ofstream logFileErr;
    std::string getTimestamp() const;
    std::string className;

    LogInfo getLogInfo(LogLevel level) const;

public:
    Logger(std::string clsName);
    ~Logger();
    void log(LogLevel level, const std::string &message);
};
