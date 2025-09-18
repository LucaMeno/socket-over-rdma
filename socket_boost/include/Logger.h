#pragma once

#include <string>
#include <fstream>

#include "Config.hpp"

enum class LogLevel
{
    DEBUG_TX,
    DEBUG_RX,
    DEBUG,
    WARNING,
    ERROR,
    INIT,
    SHUTDOWN,
    INFO,
    CLEANUP,
    MAIN,
    DEVICES,
    CONFIG
};

class Logger
{
private:
    std::ofstream logFile;
    std::ofstream logFileErr;
    std::string getTimestamp() const;
    std::string className;

public:
    Logger(std::string clsName);
    ~Logger();
    void log(LogLevel level, const std::string &message);
};
