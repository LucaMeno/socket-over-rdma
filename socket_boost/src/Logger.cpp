#include "Logger.h"
#include <iostream>
#include <ctime>

Logger::Logger(std::string clsName) : className(clsName)
{
    if (!Config::LOG_TO_FILE)
        return;

    logFile.open(Config::LOG_FILE, std::ios::app);
    if (!logFile.is_open())
        std::cerr << "Error opening log file!" << std::endl;

    logFileErr.open(Config::LOG_FILE_ERR, std::ios::app);
    if (!logFileErr.is_open())
        std::cerr << "Error opening error log file!" << std::endl;
}

Logger::~Logger()
{
    if (!Config::LOG_TO_FILE)
        return;
    if (logFile.is_open())
        logFile.close();
    if (logFileErr.is_open())
        logFileErr.close();
}

std::string Logger::getTimestamp() const
{
    if (!Config::LOG_TIME)
        return "";
    std::time_t now = std::time(nullptr);
    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buffer);
}

void Logger::log(LogLevel level, const std::string &message)
{
    std::string levelStr;
    switch (level)
    {
    case LogLevel::DEBUG_TX:
        levelStr = "[DEBUG_TX]";
        break;
    case LogLevel::DEBUG_RX:
        levelStr = "[DEBUG_RX]";
        break;
    case LogLevel::WARNING:
        levelStr = "[WARNING  ]";
        break;
    case LogLevel::ERROR:
        levelStr = "[ERROR    ]";
        break;
    case LogLevel::INIT:
        levelStr = "[INIT     ]";
        break;
    case LogLevel::SHUTDOWN:
        levelStr = "[SHUTDOWN ]";
        break;
    case LogLevel::INFO:
        levelStr = "[INFO     ]";
        break;
    case LogLevel::CLEANUP:
        levelStr = "[CLEANUP  ]";
        break;
    case LogLevel::DEBUG:
        levelStr = "[DEBUG    ]";
        break;
    case LogLevel::MAIN:
        levelStr = "[MAIN     ]";
        break;
    case LogLevel::DEVICES:
        levelStr = "[DEVICES  ]";
        break;
    case LogLevel::CONFIG:
        levelStr = "[CONFIG   ]";
        break;
    case LogLevel::SOCKOPS:
        levelStr = "[SOCKOPS  ]";
        break;
    case LogLevel::CONNECT:
        levelStr = "[CONNECT  ]";
        break;
    case LogLevel::EBPF:
        levelStr = "[EBPF     ]";
        break;
    default:
        levelStr = "[?????????]";
        break;
    }

    std::ostringstream oss;
    if (Config::LOG_TIME)
        oss << "[" << getTimestamp() << "] ";
    if (Config::PRINT_CLASS_NAME)
        oss << "[" << className << "] ";

    oss << levelStr << " " << message;

    std::string logStr = oss.str();

    if (level == LogLevel::ERROR || level == LogLevel::WARNING)
    {
        if (!Config::LOG_TO_FILE)
            std::cout << logStr << std::endl;
        else if (logFileErr.is_open())
            logFileErr << logStr << std::endl;
        perror(message.c_str());
    }
    else
    {
        if (!Config::LOG_TO_FILE)
            std::cout << logStr << std::endl;
        else if (logFile.is_open())
            logFile << logStr << std::endl;
    }
}
