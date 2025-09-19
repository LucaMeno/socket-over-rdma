#include "Logger.h"

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

LogInfo Logger::getLogInfo(LogLevel level) const
{
    switch (level)
    {
    case LogLevel::WARNING:
        return {"[WARN ]", 5};
    case LogLevel::ERROR:
        return {"[ERR  ]", 6};
    case LogLevel::INIT:
        return {"[INIT ]", 1};
    case LogLevel::SHUTDOWN:
        return {"[SHUTD]", 1};
    case LogLevel::INFO:
        return {"[INFO ]", 1};
    case LogLevel::CLEANUP:
        return {"[CLEAN]", 1};
    case LogLevel::DEBUG:
        return {"[DEBUG]", 0};
    case LogLevel::MAIN:
        return {"[MAIN ]", 1};
    case LogLevel::DEVICES:
        return {"[DEV  ]", 2};
    case LogLevel::CONFIG:
        return {"[CONF ]", 2};
    case LogLevel::SOCKOPS:
        return {"[SKOPS]", 2};
    case LogLevel::CONNECT:
        return {"[CONN ]", 2};
    case LogLevel::EBPF:
        return {"[EBPF ]", 2};
    default:
        return {"[?????]", -1};
    }
}

void Logger::log(LogLevel level, const std::string &message)
{
    LogInfo logInfo = getLogInfo(level);

    if (logInfo.numeric < Config::LOG_LEVEL)
        return;

    const char *levelStr = logInfo.str;

    std::ostringstream oss;
    if (Config::LOG_TIME)
        oss << "[" << getTimestamp() << "] ";
    if (Config::PRINT_CLASS_NAME)
        oss << "[" << className << "] ";

    oss << levelStr << " " << message;

    std::string logStr = oss.str();

    if (level == LogLevel::ERROR || level == LogLevel::WARNING)
    {
        if (errno != 0) // avoid spurious messages if errno wasn't set
            oss << " (errno " << errno << ": " << std::strerror(errno) << ")";

        if (!Config::LOG_TO_FILE)
            std::cout << logStr << std::endl;
        else if (logFileErr.is_open())
            logFileErr << logStr << std::endl;
    }
    else
    {
        if (!Config::LOG_TO_FILE)
            std::cout << logStr << std::endl;
        else if (logFile.is_open())
            logFile << logStr << std::endl;
    }
}
