#include <signal.h>
#include <optional>

#include "RdmaMng.h"
#include "Config.hpp"
#include "Logger.h"

int STOP = false;

using namespace std;

void handle_signal(int signal)
{
    STOP = true;
}

std::optional<uint32_t> parseNumber(const string &arg)
{
    try
    {
        size_t pos;
        int value = stoi(arg, &pos);

        // Ensure input is fully numeric and non-negative
        if (pos != arg.length() || value < 0)
            return std::nullopt;

        return static_cast<uint32_t>(value);
    }
    catch (...)
    {
        return std::nullopt;
    }
}

int main(int argc, char *argv[])
{
    Logger logger("Main");
    try
    {
        logger.log(LogLevel::MAIN, "Starting Socket over RDMA application...");

        signal(SIGINT, handle_signal);
        signal(SIGTSTP, handle_signal);

        if (argc != 1 && argc != 3)
        {
            cerr << "Usage: " << argv[0] << " [RDMA_dev_idx] [RDMA_dev_GID_idx]" << endl;
            logger.log(LogLevel::ERROR, "Invalid command line arguments");
            return EXIT_FAILURE;
        }

        std::optional<uint32_t> devIdx;
        std::optional<uint32_t> devGidIdx;

        if (argc == 3)
        {
            devIdx = parseNumber(argv[1]);
            devGidIdx = parseNumber(argv[2]);
            if (!devIdx || !devGidIdx)
            {
                logger.log(LogLevel::WARNING, "Invalid server number: " + std::string(argv[1]) + " Setting to default (0).");
                devIdx = Config::DEFAULT_DEV_INDEX;
                devGidIdx = Config::DEFAULT_DEV_GID_INDEX;
            }
        }
        else
        {
            devIdx = Config::DEFAULT_DEV_INDEX;
            devGidIdx = Config::DEFAULT_DEV_GID_INDEX;
        }

        Config::setDevIdx(*devIdx);
        Config::setRdmaDevGidIdx(*devGidIdx);

        rdmaMng::RdmaMng r(Config::PROXY_PORT,
                           inet_addr(Config::SERVER_IP),
                           Config::RDMA_SERVER_PORT,
                           Config::getTargetPorts());

        r.run();

        logger.log(LogLevel::MAIN, "Waiting for messages, press Ctrl+C to exit...");
        logger.log(LogLevel::MAIN, "-----------------------------------------------------------");
        while (!STOP)
            pause(); // wait for signal
        logger.log(LogLevel::MAIN, "Stopping application...");
        logger.log(LogLevel::MAIN, "-----------------------------------------------------------");
    }
    catch (const std::exception &e)
    {
        logger.log(LogLevel::ERROR, "Exception in main: " + std::string(e.what()));
        return EXIT_FAILURE;
    }
    return 0;
}
