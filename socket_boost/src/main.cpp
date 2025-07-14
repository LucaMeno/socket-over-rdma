#include <signal.h>
#include <optional>

#include "RdmaMng.h"
#include "Config.hpp"

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
    try
    {
        signal(SIGINT, handle_signal);
        signal(SIGTSTP, handle_signal);

        if (argc != 1 && argc != 3)
        {
            cerr << "Usage: " << argv[0] << " [RDMA_dev_idx] [RDMA_dev_GID_idx]" << endl;
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
                cerr << "Invalid server number: " << argv[1] << " Setting to default (0)." << endl;
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

        cout << "Waiting for messages, press Ctrl+C to exit..." << endl;
        cout << "-----------------------------------------------------------" << endl;
        while (!STOP)
            pause(); // wait for signal
        cout << "-----------------------------------------------------------" << endl;
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        perror("Exception caught");
        return EXIT_FAILURE;
    }
    return 0;
}
