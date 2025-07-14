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

std::optional<uint32_t> parseServerNumber(const string &arg)
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

        if (argc > 2)
        {
            cerr << "Usage: " << argv[0] << " [server_number]" << endl;
            return EXIT_FAILURE;
        }

        std::optional<uint32_t> serverNum;
        if (argc == 2)
        {
            serverNum = parseServerNumber(argv[1]);
            if (!serverNum)
            {
                cerr << "Invalid server number: " << argv[1] << " Setting to default (0)." << endl;
                serverNum = 0; // Default if parsing fails
            }
        }
        else
        {
            serverNum = 0; // Default if no argument provided
        }

        Config::setServerNumber(*serverNum);

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
