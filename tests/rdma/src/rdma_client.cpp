
#include <Manager.h>
#include <signal.h>
#include <optional>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>

int STOP = false;

using namespace std;
uint32_t ipToUint32(const std::string &ip);
void handle_signal(int signal)
{
    STOP = true;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <ip>\n";
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTSTP, handle_signal);

    std::string ip = argv[1];
    uint32_t ipNum = ipToUint32(ip);

    Manager::Manager manager;

    manager.client(ipNum, RdmaTestConf::RDMA_SERVER_PORT);

    cout << "Waiting for messages, press Ctrl+C to exit..." << endl;
    cout << "-----------------------------------------------------------" << endl;
    while (!STOP)
        pause(); // wait for signal
    cout << "-----------------------------------------------------------" << endl;

    return 0;
}

uint32_t ipToUint32(const std::string &ip)
{
    std::stringstream ss(ip);
    std::string token;
    uint32_t result = 0;
    int shift = 24;

    while (std::getline(ss, token, '.'))
    {
        int octet = std::stoi(token);
        if (octet < 0 || octet > 255)
        {
            throw std::invalid_argument("Ottetto fuori dal range (0-255).");
        }
        result |= (octet << shift);
        shift -= 8;
    }

    return result;
}
