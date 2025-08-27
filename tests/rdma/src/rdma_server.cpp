
#include <Manager.h>
#include <signal.h>
#include <optional>

int STOP = false;

using namespace std;

void handle_signal(int signal)
{
    STOP = true;
}

int main(int argc, char **argv)
{
    signal(SIGINT, handle_signal);
    signal(SIGTSTP, handle_signal);

    Manager::Manager manager;

    manager.server(RdmaTestConf::RDMA_SERVER_PORT);

    cout << "Waiting for messages, press Ctrl+C to exit..." << endl;
    cout << "-----------------------------------------------------------" << endl;
    while (!STOP)
        pause(); // wait for signal
    cout << "-----------------------------------------------------------" << endl;

    return 0;
}
