#include <signal.h>

#include "RdmaMng.h"

int STOP = false;

using namespace std;

void handle_signal(int signal)
{
    STOP = true;
}

int main()
{
    try
    {
        signal(SIGINT, handle_signal);
        signal(SIGTSTP, handle_signal);

        rdmaMng::RdmaMng r(PROXY_PORT, inet_addr(SERVER_IP), RDMA_PORT, {TARGET_PORT});
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
