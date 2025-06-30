#include <signal.h>
#include <vector>

#include <SocketMng.h>
#include <BpfMng.h>
#include "RdmaMng.h"

int STOP = false;

using namespace std;

void handle_signal(int signal);
int fun(void *ctx, void *data, size_t len);

sk::SocketMng *s = nullptr;
bpf::BpfMng *b = nullptr;
rdmaMng::RdmaMng *r = nullptr;

int fun(void *ctx, void *data, size_t len)
{
    struct userspace_data_t *user_data = (struct userspace_data_t *)data;
    printf("New : [%u:%u -> %u:%u] <-> [%u:%u -> %u:%u]\n",
           user_data->association.app.sip,
           user_data->association.app.sport,
           user_data->association.app.dip,
           user_data->association.app.dport,
           user_data->association.proxy.sip,
           user_data->association.proxy.sport,
           user_data->association.proxy.dip,
           user_data->association.proxy.dport);

    // start the RDMA connection
    // only the client start the connection
    if (user_data->sockops_op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
    {
        int ret;
        int proxy_fd = s->getProxyFdFromSockid(user_data->association.proxy);

        if (proxy_fd < 0)
        {
            cerr << "Error: Proxy fd not found for association: "
                 << user_data->association.proxy.sip << ":"
                 << user_data->association.proxy.sport << endl;
            throw std::runtime_error("Proxy fd not found");
        }

        cout << "Proxy fd: " << proxy_fd << endl;
        cout << "App socket: " << user_data->association.app.sip << ":" << user_data->association.app.sport << endl;

        r->connect(user_data->association.app, proxy_fd);
    }

    return 0;
}

int main()
{
    try
    {
        signal(SIGINT, handle_signal);
        signal(SIGTSTP, handle_signal);

        s = new sk::SocketMng(PROXY_PORT, inet_addr(SERVER_IP));

        bpf::EventHandler handler = {
            .ctx = nullptr,
            .handle_event = fun};
        b = new bpf::BpfMng(handler, {TARGET_PORT}, PROXY_PORT, s->client_sk_fd);

        r = new rdmaMng::RdmaMng(PROXY_PORT, s->client_sk_fd, *b);

        b->run();

        r->run();

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

void handle_signal(int signal)
{
    STOP = true;
}
