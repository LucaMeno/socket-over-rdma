#include <signal.h>
#include <vector>

#include <SocketMng.h>
#include <BpfMng.h>
#include "RdmaMng.h"

constexpr int MAX_NUMBER_OF_RDMA_CONN = NUMBER_OF_SOCKETS;
int STOP = false;

using namespace std;

void handle_signal(int signal);
int fun(void *ctx, void *data, size_t len);

sk::SocketMng s;

bpf::EventHandler handler = {
    .ctx = nullptr,
    .handle_event = fun};
bpf::BpfMng b(handler);

rdmaMng::RdmaMng r(RDMA_PORT, s.client_sk_fd.data(), b);

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
        int proxy_fd = s.get_proxy_fd_from_sockid(user_data->association.proxy);

        if (proxy_fd < 0)
        {
            printf("Failed to get proxy fd from sockid\n");
            return -1;
        }

        cout << "Proxy fd: " << proxy_fd << endl;
        cout << "App socket: " << user_data->association.app.sip << ":" << user_data->association.app.sport << endl;

        r.rdma_manager_connect(user_data->association.app, proxy_fd);
    }

    return 0;
}

int main()
{
    try
    {
        signal(SIGINT, handle_signal);
        signal(SIGTSTP, handle_signal);

        vector<uint16_t> ports_to_set = {TARGET_PORT};
        b.set_target_ports(ports_to_set, PROXY_PORT);
        b.run();

        s.init(PROXY_PORT, inet_addr(SERVER_IP));

        b.push_sock_to_map(s.client_sk_fd);

        r.rdma_manager_run();

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
