#include <signal.h>
#include <vector>

#include <SocketMng.h>
#include <BpfMng.h>

constexpr int MAX_NUMBER_OF_RDMA_CONN = NUMBER_OF_SOCKETS;
int STOP = false;

using namespace std;

void handle_signal(int signal);

sk::SocketMng s;
bpf::BpfMng b;

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

        // ret = rdma_manager_connect(&rdma_ctxm, user_data->association.app, proxy_fd);
    }

    return 0;
}

int main()
{
    try
    {
        signal(SIGINT, handle_signal);
        signal(SIGTSTP, handle_signal);

        bpf::EventHandler handler = {
            .ctx = NULL,
            .handle_event = fun};
        b.init(handler);

        vector<uint16_t> ports_to_set = {TARGET_PORT};
        b.set_target_ports(ports_to_set, PROXY_PORT);
        b.run();

        s.init(PROXY_PORT, inet_addr(SERVER_IP));

        b.push_sock_to_map(s.client_sk_fd);

        printf("Waiting for messages, press Ctrl+C to exit...\n");
        while (!STOP)
            pause(); // wait for signal

        printf("Exiting gracefully...\n");
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    /*int err;
    EventHandler handler = {
        .ctx = NULL,
        .handle_event = fun};

    err = bpf_init(&bpf_ctx, handler);

    check_error(err, "");
    printf("eBPF program setup complete\n");

    // TODO: scale this
    __u16 ports_to_set[1] = {TARGET_PORT};
    int nport = sizeof(ports_to_set) / sizeof(ports_to_set[0]);

    // const char *ip_env = getenv("REMOTE_IP");
    const char *ip1 = "192.168.17.86";
    const char *ip2 = "192.168.17.84";
    __u32 ips_to_set[2];

    ips_to_set[0] = inet_addr(ip1);
    ips_to_set[1] = inet_addr(ip2);

    int nip = sizeof(ips_to_set) / sizeof(ips_to_set[0]);

    err = bpf_set_target_ports(&bpf_ctx, ports_to_set, nport, PROXY_PORT);
    check_error(err, "");
    printf("Target ports set\n");

    err = bpf_set_target_ip(&bpf_ctx, ips_to_set, nip);
    check_error(err, "");
    printf("Target IPs set\n");

    err = bpf_run(&bpf_ctx);
    check_error(err, "");
    printf("eBPF program attached to socket\n");

    err = sk_init(&sk_ctx, PROXY_PORT, inet_addr(SERVER_IP));
    check_error(err, "");
    printf("Sockets setup complete\n");

    err = bpf_push_sock_to_map(&bpf_ctx, sk_ctx.client_sk_fd, NUMBER_OF_SOCKETS);
    check_error(err, "");
    printf("Map updated\n");

    // RDMA
    err = rdma_manager_run(&rdma_ctxm, RDMA_PORT, &bpf_ctx, sk_ctx.client_sk_fd);

    printf("Waiting for messages, press Ctrl+C to exit...\n");
    while (!STOP)
    {
        pause(); // wait for signal
    }

    err = sk_destroy(&sk_ctx);
    check_error(err, "");
    printf("Socket closed\n");

    err = bpf_destroy(&bpf_ctx);
    check_error(err, "");
    printf("Successfully detached eBPF program\n");

    err = rdma_manager_destroy(&rdma_ctxm);
    check_error(err, "");
    printf("RDMA manager destroyed\n");*/

    return 0;
}

void handle_signal(int signal)
{
    STOP = true;
}
