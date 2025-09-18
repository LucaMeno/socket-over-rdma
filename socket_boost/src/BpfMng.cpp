
#include <BpfMng.h>

using namespace std;

namespace bpf
{
    BpfMng::BpfMng()
    {
        // open the BPF object file
        obj = bpf_object__open_file(Config::BPF_PATH_TO_BPF_OBJ_FILE, NULL);

        if (!obj)
            throw runtime_error("Failed to open BPF object");

        // load the BPF object file into the kernel
        int err = bpf_object__load(obj);
        if (err != 0)
            throw runtime_error("Failed to load BPF object");

        struct bpf_map *intercepted_sockets,
            *socket_association,
            *target_ports,
            *server_port,
            *free_sk,
            *rb_map,
            *target_ip;

        // find the maps in the object file
        intercepted_sockets = bpf_object__find_map_by_name(obj, "intercepted_sockets");
        if (!intercepted_sockets)
            throw runtime_error("Failed to find the intercepted_sockets map");

        free_sk = bpf_object__find_map_by_name(obj, "free_sockets");
        if (!free_sk)
            throw runtime_error("Failed to find the free_sk map");

        socket_association = bpf_object__find_map_by_name(obj, "socket_association");
        if (!socket_association)
            throw runtime_error("Failed to find the socket_association map");

        target_ports = bpf_object__find_map_by_name(obj, "target_ports");
        if (!target_ports)
            throw runtime_error("Failed to find the target_ports map");

        server_port = bpf_object__find_map_by_name(obj, "server_port");
        if (!server_port)
            throw runtime_error("Failed to find the server_port map");

        rb_map = bpf_object__find_map_by_name(obj, "new_sk");
        if (!rb_map)
            throw runtime_error("Failed to find the new_sk map");

        target_ip = bpf_object__find_map_by_name(obj, "target_ip");
        if (!target_ip)
            throw runtime_error("Failed to find the target_ip map");

        // get the file descriptor for the map
        intercepted_sk_fd = bpf_map__fd(intercepted_sockets);
        if (intercepted_sk_fd < 0)
            throw runtime_error("Failed to get intercepted_sockets fd");

        free_sk_fd = bpf_map__fd(free_sk);
        if (free_sk_fd < 0)
            throw runtime_error("Failed to get free_sockets fd");

        socket_association_fd = bpf_map__fd(socket_association);
        if (socket_association_fd < 0)
            throw runtime_error("Failed to get socket_association fd");

        target_ports_fd = bpf_map__fd(target_ports);
        if (target_ports_fd < 0)
            throw runtime_error("Failed to get target_ports fd");

        server_port_fd = bpf_map__fd(server_port);
        if (server_port_fd < 0)
            throw runtime_error("Failed to get server_port fd");

        ring_buffer_fd = bpf_map__fd(rb_map);
        if (ring_buffer_fd < 0)
            throw runtime_error("Failed to get ring buffer fd");

        target_ip_fd = bpf_map__fd(target_ip);
        if (target_ip_fd < 0)
            throw runtime_error("Failed to get target_ip fd");

        // find the programs in the object file
        struct bpf_program *prog_sockops, *prog_sk_msg;

        prog_sockops = bpf_object__find_program_by_name(obj, "sockops_prog");
        prog_fd_sockops = bpf_program__fd(prog_sockops);
        if (prog_fd_sockops < 0)
            throw runtime_error("Failed to getr prog_sock_ops fd");

        prog_sk_msg = bpf_object__find_program_by_name(obj, "sk_msg_prog");
        prog_fd_sk_msg = bpf_program__fd(prog_sk_msg);
        if (prog_fd_sk_msg < 0)
            throw runtime_error("Failed to load prog_fd_sk_msg");

        cgroup_fd = open(Config::BPF_CGROUP_PATH, O_RDONLY);
        if (cgroup_fd < 0)
            throw runtime_error("Failed to open cgroup");

        prog_tcp_destroy_sock = bpf_object__find_program_by_name(obj, "tcp_destroy_sock_prog");
        if (!prog_tcp_destroy_sock)
            throw runtime_error("Failed to find tcp_destroy_sock_prog");
    }

    void BpfMng::init(EventHandler event_handler, const std::vector<uint16_t> &target_ports_to_set, uint16_t proxy_port, const std::vector<sk::client_sk_t> &client_sks)
    {
        // set the event handler
        new_sk_event_handler.ctx = event_handler.ctx;
        new_sk_event_handler.handle_event = event_handler.handle_event;

        int err = 0;

        // attach sockops_prog to the cgroup
        err = bpf_prog_attach(prog_fd_sockops, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
        if (err != 0)
            throw runtime_error("Failed to attach sockops_prog to cgroup");

        // Attach sk_msg_prog to the sockmap
        err = bpf_prog_attach(prog_fd_sk_msg, intercepted_sk_fd, BPF_SK_MSG_VERDICT, 0);
        if (err != 0)
            throw runtime_error("Failed to attach sk_msg_prog to sockmap");

        // Attach tcp_destroy_sock_prog to the tracepoint
        tcp_destroy_link = bpf_program__attach_tracepoint(prog_tcp_destroy_sock, "tcp", "tcp_destroy_sock");
        if (!tcp_destroy_link)
            throw runtime_error("Failed to attach tcp_destroy_sock_prog to tracepoint");

        // create a thread to poll the ring buffer
        stop_threads = false;
        rb_thread = thread(&BpfMng::threadPollRb, this);
        pthread_setname_np(rb_thread.native_handle(), "RbPollThrd");
        rb_thread.detach();
        logger.log(LogLevel::SOCKOPS, "Started polling thread for new socket events.");

        pushSockToMap(client_sks);
        setTargetPort(target_ports_to_set, proxy_port);

        logger.log(LogLevel::EBPF, "BPF programs attached successfully.");
    }

    void BpfMng::threadPollRb()
    {
        // create a ring buffer to poll events
        rb = ring_buffer__new(
            ring_buffer_fd,
            new_sk_event_handler.handle_event,
            new_sk_event_handler.ctx,
            NULL);

        if (!rb)
            throw runtime_error("Failed to create ring buffer");

        // poll the ring buffer for events
        while (stop_threads == false)
        {
            int err = ring_buffer__poll(rb, Config::BPF_POOL_RB_INTERVAL);

            if (err < 0)
            {
                if (stop_threads == true)
                {
                    // if we are stopping, just exit the loop
                    break;
                }
                logger.log(LogLevel::ERROR, "Failed to poll ring buffer - bpf_ringbuf_poll");
                break;
            }
        }
    }

    BpfMng::~BpfMng()
    {
        logger.log(LogLevel::INFO, "Cleaning up BPF resources...");

        stop_threads = true;
        int err = 0;

        // Detach sk_msg_prog from sockmap
        if (intercepted_sk_fd > 0)
        {
            err = bpf_prog_detach2(prog_fd_sk_msg, intercepted_sk_fd, BPF_SK_MSG_VERDICT);
            if (err != 0)
                logger.log(LogLevel::ERROR, "Failed to detach sk_msg_prog from sockmap");
        }

        // Detach sockops_prog from cgroup
        if (cgroup_fd > 0)
        {
            err = bpf_prog_detach2(prog_fd_sockops, cgroup_fd, BPF_CGROUP_SOCK_OPS);
            if (err != 0)
                logger.log(LogLevel::ERROR, "Failed to detach sockops_prog from cgroup");
        }

        // Detach tcp_destroy_sock_prog from tracepoint
        if (tcp_destroy_link != NULL)
        {
            err = bpf_link__destroy(tcp_destroy_link);
            if (err != 0)
                logger.log(LogLevel::ERROR, "Failed to detach tcp_destroy_sock_prog from tracepoint");
        }

        // Close all file descriptors
        wrapClose(intercepted_sk_fd);
        wrapClose(free_sk_fd);
        wrapClose(socket_association_fd);
        wrapClose(target_ports_fd);
        wrapClose(cgroup_fd);
        wrapClose(prog_fd_sockops);
        wrapClose(prog_fd_sk_msg);
        wrapClose(ring_buffer_fd);
        ring_buffer__free(rb);

        // Destroy BPF object
        bpf_object__close(obj);

        if (rb_thread.joinable())
            rb_thread.join();
        logger.log(LogLevel::CLEANUP, "Polling thread stopped.");

        logger.log(LogLevel::SHUTDOWN, "eBPF resources cleaned up successfully.");
    }

    void BpfMng::setTargetPort(const vector<uint16_t> &target_ports, uint16_t server_port)
    {
        int val = 1;
        int err = 0;

        for (auto &port : target_ports)
        {
            err = bpf_map_update_elem(target_ports_fd, &port, &val, BPF_ANY);
            if (err != 0)
                throw runtime_error("Failed to update target_ports map");
        }

        // set the server port
        int k = 0;
        err = bpf_map_update_elem(server_port_fd, &k, &server_port, BPF_ANY);
        if (err != 0)
            throw runtime_error("Failed to update server_port map");
    }

    void BpfMng::setTargetIp(const std::vector<uint32_t> &target_ip)
    {
        int val = 1;
        int err = 0;

        for (auto &ip : target_ip)
        {
            err = bpf_map_update_elem(target_ip_fd, &ip, &val, BPF_ANY);
            if (err != 0)
                throw runtime_error("Failed to update target_ip map");
        }
    }

    void BpfMng::pushSockToMap(const std::vector<sk::client_sk_t> &client_sks)
    {
        int err = 0;
        for (auto &client_sk : client_sks)
        {
            // push the socket to the free_sockets map
            err = bpf_map_update_elem(free_sk_fd, NULL, &client_sk.sk_id, BPF_ANY);
            if (err != 0)
                throw runtime_error("Failed to update free_sockets map");

            // add the socket to the intercepted_sockets map
            err = bpf_map_update_elem(intercepted_sk_fd, &client_sk.sk_id, &client_sk.fd, BPF_ANY);
            if (err != 0)
            {
                logger.log(LogLevel::ERROR, "Error on update intercepted_sockets map: " + std::string(strerror(errno)));
                throw runtime_error("Failed to add socket to intercepted_sockets map");
            }
        }
    }

    struct sock_id BpfMng::getProxySkFromAppSk(struct sock_id app_sk)
    {
        struct association_t app = {0};
        struct association_t proxy = {0};

        app.app = app_sk;

        int err = bpf_map_lookup_elem(socket_association_fd, &app, &proxy);

        return proxy.proxy;
    }

    struct sock_id BpfMng::getAppSkFromProxyFd(const std::vector<sk::client_sk_t> &client_sks, int target_fd)
    {
        struct sock_id app_sk = {0};

        // get the socket info
        int j = 0;
        for (; j < Config::NUMBER_OF_SOCKETS; j++)
            if (client_sks[j].fd == target_fd)
                break;

        if (j == Config::NUMBER_OF_SOCKETS)
        {
            logger.log(LogLevel::ERROR, "Failed to find socket in client_sks");
            return app_sk;
        }

        struct sock_id proxy_sk = client_sks[j].sk_id;

        struct association_t sk_assoc_k = {0};
        struct association_t sk_assoc_v = {0};

        sk_assoc_k.proxy = proxy_sk;

        int ret = bpf_map_lookup_elem(socket_association_fd, &sk_assoc_k, &sk_assoc_v);
        if (ret != 0)
            throw runtime_error("Failed to lookup socket association map - getAppSkFromProxyFd");

        return sk_assoc_v.app;
    }

    struct sock_id BpfMng::getAppSkFromProxySk(struct sock_id proxy_sk)
    {
        struct association_t app = {0};
        struct association_t proxy = {0};

        proxy.proxy = proxy_sk;

        int err = bpf_map_lookup_elem(socket_association_fd, &proxy, &app);

        if (err != 0 && errno != ENOENT)
            throw runtime_error("Failed to lookup socket association map - getAppSkFromProxySk");

        return app.app;
    }

    void BpfMng::wrapClose(int fd)
    {
        if (fd >= 0)
            close(fd);
    }

}