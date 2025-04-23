

#include "scap.h"

// PRIVATE FUNCTIONS

int bpf_launch_poll_thread(bpf_context_t *ctx);
void *bpf_ringbuf_poll(void *ctx);

void wrap_close(int fd)
{
    if (fd >= 0)
        close(fd);
}

int scap_ret_err(bpf_context_t *bpf_ctx, char *msg)
{
    perror(msg);
    if (bpf_ctx)
    {
        printf("Cleaning up BPF resources...\n");
        cleanup_bpf(bpf_ctx);
    }
    return -1;
}

void *bpf_ringbuf_poll(void *ctx)
{
    bpf_context_t *bpf_ctx = (bpf_context_t *)ctx;
    int err = 0;

    // create a ring buffer to poll events
    bpf_ctx->rb = ring_buffer__new(
        bpf_ctx->ring_buffer_fd,
        bpf_ctx->new_sk_event_handler.handle_event,
        bpf_ctx->new_sk_event_handler.ctx,
        NULL);

    if (!bpf_ctx->rb)
    {
        perror("Failed to create ring buffer - bpf_ringbuf_poll");
        return NULL;
    }

    // poll the ring buffer for events
    while (bpf_ctx->stop_threads == FALSE)
    {
        err = ring_buffer__poll(bpf_ctx->rb, POOL_RB_INTERVAL);
        if (err < 0)
        {
            perror("Failed to poll ring buffer - bpf_ringbuf_poll");
            break;
        }
    }

    return NULL;
}

int bpf_launch_poll_thread(bpf_context_t *ctx)
{
    int err = 0;
    ctx->stop_threads = FALSE;

    // create a thread to poll the ring buffer
    err = pthread_create(&ctx->thread_pool_rb, NULL, (void *)bpf_ringbuf_poll, ctx);
    if (err != 0)
        return scap_ret_err(ctx, "Failed to create thread for ring buffer");

    return 0;
}

int setup_bpf(bpf_context_t *ctx, EventHandler event_handler)
{
    if (!ctx)
        return -1;

    // set the event handler
    ctx->new_sk_event_handler.ctx = event_handler.ctx;
    ctx->new_sk_event_handler.handle_event = event_handler.handle_event;

    // open the BPF object file
    ctx->obj = bpf_object__open_file(PATH_TO_BPF_OBJ_FILE, NULL);

    if (!ctx->obj)
        return scap_ret_err(ctx, "Failed to open BPF object");

    // load the BPF object file into the kernel
    int err = bpf_object__load(ctx->obj);
    if (err != 0)
        return scap_ret_err(ctx, "Failed to load BPF object");

    struct bpf_map *intercepted_sockets, *socket_association, *target_ports, *server_port, *free_sk, *rb_map;

    // find the maps in the object file
    intercepted_sockets = bpf_object__find_map_by_name(ctx->obj, "intercepted_sockets");
    if (!intercepted_sockets)
        return scap_ret_err(ctx, "Failed to find the intercepted_sockets map");

    free_sk = bpf_object__find_map_by_name(ctx->obj, "free_sockets");
    if (!free_sk)
        return scap_ret_err(ctx, "Failed to find the free_sk map");

    socket_association = bpf_object__find_map_by_name(ctx->obj, "socket_association");
    if (!socket_association)
        return scap_ret_err(ctx, "Failed to find the socket_association map");

    target_ports = bpf_object__find_map_by_name(ctx->obj, "target_ports");
    if (!target_ports)
        return scap_ret_err(ctx, "Failed to find the target_ports map");

    server_port = bpf_object__find_map_by_name(ctx->obj, "server_port");
    if (!server_port)
        return scap_ret_err(ctx, "Failed to find the server_port map");

    rb_map = bpf_object__find_map_by_name(ctx->obj, "new_sk");
    if (!rb_map)
        return scap_ret_err(ctx, "Failed to find the new_sk map");

    // get the file descriptor for the map
    ctx->intercepted_sk_fd = bpf_map__fd(intercepted_sockets);
    if (ctx->intercepted_sk_fd < 0)
        return scap_ret_err(ctx, "Failed to get intercepted_sockets fd");

    ctx->free_sk_fd = bpf_map__fd(free_sk);
    if (ctx->free_sk_fd < 0)
        return scap_ret_err(ctx, "Failed to get free_sockets fd");

    ctx->socket_association_fd = bpf_map__fd(socket_association);
    if (ctx->socket_association_fd < 0)
        return scap_ret_err(ctx, "Failed to get socket_association fd");

    ctx->target_ports_fd = bpf_map__fd(target_ports);
    if (ctx->target_ports_fd < 0)
        return scap_ret_err(ctx, "Failed to get target_ports fd");

    ctx->server_port_fd = bpf_map__fd(server_port);
    if (ctx->server_port_fd < 0)
        return scap_ret_err(ctx, "Failed to get server_port fd");

    ctx->ring_buffer_fd = bpf_map__fd(rb_map);
    if (ctx->ring_buffer_fd < 0)
        return scap_ret_err(ctx, "Failed to get ring buffer fd");

    // find the programs in the object file
    struct bpf_program *prog_sockops, *prog_sk_msg;

    prog_sockops = bpf_object__find_program_by_name(ctx->obj, "sockops_prog");
    ctx->prog_fd_sockops = bpf_program__fd(prog_sockops);
    if (ctx->prog_fd_sockops < 0)
        return scap_ret_err(ctx, "Failed to getr prog_sock_ops fd");

    prog_sk_msg = bpf_object__find_program_by_name(ctx->obj, "sk_msg_prog");
    ctx->prog_fd_sk_msg = bpf_program__fd(prog_sk_msg);
    if (ctx->prog_fd_sk_msg < 0)
        return scap_ret_err(ctx, "Failed to load prog_fd_sk_msg");

    ctx->cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    if (ctx->cgroup_fd < 0)
        return scap_ret_err(ctx, "Failed to open cgroup");

    ctx->prog_tcp_destroy_sock = bpf_object__find_program_by_name(ctx->obj, "tcp_destroy_sock_prog");
    if (!ctx->prog_tcp_destroy_sock)
        return scap_ret_err(ctx, "Failed to find tcp_destroy_sock_prog");

    return 0;
}

int cleanup_bpf(bpf_context_t *ctx)
{
    int err = 0;

    // Detach sk_msg_prog from sockmap
    if (ctx->intercepted_sk_fd > 0)
    {
        err = bpf_prog_detach2(ctx->prog_fd_sk_msg, ctx->intercepted_sk_fd, BPF_SK_MSG_VERDICT);
        if (err != 0)
            perror("Failed to detach sk_msg_prog from sockmap");
    }

    // Detach sockops_prog from cgroup
    if (ctx->cgroup_fd > 0)
    {
        err = bpf_prog_detach2(ctx->prog_fd_sockops, ctx->cgroup_fd, BPF_CGROUP_SOCK_OPS);
        if (err != 0)
            perror("Failed to detach sockops_prog from cgroup");
    }

    // Detach tcp_destroy_sock_prog from tracepoint
    if (ctx->tcp_destroy_link != NULL)
    {
        err = bpf_link__destroy(ctx->tcp_destroy_link);
        if (err != 0)
            perror("Failed to detach tcp_destroy_sock_prog from tracepoint");
    }

    // Close all file descriptors
    wrap_close(ctx->intercepted_sk_fd);
    wrap_close(ctx->free_sk_fd);
    wrap_close(ctx->socket_association_fd);
    wrap_close(ctx->target_ports_fd);
    wrap_close(ctx->cgroup_fd);
    wrap_close(ctx->prog_fd_sockops);
    wrap_close(ctx->prog_fd_sk_msg);
    wrap_close(ctx->ring_buffer_fd);
    ring_buffer__free(ctx->rb);

    // Destroy BPF object
    bpf_object__close(ctx->obj);

    return 0;
}

int run_bpf(bpf_context_t *ctx)
{
    int err = 0;

    // attach sockops_prog to the cgroup
    err = bpf_prog_attach(ctx->prog_fd_sockops, ctx->cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
    if (err != 0)
        return scap_ret_err(ctx, "Failed to attach sockops_prog to cgroup");

    // Attach sk_msg_prog to the sockmap
    err = bpf_prog_attach(ctx->prog_fd_sk_msg, ctx->intercepted_sk_fd, BPF_SK_MSG_VERDICT, 0);
    if (err != 0)
        return scap_ret_err(ctx, "Failed to attach sk_msg_prog to sockmap");

    // Attach tcp_destroy_sock_prog to the tracepoint
    ctx->tcp_destroy_link = bpf_program__attach_tracepoint(ctx->prog_tcp_destroy_sock, "tcp", "tcp_destroy_sock");
    if (!ctx->tcp_destroy_link)
        return scap_ret_err(ctx, "Failed to attach tcp_destroy_sock_prog to tracepoint");

    // create a thread to poll the ring buffer
    err = bpf_launch_poll_thread(ctx);
    if (err != 0)
        return scap_ret_err(ctx, "Failed to create thread for ring buffer");

    return 0;
}

int set_target_ports(bpf_context_t *ctx, __u16 target_ports[], int n, __u16 server_port)
{
    int val = 1;
    int err = 0;

    // set the target ports
    for (int i = 0; i < n; i++)
    {
        err = bpf_map_update_elem(ctx->target_ports_fd, &target_ports[i], &val, BPF_ANY);
        if (err != 0)
            return scap_ret_err(ctx, "Failed to update target_ports map");
    }

    // set the server port
    int k = 0;
    err = bpf_map_update_elem(ctx->server_port_fd, &k, &server_port, BPF_ANY);
    if (err != 0)
        return scap_ret_err(ctx, "Failed to update server_port map");

    return 0;
}

int push_sock_to_map(bpf_context_t *ctx, client_sk_t client_sks[], int n)
{
    int err = 0;
    for (int i = 0; i < n; i++)
    {
        // push the socket to the free_sockets map
        err = bpf_map_update_elem(ctx->free_sk_fd, NULL, &client_sks[i].sk_id, BPF_ANY);
        if (err != 0)
            return scap_ret_err(ctx, "Failed to update free_sockets map");

        // add the socket to the intercepted_sockets map
        int err = bpf_map_update_elem(ctx->intercepted_sk_fd, &client_sks[i].sk_id, &client_sks[i].fd, BPF_ANY);
        if (err != 0)
            return scap_ret_err(ctx, "Failed to add socket to intercepted_sockets map");
    }
    return 0;
}

struct sock_id get_proxy_sk_from_app_sk(bpf_context_t *ctx, struct sock_id app_sk)
{
    struct association_t app;
    struct association_t proxy = {0};

    app.app = app_sk;

    int err = bpf_map_lookup_elem(ctx->socket_association_fd, &app, &proxy);

    return proxy.proxy;
}
