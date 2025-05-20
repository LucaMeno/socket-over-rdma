// scap.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "config.h"

#define AF_INET 2
#define AF_INET6 10

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct sock_id);
	__type(value, int);
} sock_proxyfd_association SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2048);
} new_sk SEC(".maps");

/**
 * list of all the socket from witch i want to intercept the data
 * the ones of user space are inserted from the proxy app
 */
struct
{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, struct sock_id);
	__type(value, int); // the value is the socket fd
} intercepted_sockets SEC(".maps");

/**
 * queue of all the socket that are free to be used to reach the user space
 * filled by the proxy app
 */
struct
{
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct sock_id); // the value is the socket fd
} free_sockets SEC(".maps");

/**
 * association between:
 * - one of the socket created by the proxy
 * - one socket created by the app
 *
 * for eache association there are 2 entries in the map:
 * - key = proxy socket -> value = app socket
 * - key = app socket -> value = proxy socket
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct association_t);
	__type(value, struct association_t);
} socket_association SEC(".maps");

/**
 * list of all the target ports
 * the key is the port number
 * used to check if the socket is one of the one that i want to intercept
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16);
	__type(value, int);
} target_ports SEC(".maps");

/**
 * list of all the target IPs
 * the key is the IP address
 * used to check if the socket is one of the one that i want to intercept
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, int);
} target_ip SEC(".maps");

/**
 * port used by the server to send the data
 * key = 0
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u16);
} server_port SEC(".maps");

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
	// get the socket operation type
	int op = (int)skops->op;

	struct sock_id sk_id = {0};
	struct sock_id sk_id_reverse = {0};

	struct bpf_sock *sk = skops->sk;
	long ret;

	/*if (skops->family != AF_INET)
	{
		bpf_printk("Not IPv4 family");
		return 0;
	}*/

	if (sk == NULL)
	{
#ifdef EBPF_DEBUG_SOCKET
		bpf_printk("Socket is NULL, op: %d", op);
#endif // EBPF_DEBUG_SOCKET
		return 0;
	}

	switch (op)
	{
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:

		// get the socket id
		sk_id.sip = sk->src_ip4;
		sk_id.dip = sk->dst_ip4;
		sk_id.sport = sk->src_port;
		sk_id.dport = bpf_ntohs(sk->dst_port);

#ifdef INTERCEPT_EVERYTHING
		goto is_target;
#endif // INTERCEPT_EVERYTHING

		// check if SRC or DST port is the one of the target ports
		int key = sk_id.dport;
		int *is_port_target_1 = bpf_map_lookup_elem(&target_ports, &key);
		if (is_port_target_1 != NULL)
			goto is_target;

		key = sk_id.sport;
		int *is_port_target_2 = bpf_map_lookup_elem(&target_ports, &key);
		if (is_port_target_2 != NULL)
			goto is_target;

		// check if SRC or DST IP is the one of the target IPs
		/*key = sk_id.dip;
		int *is_ip_target_1 = bpf_map_lookup_elem(&target_ip, &key);
		if (is_ip_target_1 != NULL)
			goto is_target;

		key = sk_id.sip;
		int *is_ip_target_2 = bpf_map_lookup_elem(&target_ip, &key);
		if (is_ip_target_2 != NULL)
			goto is_target;*/

#ifdef EBPF_DEBUG_SOCKET
		bpf_printk("SKIP [SRC: %u:%u, DST: %u:%u] - not target port", sk_id.sip, sk_id.sport, sk_id.dip, sk_id.dport);
#endif // EBPF_DEBUG_SOCKET
		return 0;

	is_target:

#ifdef EBPF_DEBUG_SOCKET
		bpf_printk("----------sockops-----------");
#endif // EBPF_DEBUG_SOCKET

		/* NOP */; //  just to avoid the warning

		// get one free socket from the free_sockets queue
		struct sock_id free_sk = {0};
		ret = bpf_map_pop_elem(&free_sockets, &free_sk); // pop
		if (ret != 0)
		{
			bpf_printk("Error on pop free socket - operation aborted");
			return 0;
		}

		// Add the socket to the map so is possible to intercept the msg
		ret = bpf_sock_hash_update(skops, &intercepted_sockets, &sk_id, BPF_NOEXIST);
		if (ret != 0)
		{
			bpf_printk("Error on update intercepted sockets: %ld", ret);
			return 0;
		}

		// add the socket association to the map
		// push 2 entries to have a fast lookup
		struct association_t sk_association_proxy = {0};
		sk_association_proxy.proxy = free_sk;

		struct association_t sk_association_app = {0};
		sk_association_app.app = sk_id;

		// key = proxy socket -> value = app socket
		ret = bpf_map_update_elem(&socket_association, &sk_association_proxy, &sk_association_app, BPF_NOEXIST);
		if (ret != 0)
		{
			bpf_printk("Error on update socket association 1");
			return 0;
		}

		// key = app socket -> value = proxy socket
		ret = bpf_map_update_elem(&socket_association, &sk_association_app, &sk_association_proxy, BPF_NOEXIST);
		if (ret != 0)
		{
			bpf_printk("Error on update socket association 2");
			return 0;
		}

		// Notify the user space about the new socket
		struct userspace_data_t *userdata_ptr = bpf_ringbuf_reserve(&new_sk, sizeof(struct userspace_data_t), 0);

		if (!userdata_ptr)
		{
			bpf_printk("Error on reserve ring buffer");
			return 0;
		}

		// copy the socket id to the ring buffer
		userdata_ptr->association.app = sk_association_app.app;
		userdata_ptr->association.proxy = sk_association_proxy.proxy;
		userdata_ptr->sockops_op = op;

		// submit the ring buffer
		bpf_ringbuf_submit(userdata_ptr, 0);

#ifdef EBPF_DEBUG_SOCKET
		bpf_printk("ADD: APP [SRC: %u:%u, DST: %u:%u] <-> PROXY [SRC: %u:%u, DST: %u:%u]",
				   sk_association_app.app.sip, sk_association_app.app.sport, sk_association_app.app.dip, sk_association_app.app.dport,
				   sk_association_proxy.proxy.sip, sk_association_proxy.proxy.sport, sk_association_proxy.proxy.dip, sk_association_proxy.proxy.dport);
#endif // EBPF_DEBUG_SOCKET

		break;
#ifdef EBPF_DEBUG_SOCKET
	case BPF_SOCK_OPS_STATE_CB:
		// just in case....
		bpf_printk("===========================================BPF_SOCK_OPS_STATE_CB===========================================");

		break;
	default:
		bpf_printk("Unknown socket operation: %d\n", op);
		break;
#endif // EBPF_DEBUG_SOCKET
	}

	return 0;
}

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
#ifdef EBPF_DEBUG_MSG
	bpf_printk("----------sk_msg-----------");
#endif // EBPF_DEBUG_MSG

	// Only process IPv4 packets
	if (msg->family != AF_INET)
		return SK_PASS;

	int k = 0; // Key for retrieving the server port
	int ret = 0;

	// Retrieve the server port for matching with the destination port
	__u16 *server_port_ptr = bpf_map_lookup_elem(&server_port, &k);
	if (!server_port_ptr)
	{
		bpf_printk("Error on lookup server port");
		return SK_PASS;
	}

	// Prepare the key for the sockmap
	struct sock_id sk_id = {
		msg->sk->src_ip4,			 // source IP
		msg->sk->dst_ip4,			 // destination IP
		msg->sk->src_port,			 // source port
		bpf_ntohs(msg->sk->dst_port) // destination port
	};

	// Initialize association structure for lookup
	struct association_t sk_association_key = {0};
	struct association_t *sk_association_val = NULL;

	if (sk_id.dport == *server_port_ptr)
	{
		// the message is coming from the proxy
		sk_association_key.proxy = sk_id;
	}
	else
	{
		// the message is coming from the app
		sk_association_key.app = sk_id;
	}

#ifdef EBPF_DEBUG_MSG
	bpf_printk("SRC -- [SRC: %u:%u, DST: %u:%u]", sk_id.sip, sk_id.sport, sk_id.dip, sk_id.dport);
#endif // EBPF_DEBUG_MSG

	// Lookup socket association
	sk_association_val = bpf_map_lookup_elem(&socket_association, &sk_association_key);
	if (!sk_association_val)
	{
		bpf_printk("Error on lookup socket association");
		return SK_PASS;
	}

	// Determine the destination socket ID based on the direction
	struct sock_id dest_sk_id = (sk_id.dport == *server_port_ptr) ? sk_association_val->app : sk_association_val->proxy;

#ifdef EBPF_DEBUG_MSG
	bpf_printk("DST -- [SRC: %u:%u, DST: %u:%u]", dest_sk_id.sip, dest_sk_id.sport, dest_sk_id.dip, dest_sk_id.dport);
#endif // EBPF_DEBUG_MSG

	// Redirect the message to the associated socket
	ret = bpf_msg_redirect_hash(msg, &intercepted_sockets, &dest_sk_id, BPF_F_INGRESS);
	if (ret != SK_PASS)
	{
		bpf_printk("Error on redirect msg %ld", ret);
		return SK_PASS;
	}

#ifdef EBPF_DEBUG_MSG
	bpf_printk("Redirect msg to %s", (sk_id.dport == *server_port_ptr) ? "app" : "proxy");
#endif // EBPF_DEBUG_MSG

	return SK_PASS;
}

SEC("tracepoint/tcp/tcp_destroy_sock")
int tcp_destroy_sock_prog(struct trace_event_raw_tcp_event_sk *ctx)
{
	// check if it is one of the target socket
	struct sock_id sk_id_app = {
		.sport = ctx->sport,
		.dport = ctx->dport,
		.sip = bpf_ntohl((__u32)ctx->saddr[0] << 24 | (__u32)ctx->saddr[1] << 16 | (__u32)ctx->saddr[2] << 8 | (__u32)ctx->saddr[3]),
		.dip = bpf_ntohl((__u32)ctx->daddr[0] << 24 | (__u32)ctx->daddr[1] << 16 | (__u32)ctx->daddr[2] << 8 | (__u32)ctx->daddr[3])};

	int err = 0;

	// lookup the socket in the socket_association map
	struct association_t sk_association_app = {0};
	sk_association_app.app = sk_id_app;

	struct association_t *sk_association_proxy = bpf_map_lookup_elem(&socket_association, &sk_association_app);
	if (!sk_association_proxy)
	{
		// not found in the map: socket not intercepted
		return 0;
	}

#ifdef EBPF_DEBUG_SOCKET
	bpf_printk("----------sk_close-----------");
	bpf_printk("REM: APP [SRC: %u:%u, DST: %u:%u] <-> PROXY [SRC: %u:%u, DST: %u:%u]",
			   sk_association_app.app.sip, sk_association_app.app.sport, sk_association_app.app.dip, sk_association_app.app.dport,
			   sk_association_proxy->proxy.sip, sk_association_proxy->proxy.sport, sk_association_proxy->proxy.dip, sk_association_proxy->proxy.dport);
#endif // EBPF_DEBUG_SOCKET

	struct sock_id sk_id_proxy = sk_association_proxy->proxy;

	// remove the socket from the socket_association map
	err = bpf_map_delete_elem(&socket_association, &sk_association_app);
	if (err != 0)
	{
		bpf_printk("Error on delete socket association - app");
		return 0;
	}

	// remove also the reverse association
	err = bpf_map_delete_elem(&socket_association, sk_association_proxy);
	if (err != 0)
	{
		bpf_printk("Error on delete socket association - proxy");
		return 0;
	}

	// push the proxy socket to the free_sockets map to be reused
	err = bpf_map_push_elem(&free_sockets, &sk_id_proxy, BPF_ANY);
	if (err != 0)
	{
		bpf_printk("Error on push free socket");
		return 0;
	}

	// the socket is not removed from the intercepted_sockets map
	// because it will be automatically removed when the socket is closed

#ifdef EBPF_DEBUG_SOCKET
	bpf_printk("Free sk: [SRC: %u:%u, DST: %u:%u]",
			   sk_id_proxy.sip, sk_id_proxy.sport, sk_id_proxy.dip, sk_id_proxy.dport);
#endif // EBPF_DEBUG_SOCKET

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
