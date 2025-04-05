// scap.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include "common.h"

#define AF_INET 2
#define AF_INET6 10

/**
 * list of all the socket from witch i want to intercept the data
 */
struct
{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, struct sock_id);
	__type(value, int); // the value is the socket fd
} intercepted_sockets SEC(".maps");

/**
 * list of all the socket that are free to be used to reach the user space
 */
struct
{
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 2048);
	__type(value, struct sock_id); // the value is the socket fd
} free_sockets SEC(".maps");

struct association_t
{
	struct sock_id proxy;
	struct sock_id app;
};

/**
 * association between:
 * - the socket fd of one of the free socket
 * - one of the socket in the intercepted_sockets map
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
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, int);
} target_ports SEC(".maps");

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

	struct bpf_sock *sk = skops->sk;
	long ret;

	if (skops->family != AF_INET || !sk)
		return 0;

	switch (op)
	{
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		// new established connection

		sk_id.ip = sk->src_ip4;
		sk_id.sport = sk->src_port;
		sk_id.dport = bpf_ntohs(sk->dst_port);

		// check if the destination port is the target one
		int key = sk_id.dport;
		int *is_port_target = bpf_map_lookup_elem(&target_ports, &key);

		if (is_port_target == NULL)
		{

			// bpf_printk("----------sockops-----------");
			// bpf_printk("SKIP key:: ip: %u, sport %u, dport %u ", sk_id.ip, sk_id.sport, sk_id.dport);
			return 0;
		}

		bpf_printk("----------sockops-----------");

		// Add the socket to the map
		ret = bpf_sock_hash_update(skops, &intercepted_sockets, &sk_id, BPF_NOEXIST);

		if (ret == 0)
		{
			bpf_printk("ADD key: %u, sport %u, dport %u", sk_id.ip, sk_id.sport, sk_id.dport);
		}
		else
		{
			bpf_printk("[skops=%p] bpf_sock_hash_update %ld", skops->sk, ret);
		}

		// get one free socket from the free_sockets map
		struct sock_id free_sk = {0};
		ret = bpf_map_pop_elem(&free_sockets, &free_sk); // pop a free socket from the queue
		if (ret != 0)
		{
			bpf_printk("Error on pop free socket");
			return 0;
		}

		// add the socket association to the map
		// push 2 entries to have a fast lookup
		struct association_t sk_association_key = {0};
		sk_association_key.proxy = free_sk;

		struct association_t sk_association_val = {0};
		sk_association_val.app = sk_id;

		ret = bpf_map_update_elem(&socket_association, &sk_association_key, &sk_association_val, BPF_NOEXIST);
		if (ret != 0)
		{
			bpf_printk("Error on update socket association 1");
			return 0;
		}

		ret = bpf_map_update_elem(&socket_association, &sk_association_val, &sk_association_key, BPF_NOEXIST);
		if (ret != 0)
		{
			bpf_printk("Error on update socket association 2");
			return 0;
		}

		bpf_printk("ASSOC app:: ip: %u, sport %u, dport %u // proxy:: ip: %u, sport %u, dport %u",
				   sk_association_val.app.ip, sk_association_val.app.sport, sk_association_val.app.dport,
				   sk_association_key.proxy.ip, sk_association_key.proxy.sport, sk_association_key.proxy.dport);

		break;

		// TODO: REMOVE THE SOCKET FROM THE MAP WHEN THE CONNECTION IS CLOSED

	default:
		break;
	}

	return 0;
}

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
	bpf_printk("----------sk_msg-----------");

	if (msg->family != AF_INET) // only IPv4
		return SK_PASS;

	int k = 0; // key for the sockmap
	int ret = SK_PASS;

	// retrieve the server port to understand if the msg is coming from the server
	__u16 *p = bpf_map_lookup_elem(&server_port, &k);
	if (p == NULL)
	{
		bpf_printk("Error on lookup server port");
		return SK_PASS;
	}

	// prepare the key for the sockmap
	struct association_t sk_association_key = {0};
	struct sock_id sk_id = {0};
	sk_id.ip = msg->sk->src_ip4;
	sk_id.sport = msg->sk->src_port;
	sk_id.dport = bpf_ntohs(msg->sk->dst_port);

	bpf_printk("Original:: ip: %u, sport %u, dport %u",
			   sk_id.ip, sk_id.sport, sk_id.dport);

	if (msg->local_port == *p) // 5555
	{
		// msg coming from the server
		bpf_printk("From proxy");
		sk_association_key.proxy = sk_id;

		// swap the sport and dport
		__u16 tmp = sk_association_key.proxy.sport;
		sk_association_key.proxy.sport = sk_association_key.proxy.dport;
		sk_association_key.proxy.dport = tmp;

		// lookup the socket association
		struct association_t *sk_association_val = bpf_map_lookup_elem(&socket_association, &sk_association_key);
		if (sk_association_val == NULL)
		{
			bpf_printk("Error on lookup socket association - 1");
			return SK_PASS;
		}

		struct sock_id dest_sk_id = sk_association_val->app;

		bpf_printk("after lookup:: ip: %u, sport %u, dport %u",
				   dest_sk_id.ip, dest_sk_id.sport, dest_sk_id.dport);

		// redirect the msg to the associated socket
		ret = bpf_msg_redirect_hash(msg, &intercepted_sockets, &dest_sk_id, BPF_F_INGRESS);
		if (ret != SK_PASS)
		{
			bpf_printk("Error on redirect msg %ld", ret);
			return SK_PASS;
		}
	}
	else
	{
		bpf_printk("From app");
		sk_association_key.app = sk_id;

		// lookup the socket association
		struct association_t *sk_association_val = bpf_map_lookup_elem(&socket_association, &sk_association_key);
		if (sk_association_val == NULL)
		{
			bpf_printk("Error on lookup socket association - 2");
			return SK_PASS;
		}
		struct sock_id dest_sk_id = sk_association_val->proxy;

		bpf_printk("after lookup:: ip: %u, sport %u, dport %u",
				   dest_sk_id.ip, dest_sk_id.sport, dest_sk_id.dport);

		// redirect the msg to the associated socket
		ret = bpf_msg_redirect_hash(msg, &intercepted_sockets, &dest_sk_id, BPF_F_INGRESS);
		if (ret != SK_PASS)
		{
			bpf_printk("Error on redirect msg %ld", ret);
			return SK_PASS;
		}

		bpf_printk("Redirect msg to proxy");
	}

	return ret;
}

char LICENSE[] SEC("license") = "GPL";
