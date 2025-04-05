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
	__type(key, struct sock_descriptor);
	__type(value, __u32); // the value is the socket fd
} intercepted_sockets SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 2048);
	__type(value, __u32); // the value is the socket fd
} free_sockets SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, int); // proxy socket fd
	__type(value, struct sock_descriptor);
} socket_association SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, int);
} target_ports SEC(".maps");

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
	// get the socket operation type
	int op = (int)skops->op;

	struct sock_descriptor sock_key = {0};

	struct bpf_sock *sk = skops->sk;
	long ret;

	if (skops->family != AF_INET || !sk)
		return 0;

	switch (op)
	{
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		// new established connection

		sock_key.ip = sk->src_ip4;
		sock_key.sport = sk->src_port;
		sock_key.dport = bpf_ntohs(sk->dst_port);

		bpf_printk("----------sockops-----------");

		// check if the destination port is the target one
		int key = sock_key.dport;
		int *is_port_target = bpf_map_lookup_elem(&target_ports, &key);

		if (is_port_target == NULL)
		{
			bpf_printk("SKIP key:: ip: %u, sport %u, dport %u ",
					   sock_key.ip, sock_key.sport, sock_key.dport);
			return 0;
		}

		// Add the socket to the map
		ret = bpf_sock_hash_update(skops, &intercepted_sockets, &sock_key, BPF_NOEXIST);

		if (ret == 0)
		{
			bpf_printk("ADD key: %u, sport %u, dport %u", sock_key.ip, sock_key.sport, sock_key.dport);
		}
		else
		{
			bpf_printk("[skops=%p] bpf_sock_hash_update %ld", skops->sk, ret);
		}

		// get one free socket from the free_sockets map
		__u32 free_sk = 0;
		ret = bpf_map_pop_elem(&free_sockets, &free_sk); // pop a free socket from the queue
		if (ret != 0)
		{
			bpf_printk("Error on pop free socket");
			return 0;
		}

		// add the socket association to the map
		ret = bpf_map_update_elem(&socket_association, &free_sk, &sock_key, BPF_NOEXIST);
		if (ret != 0)
		{
			bpf_printk("Error on update socket association");
			return 0;
		}

		bpf_printk("ASSOC val:: key: %u, sport %u, dport %u",
				   sock_key.ip, sock_key.sport, sock_key.dport);
		bpf_printk("ASSOC key:: free_sk: %u", free_sk);

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
	/*
	// retrieve if the server port to understand if the msg is coming from the server
	k = 1;
	__u16 *server_port = bpf_map_lookup_elem(&targetport, &k);

	if (server_port != NULL && msg->local_port == *server_port)
	{
		// msg coming from the server
		struct msg_header msg_header_ptr = {0};

		// pop the original msg header from the msg_from_user map
		ret = bpf_map_pop_elem(&msg_from_user, &msg_header_ptr);
		if (ret != 0)
		{
			bpf_printk("Error on pop");
			return SK_PASS;
		}

		// create the key for the sockmap
		struct sock_descriptor desc = {0};
		desc.ip = msg_header_ptr.laddr.in.s_addr;
		desc.sport = msg_header_ptr.lport;
		desc.dport = msg_header_ptr.rport;

		// print the key
		bpf_printk("POP key: ip: %u, sport: %u, dport: %u", desc.ip, desc.sport, desc.dport);

		// redirect the msg to the original socket
		ret = bpf_msg_redirect_hash(msg, &sockmap, &desc, BPF_F_INGRESS);

		if (ret != SK_PASS)
		{
			bpf_printk("Error on redirect to original socket %d", ret);
		}

		bpf_printk("Redirect to original socket");
		return SK_PASS;
	}

	struct msg_header msg_header = {0};
	msg_header.laddr.in.s_addr = msg->local_ip4;
	msg_header.raddr.in.s_addr = msg->remote_ip4;
	msg_header.lport = msg->sk->src_port;
	msg_header.rport = bpf_ntohs(msg->sk->dst_port);
	msg_header.af = msg->family;

	// redirect the msg to my socket
	k = 0; // key for the sockmap
	ret = bpf_msg_redirect_hash(msg, &mysoc, &k, BPF_F_INGRESS);

	if (ret != SK_PASS)
	{
		bpf_printk("Error on redirect");
		return SK_PASS;
	}

	// push the msg header to be able to read it in user space
	if (bpf_map_push_elem(&msg_to_user, &msg_header, 0) != 0)
	{
		bpf_printk("Error on push");
	}

	bpf_printk("PUSH key: ip: %u, sport: %u, dport: %u", msg_header.laddr.in.s_addr, msg_header.lport, msg_header.rport);
*/
	return ret;
}

char LICENSE[] SEC("license") = "GPL";
