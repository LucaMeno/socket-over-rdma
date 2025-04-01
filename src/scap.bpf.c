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
	__type(value, __u64);
} sockmap SEC(".maps");

/**
 * socket to send the data to user space
 */
struct
{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} mysoc SEC(".maps");

// message structure to be passed to user space
struct
{
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 2048);
	__type(value, struct msg_header);
} userMsg SEC(".maps");

/**
 * two ports:
 * 1. to select the sockets to intercept
 * 2. to send back the traffic coming from userpace
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, __u16);
} targetport SEC(".maps");

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
	// get the socket operation type
	int op = (int)skops->op;

	struct sock_descriptor desc = {0};

	struct bpf_sock *sk = skops->sk;
	long ret;

	if (skops->family != AF_INET || !sk)
		return 0;

	switch (op)
	{
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:

		// create the key for the sockmap
		desc.ip = skops->local_ip4;
		desc.sport = (skops->local_port);
		desc.dport = bpf_ntohs(sk->dst_port);

		bpf_printk("----------sockops-----------");

		bpf_printk("sk: %p, ip: %u, sport: %u, dport: %u", skops->sk, desc.ip, desc.sport, desc.dport);

		// check the port
		int key = 0;
		__u16 *target_port = bpf_map_lookup_elem(&targetport, &key);

		if (target_port == NULL)
		{
			// port not set in user space
			bpf_printk("Port not found");
			return 0;
		}
		if (desc.dport != *target_port) // check if the destination port is the target one
		{
			// socket i am not interested in
			bpf_printk("Port not matched");
			return 0;
		}

		// Add the socket to the map
		// then we can intercept the msg on this socket
		ret = bpf_sock_hash_update(skops, &sockmap, &desc, BPF_NOEXIST);

		if (ret == 0)
		{
			bpf_printk("added sk: %p", skops->sk);
		}
		else
		{
			bpf_printk("[skops=%p] bpf_sock_hash_update %ld", skops->sk, ret);
		}

	default:
		break;
	}

	return 0;
}

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
	bpf_printk("----------sk_msg-----------");

	bpf_printk("sk_msg s: %p", msg->sk);

	struct msg_header msg_header = {0};

	if (msg->family != AF_INET) // only IPv4
		return SK_PASS;

	msg_header.size = msg->size;
	msg_header.laddr.in.s_addr = msg->local_ip4;
	msg_header.raddr.in.s_addr = msg->remote_ip4;
	msg_header.lport = msg->local_port;
	msg_header.rport = bpf_ntohs(msg->remote_port);
	msg_header.af = msg->family;
	// msg_header.orig_sock_id = msg->sk;

	int k = 0; // key for the sockmap

	// redirect the msg to my socket
	int ret = 0;

	// retrieve if the server port to understand if the msg is coming from the server
	k = 1;
	__u16 *server_port = bpf_map_lookup_elem(&targetport, &k);

	if (server_port != NULL && msg_header.lport == *server_port)
	{
		// msg coming from the server
		bpf_printk("RESP FROM SERVER");
		return SK_PASS; // don't redirect the msg to my socket

		/**
		 * TODO
		 * in some way, get the sk from the msg header
		 * once we have the sk, we can use bpf_msg_redirect_hash to redirect the msg to the orignal destination
		 * the key could be the sk_desc so i can use the sockmap to retrieve the sk
		 */
	}

	// redirect the msg to my socket
	k = 0; // key for the sockmap
	ret = bpf_msg_redirect_hash(msg, &mysoc, &k, BPF_F_INGRESS);

	if (ret != SK_PASS)
	{
		bpf_printk("Error on redirect");
		return SK_PASS;
	}

	// push the msg header to be able to read it in user space
	if (bpf_map_push_elem(&userMsg, &msg_header, 0) != 0)
	{
		bpf_printk("Error on push");
	}

	bpf_printk("Size: %u, laddr: %u, raddr: %u, lport: %u, rport: %u, af: %u",
			   msg_header.size,
			   msg_header.laddr.in.s_addr,
			   msg_header.raddr.in.s_addr,
			   msg_header.lport,
			   msg_header.rport,
			   msg_header.af);

	return ret;
}

char LICENSE[] SEC("license") = "GPL";
