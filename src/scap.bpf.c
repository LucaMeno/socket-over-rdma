// scap.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include "common.h"

#define AF_INET 2
#define AF_INET6 10

// key structure for the sockmap
struct sock_descriptor
{
	__u32 ip;
	__u16 sport;
	__u16 dport;
};

// list of sockets to redirect
struct
{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, struct sock_descriptor);
	__type(value, __u64);
} sockmap SEC(".maps");

// single socket of the receiver app in user space
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
	__type(value, struct my_msg);
} userMsg SEC(".maps");

// store the target port set in user space
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
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
		desc.sport = bpf_htons(skops->local_port);
		desc.dport = bpf_ntohs(sk->dst_port);

		bpf_printk("----------sockops-----------");

		bpf_printk("sk: %p, ip: %u, sport: %u, dport: %u", skops->sk, desc.ip, desc.sport, desc.dport);

		// check the port
		int key = 0;
		__u16 *port = bpf_map_lookup_elem(&targetport, &key);
		if (port == NULL)
		{
			// port not set in user space
			bpf_printk("Port not found");
			return 0;
		}
		if (desc.dport != *port)
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

	struct my_msg my_msg = {0};

	if (msg->family != AF_INET) // only IPv4
		return SK_PASS;

	my_msg.size = msg->size;
	my_msg.laddr.in.s_addr = msg->local_ip4;
	my_msg.raddr.in.s_addr = msg->remote_ip4;
	my_msg.lport = bpf_ntohs(msg->local_port);
	my_msg.rport = bpf_ntohs(msg->remote_port);
	my_msg.af = msg->family;
	my_msg.data = msg->data;

	int k = 0; // key for the sockmap

	// redirect the msg to my socket
	int ret = bpf_msg_redirect_hash(msg, &mysoc, &k, BPF_F_INGRESS);

	if (ret == SK_PASS)
	{
		// push the msg header to be able to read it in user space
		if (bpf_map_push_elem(&userMsg, &my_msg, 0) != 0)
		{
			bpf_printk("Error on push");
		}
		bpf_printk("Size: %u, laddr: %u, raddr: %u, lport: %u, rport: %u, af: %u",
				   my_msg.size,
				   my_msg.laddr.in.s_addr,
				   my_msg.raddr.in.s_addr,
				   my_msg.lport,
				   my_msg.rport,
				   my_msg.af);
	}

	return ret;
}

char LICENSE[] SEC("license") = "GPL";
