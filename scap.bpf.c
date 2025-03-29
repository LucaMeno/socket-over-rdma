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

struct
{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, int);
} sockmap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, int);
} mysoc SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 2048);
	__type(value, struct my_msg);
} userMsg SEC(".maps");

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
		desc.ip = skops->local_ip4;
		desc.sport = bpf_htons(skops->local_port);
		desc.dport = bpf_ntohs(sk->dst_port);

		// Add the socket to the map if it doesn't exist
		// The key is the socket descriptor
		ret = bpf_sock_hash_update(skops, &sockmap, &desc, BPF_NOEXIST);

		bpf_printk("---------------------");
		if (ret == 0)
		{
			// print the new socket added
			bpf_printk("new socket: %p", skops->sk);
			bpf_printk("ip: %u", desc.ip);
			bpf_printk("sport: %u", desc.sport);
			bpf_printk("dport: %u", desc.dport);
		}
		else
		{
			bpf_printk("[skops=%p] bpf_sock_hash_update %ld", skops, ret);
		}

	default:
		break;
	}

	return 0;
}

/*
union scap_addr
{
	struct in6_addr in6;
	struct in_addr in;
};

struct my_msg
{
	__u32 size;
	union scap_addr laddr;
	union scap_addr raddr;
	__u16 lport;
	__u16 rport;
	__u16 af;

	__u8 data[];
};
*/

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
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

	int ret = bpf_msg_redirect_hash(msg, &mysoc, &k, BPF_F_INGRESS);

	if (ret == SK_PASS)
	{
		if(bpf_map_push_elem(&userMsg, &my_msg, 0) != 0) {
			bpf_printk("Error on push");
		}
		bpf_printk("Size: %u", my_msg.size);
		bpf_printk("Laddr: %u", my_msg.laddr.in.s_addr);
		bpf_printk("Raddr: %u", my_msg.raddr.in.s_addr);
		bpf_printk("Lport: %u", my_msg.lport);
		bpf_printk("Rport: %u", my_msg.rport);
		bpf_printk("AF: %u", my_msg.af);
	}

	return ret;
}

char LICENSE[] SEC("license") = "GPL";
