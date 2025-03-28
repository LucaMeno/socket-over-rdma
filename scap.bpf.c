// scap.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/in.h>

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

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
	// get the socket operation type
	int op = (int)skops->op;

	struct sock_descriptor desc = {0};

	struct bpf_sock *sk = skops->sk;
	long ret;

	if (skops->family != 2 /* AF_INET */ || !sk)
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

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
    bpf_printk("sk_msg s: %p", msg->sk);

    struct sock_descriptor desc;

    desc.ip = bpf_ntohl(msg->remote_ip4);
    desc.sport = bpf_ntohs(msg->remote_port);
    desc.dport = bpf_ntohs(msg->local_port);

    int k = 0;
    return bpf_msg_redirect_hash(msg, &mysoc, &k, BPF_F_INGRESS);
	
}

char LICENSE[] SEC("license") = "GPL";
