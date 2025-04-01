
#include <linux/in.h>
#include <linux/in6.h>


union scap_addr
{
	struct in6_addr in6;
	struct in_addr in;
};

/*
struct my_msg
{
	__u32 size;
	union scap_addr laddr;
	union scap_addr raddr;
	__u16 lport;
	__u16 rport;
	__u16 af;

	__u8 *data;
};
*/

struct msg_header
{
	__u32 size;
	union scap_addr laddr;
	union scap_addr raddr;
	__u16 lport;
	__u16 rport;
	__u16 af;
	struct bpf_sock * orig_sock_id;
};


// key structure for the sockmap
struct sock_descriptor
{
	__u32 ip;
	__u16 sport; // stored in HOST byte
	__u16 dport; // stored in HOST byte
};