
#include <linux/in.h>
#include <linux/in6.h>

// key structure for the sockmap
struct sock_id
{
	__u32 ip;
	__u16 sport; // stored in HOST byte
	__u16 dport; // stored in HOST byte
};
