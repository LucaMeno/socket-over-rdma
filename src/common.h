
/*#include <linux/in.h>
#include <linux/in6.h>*/

// key structure for the sockmap
struct sock_id
{
	__u32 ip;    // stored in NET order
	__u16 sport; // stored in HOST byte
	__u16 dport; // stored in HOST byte
};

struct association_t
{
	struct sock_id proxy;
	struct sock_id app;
};