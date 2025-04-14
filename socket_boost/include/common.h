
#ifndef COMMON_H
#define COMMON_H

//#include "vmlinux.h"

// key structure for the sockmap
struct sock_id
{
	__u32 sip;	 // stored in NET order
	__u32 dip;	 // stored in NET order
	__u16 sport; // stored in HOST byte
	__u16 dport; // stored in HOST byte
};

struct association_t
{
	struct sock_id proxy;
	struct sock_id app;
};

struct client_sk_t
{
	int fd;
	__u16 port;
	__u32 ip;
};

#endif // COMMON_H