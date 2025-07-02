
#ifndef COMMON_H
#define COMMON_H

// #include "vmlinux.h"

typedef uint32_t __u32;
typedef uint16_t __u16;

typedef struct sock_id sock_id_t;

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

struct userspace_data_t
{
	struct association_t association;
	int sockops_op;
};

#endif // COMMON_H