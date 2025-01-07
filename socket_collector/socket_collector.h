
#ifndef __SOCKET_COLLECTOR_H
#define __SOCKET_COLLECTOR_H

#define AF_INET6 10
#define AF_INET 2
#define AF_UNIX 1

#define MAX_FDS 20 /*temporary limit due to verifier's path verification limit of 1E6 instructions */

#define TASK_COMM_LEN 16

struct sock_metrics {

	char cmd_name[TASK_COMM_LEN];
	__u64 time_stp;
	__u32 cpu;
	pid_t pid;
	pid_t tgid;
	__u32 uid;
	__u32 gid;

	__u16 fd;
	__u16 sock_type;
	__u16 sock_state;
	__u16 sock_family;

	__u16 dst_port;
	__u16 src_port;
	__u32 portpair;
	__u32 dst_addr;
	__u32 src_addr;
	__u64 addr_pair;
	__u16 ipv6_daddr[8];
	__u16 ipv6_saddr[8];
	__u8  msg_type; 
	__u8  err;

};


#endif /*__SOCKET_COLLECTOR_H*/



