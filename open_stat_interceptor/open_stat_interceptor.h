#ifndef __OPEN_STAT_INTERCEPTOR_H
#define __OPEN_STAT_INTERCEPTOR_H

#define TASK_COMM_LEN	16
#define PATH_MAX	4096
#define OPEN_EVENT 0
#define STAT_EVENT 1

struct event {
	__u8 event_type;
    __u64 ts_us;
	__u32 pid;
    __u32 uid;
    int flags;
	int ret;
	char comm[TASK_COMM_LEN];
	char pathname[PATH_MAX];
};


struct open_event {
	int flags;
	const char* pathname;
};



#endif /* __OPEN_STAT_INTERCEPTOR_H */
