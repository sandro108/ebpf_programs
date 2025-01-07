#ifndef __STATSNOOP_H
#define __STATSNOOP_H

#define TASK_COMM_LEN	16
#define NAME_MAX	255
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
	char pathname[NAME_MAX];
};


struct open_event {
	int flags;
	const char* pathname;
};



#endif /* __STATSNOOP_H */
