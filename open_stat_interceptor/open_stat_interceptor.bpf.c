#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "open_stat_interceptor.h"


char LICENSE[] SEC("license") = "GPL";


#define MAX_ENTRIES 10240
#define O_CREAT 00000100

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256* 1024);
 } ring_events SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, const char *);
} pid_pathname_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct open_event);
} open_map SEC(".maps");

pid_t rqstd_pid = 0;


//---------------------open---------------------------------------------------



static int open_entry(void* ctx, const char *pathname, int flags) {

	
	if (0 == (O_CREAT & flags)) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 pid = (__u32)pid_tgid;

	if (rqstd_pid && rqstd_pid != pid) {
		return 0;
	}

	if (!pathname)
		return 0;

	struct open_event o_event = {};

	o_event.pathname = pathname;
	o_event.flags = flags; //(int)ctx->args[1];

	bpf_map_update_elem(&open_map, &pid, &o_event, BPF_ANY);
	return 0;
 }


static int open_exit(void* ctx, int ret_code) {

	struct open_event* o_event = NULL;
	struct event* event = NULL;
	int ret;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 pid = (__u32)pid_tgid;

	if (rqstd_pid && rqstd_pid != pid) {
		return 0;
	}

	o_event = bpf_map_lookup_elem(&open_map, &pid);
	if (!o_event) {
		return 0;
	}

	event = bpf_ringbuf_reserve(&ring_events, sizeof(*event), 0);
	if (event == NULL) {
		bpf_printk("open: ring_buffer mem could not be reserved");
		return 0;
	}
	event->event_type = OPEN_EVENT;
	event->pid = pid;
	event->uid = bpf_get_current_uid_gid();
	event->ts_us = bpf_ktime_get_ns() / 1000;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_probe_read_user_str(&event->pathname, sizeof(event->pathname), o_event->pathname);
	event->flags = o_event->flags;
	event->ret = ret_code;

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&open_map, &pid);
	return 0;

 }


SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct syscall_trace_enter* ctx)
{
	return open_entry(ctx, (const char *)ctx->args[0], (int)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct syscall_trace_exit* ctx)
{
	return open_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct syscall_trace_enter* ctx)
{
	return open_entry(ctx, (const char *)ctx->args[1], (int)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct syscall_trace_exit* ctx)
{
	return open_exit(ctx, (int)ctx->ret);
}



//---------------------stat---------------------------------------------------




 static int stat_entry(void *ctx, const char *pathname)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 pid = (__u32)id;

	if (!pathname)
		return 0;

 	if (rqstd_pid && rqstd_pid != pid)
 		return 0;

	bpf_map_update_elem(&pid_pathname_map, &pid, &pathname, BPF_ANY);
	return 0;
};

static int stat_exit(void *ctx, int ret_code)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 pid = (__u32)id;
	
	if (rqstd_pid && rqstd_pid != tgid) {
		return 0;
	}

	const char **pathname;
	struct event* event = NULL;

    event = bpf_ringbuf_reserve(&ring_events, sizeof(*event), 0);
	if (event == NULL) {
		bpf_printk("stat: ring_buffer mem could not be reserved.");
		return 0;
	}
	pathname = bpf_map_lookup_elem(&pid_pathname_map, &pid);
	if (!pathname) {
		bpf_ringbuf_submit(event, 0);
		return 0;
	}
	event->event_type = STAT_EVENT;
	event->pid = pid;
	event->uid = bpf_get_current_uid_gid();	
	event->ts_us = bpf_ktime_get_ns() / 1000;
	event->ret = ret_code;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_probe_read_user_str(event->pathname, sizeof(event->pathname), *pathname);

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pid_pathname_map, &pid);
	return 0;
}



SEC("tracepoint/syscalls/sys_enter_statfs")
int handle_statfs_entry(struct syscall_trace_enter *ctx)
{
	return stat_entry(ctx, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_statfs")
int handle_statfs_return(struct syscall_trace_exit *ctx)
{
	return stat_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_newstat")
int handle_newstat_entry(struct syscall_trace_enter *ctx)
{
	return stat_entry(ctx, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_newstat")
int handle_newstat_return(struct syscall_trace_exit *ctx)
{
	return stat_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_statx")
int handle_statx_entry(struct syscall_trace_enter *ctx)
{
	return stat_entry(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_statx")
int handle_statx_return(struct syscall_trace_exit *ctx)
{
	return stat_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int handle_newfstatat_entry(struct syscall_trace_enter *ctx)
{
	return stat_entry(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_newfstatat")
int handle_newfstatat_return(struct syscall_trace_exit *ctx)
{
	return stat_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_newlstat")
int handle_newlstat_entry(struct syscall_trace_enter *ctx)
{
	return stat_entry(ctx, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_newlstat")
int handle_newlstat_return(struct syscall_trace_exit *ctx)
{
	return stat_exit(ctx, (int)ctx->ret);
}
