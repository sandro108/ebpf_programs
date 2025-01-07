#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "socket_collector.h"

char LICENSE[] SEC("license") = "GPL";

pid_t rqst_pid  = 0;
__u8  set_debug = 0;
uid_t rqst_uid  = 0;

#define BPF_PRINT(...)               \
    do {                                  \
        if (set_debug)                    \
            bpf_printk(__VA_ARGS__); \
        else                              \
            do {} while (0);              \
    } while (0)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ring_events SEC(".maps");



SEC("kprobe/schedule") /* as def in /kernel/sched/core.c */
int socket_collector(struct pt_regs *ctx)
{
	/* filter by PID or UID first, if requested */
	bpf_printk(" A ");
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id;

	BPF_PRINT("PID: %u", pid);
	if (rqst_pid && rqst_pid != pid) {
		return 0;
	}
	
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	
	BPF_PRINT("UID: %u", uid);
	if (rqst_uid && rqst_uid != uid) {
		return 0;
	}
	
	__u32 tgid = id >> 32;
	__u32 gid = uid_gid >> 32;
	__u32 cpu = bpf_get_smp_processor_id();

	bpf_printk(" B ");

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFREG  0100000
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

	u16 fds[MAX_FDS] ;
	struct sock_metrics* sock_event = NULL;
	struct files_struct* files = NULL;
	struct fdtable* fdt = NULL;
	struct file** filp_arr = NULL;
	struct file* filp = NULL;
	struct task_struct* task = NULL;
	

	/* Obtain the currently scheduled task_struct and start digging */
	task = (struct task_struct*)bpf_get_current_task();
	
	if (task == NULL) {
		BPF_PRINT("task is NULL.");
		return 0;
	}
	
	 /* obtain the file descriptor table from the files_struct */
	
	if (0 != (bpf_probe_read_kernel(&files, sizeof(files), &task->files))) { 
		return 0;
	}
	if (0 != (bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt))) { 
		return 0;
	}
	unsigned long* op_fds = NULL; 
	op_fds = BPF_CORE_READ(fdt, open_fds);
	if (!op_fds) {
		return 0;
	}

	unsigned long open_fds;
	if(0 != (bpf_probe_read_kernel(&open_fds, sizeof(open_fds), op_fds ))) {
		return 0;			
	}
	BPF_PRINT("open_fds: 0x%lx", open_fds);


	/* obtain the 1-bits to see which file descriptors are open, if any */
	
	if (!open_fds) { 
		return 0;
	}
	
	u16 cnt = 0, fd;
	for (u8 i = 0; i < MAX_FDS; i++ ) {
		if ((open_fds & 0x1u) == 1) {
			fds[cnt] = i;
			cnt++;
		}       
		open_fds >>= 1;
	}
				
	/* 
	 * Obtain the fd array to start the open socket search with.
	 * TODO: Since only MAX_FDS fds can be queried -due to bpf verifier instruction count overflow-,
	 * tail calls should be tried out to read the rest subsequently!
	 */
	
	if (0 != (bpf_probe_read_kernel(&filp_arr, sizeof(filp_arr), (void*) &fdt->fd))) { 
		return 0;
	}	
	
	for (fd = 0; fd < cnt; fd++) {
	
		if (0 != (bpf_probe_read_kernel(&filp, sizeof(filp), (void*) &filp_arr[fds[fd]]))) { 
			continue;	
		}
		umode_t ftype = 0; 
		ftype = BPF_CORE_READ(filp, f_inode, i_mode);
		
		if (ftype && S_ISSOCK(ftype)) {//6 error case for 'ftype' checked in here
			bpf_printk(" C ");
			BPF_PRINT("Filetype is socket. ftype=%lx fd=%d", ftype, fds[fd]);
			sock_event = bpf_ringbuf_reserve(&ring_events, sizeof(*sock_event), 0);				
			if (!sock_event) {
				BPF_PRINT(" Error: Ring_buffer mem could not be reserved.");
				return 0;
			}
			sock_event->err = 0;
			struct socket* sock = NULL;
			sock = BPF_CORE_READ(filp, private_data);
			if (!sock) {
				BPF_PRINT("struct socket could not be read.");
				sock_event->err = 1;
				bpf_ringbuf_submit(sock_event, 0);
				continue;
			}  
			
			if (0 == (bpf_get_current_comm(sock_event->cmd_name, sizeof(sock_event->cmd_name)))) {
			} else {bpf_probe_read_kernel_str(sock_event->cmd_name, sizeof(sock_event->cmd_name), "null");}
			
			sock_event->fd = fds[fd];
			sock_event->time_stp = bpf_ktime_get_ns() / 1000;
			sock_event->cpu = cpu;
			sock_event->pid = pid;
			sock_event->tgid = tgid;
			sock_event->uid = uid;
			sock_event->gid = gid;

			short sock_type = 0;
			if (0 != (sock_type = BPF_CORE_READ(sock, type))) {
				sock_event->sock_type = sock_type;
			}
			BPF_PRINT("socket_type: %u", sock_type);
			
			unsigned char sock_state = 0;
			if (0 != (sock_state = BPF_CORE_READ(sock, sk, __sk_common.skc_state))) {
				sock_event->sock_state = sock_state;
			}
			BPF_PRINT("socket_state: %u", sock_state);
			
			unsigned short skc_family = 0;
			if (0 != (skc_family = BPF_CORE_READ(sock, sk, __sk_common.skc_family))) {
				sock_event->sock_family = skc_family;
			}
			BPF_PRINT("sk_type|state|family: %u|%u|%d",sock_type, sock_state, skc_family);
			
			if (skc_family == AF_UNIX) {
				if (0 != (sock_state = BPF_CORE_READ(sock, state))) {
					sock_event->sock_state = sock_state;
				}	
			}	
			
			/* af_inet socket */ 
			
			else if (skc_family == AF_INET) {
				
				/*------ipv4_addr-----------------*/
				
				__be32 d_addr = 0; 
				d_addr = BPF_CORE_READ(sock, sk, __sk_common.skc_daddr);
				if (d_addr) {
					BPF_PRINT("dest_addr %x", d_addr);
					sock_event->dst_addr = bpf_ntohs(d_addr);
				}
				__be32 s_addr = 0;
				s_addr = BPF_CORE_READ(sock, sk, __sk_common.skc_rcv_saddr);
				if (s_addr) {
					BPF_PRINT("src_addr %x", s_addr);
					sock_event->src_addr = bpf_ntohs(s_addr);
				}   
				__u64 addrpair = 0;
				addrpair = BPF_CORE_READ(sock, sk, __sk_common.skc_addrpair);
				if (addrpair) {
					BPF_PRINT("addrpair %lx", addrpair);
					sock_event->addr_pair = addrpair;
				}
			} 
			
			/* af_inet6 socket */
			
			else if (skc_family == AF_INET6) {
		
				/*------ipv6_addr-----------------*/
				
				__u16* in6_src = NULL;
				in6_src = BPF_CORE_READ(sock, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr16);
				
				if (in6_src) {
						
					sock_event->ipv6_saddr[0] = bpf_ntohs(in6_src[0]); 
					sock_event->ipv6_saddr[1] = bpf_ntohs(in6_src[1]); 
					sock_event->ipv6_saddr[2] = bpf_ntohs(in6_src[2]); 
					sock_event->ipv6_saddr[3] = bpf_ntohs(in6_src[3]); 
					sock_event->ipv6_saddr[4] = bpf_ntohs(in6_src[4]); 
					sock_event->ipv6_saddr[5] = bpf_ntohs(in6_src[5]); 
					sock_event->ipv6_saddr[6] = bpf_ntohs(in6_src[6]); 
					sock_event->ipv6_saddr[7] = bpf_ntohs(in6_src[7]); 

				} 
				__be16* in6_daddr = NULL;
				in6_daddr = BPF_CORE_READ(sock, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr16);
				if (in6_daddr) {

					sock_event->ipv6_daddr[0] = bpf_ntohs(in6_daddr[0]); 
					sock_event->ipv6_daddr[1] = bpf_ntohs(in6_daddr[1]); 
					sock_event->ipv6_daddr[2] = bpf_ntohs(in6_daddr[2]); 
					sock_event->ipv6_daddr[3] = bpf_ntohs(in6_daddr[3]); 
					sock_event->ipv6_daddr[4] = bpf_ntohs(in6_daddr[4]); 
					sock_event->ipv6_daddr[5] = bpf_ntohs(in6_daddr[5]); 
					sock_event->ipv6_daddr[6] = bpf_ntohs(in6_daddr[6]); 
					sock_event->ipv6_daddr[7] = bpf_ntohs(in6_daddr[7]); 

				}
			}
			
			/*------ports-------*/

			if (skc_family == AF_INET || skc_family == AF_INET6) {	
											
				__be16 d_port = 0;
				d_port = BPF_CORE_READ(sock, sk, __sk_common.skc_dport);
				if (d_port) {
					BPF_PRINT("dest_port %u",  bpf_ntohs(d_port));
					sock_event->dst_port = bpf_ntohs(d_port);
				}
				 __u16 s_port = 0;
				 s_port = BPF_CORE_READ(sock, sk, __sk_common.skc_num);
				if (s_port) {
					BPF_PRINT("src_port %u", s_port);
					sock_event->src_port = s_port;
				}
				__u32 portpair = 0;
				portpair = BPF_CORE_READ(sock, sk, __sk_common.skc_portpair);
				if (portpair) {
					BPF_PRINT("portpair %u", portpair);
					sock_event->portpair = bpf_ntohs(portpair);
				}
			}
			bpf_ringbuf_submit(sock_event, 0);
		}//end if 6
	}//end fd loop
	return 0;
}
