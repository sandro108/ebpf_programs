#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "nfs4_path_finderV2.h"


char LICENSE[] SEC("license") = "GPL";

pid_t own_pid   = 0;
pid_t rqst_pid  = 0;
__u64 rqst_cgid = 0;
uid_t rqst_uid  = 0;
__u8 set_debug  = 0;


/* debug print helper */
#define BPF_PRINT(...)               \
    do {                                  \
        if (set_debug)                    \
            bpf_printk(__VA_ARGS__); \
        else                              \
            do {} while (0);              \
    } while (0)

/* routine used for fs type string compare */ 
static inline int str_cmp(char str[5]) {
    if (!str) {
        return 0;
    }
    if (str[0] != 'n') { 
        return 0;
    }
    int i = 1;
    char nfs4[] = "nfs4"; 
    while (nfs4[i] != '\0') {
        if (str[i] != nfs4[i]) {
            return 0;
        }
        i++;
    }
    return 1;
}

/* ring buffer definition */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ring_events SEC(".maps");



SEC("kprobe/schedule") /* as defined in /kernel/sched/core.c */
int nfs4_pathfinderV(struct pt_regs *ctx)
{
	__u64 id      = bpf_get_current_pid_tgid();
	__u32 pid     = id;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid     = uid_gid;
	__u64 cgid    = bpf_get_current_cgroup_id(); /* cgroup_id (inode number of /sys/fs/cgroup/ entry) */

	/* filter by: */
	if (own_pid && own_pid == pid) {
		return 0;
	}
	if (rqst_pid && rqst_pid != pid) {
		return 0;
	}
	else if (rqst_uid && rqst_uid != uid) {
		return 0;
	}
	else if (rqst_cgid && rqst_cgid != cgid) {
		return 0;
	}


#define DEBUG

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFREG  0100000
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

	u16 fds[MAX_FDS] ;
	struct path_metrics* path_event = NULL;
	struct file* filp = NULL;
	struct path path;
	struct dentry* dentry = NULL;
	struct qstr dname;
	const unsigned char* kern_p = NULL;

	struct task_struct* task = NULL;
	


	/* Obtain the currently scheduled task_struct and start digging */
	task = (struct task_struct*)bpf_get_current_task();
	
	if (task == NULL) {
		BPF_PRINT("task is NULL.");
		return 0;
	}
	__u32 tgid = id >> 32;
	__u32 gid = uid_gid >> 32;
	__u32 cpu = bpf_get_smp_processor_id();


	 /* obtain the file descriptor table from the files_struct */
	struct files_struct* files = NULL;
	if (0 != (bpf_probe_read_kernel(&files, sizeof(files), &task->files))) {
		BPF_PRINT("Error obtaining files_struct.");
		return 0;
	}
	
	struct fdtable* fdt = NULL;
	if (0 != (bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt))) {
		BPF_PRINT("Error obtaining fd table.");
		return 0;
	}
	
	unsigned long* op_fds = NULL;
	op_fds = BPF_CORE_READ(fdt, open_fds);
	if (!op_fds) {
		BPF_PRINT("Error obtaining open fds bitmap.");
		return 0;
	}
	unsigned long open_fds;
	if(0 != (bpf_probe_read_kernel(&open_fds, sizeof(open_fds), op_fds ))) {
		BPF_PRINT("open_fds: 0x%lx", open_fds);
		return 0;		
	}
	
	/* obtain the 1-bits to see which file descriptors are open, if any */
	if (open_fds <= 0) {
		BPF_PRINT("No fds open!");
		return 0;		
	}

	u16 cnt = 0, fd;
	u8 i = 3;
	open_fds >>= i;
	for (; i < MAX_FDS; i++ ) {
		if ((open_fds & 0x1u) == 1) {
			fds[cnt] = i;
			cnt++;
		}
		open_fds >>= 1;
	}
	
	/* 
	 * Obtain the fd array to start the open file search with.
	 * TODO: Since only 16 fd can be queried -due to bpf verifier instruction count overflow-,
	 * tail calls should be tried out to read fds 16-31, 32-47, 48-63 subsequently!
	 */
	
	struct file** filp_arr = NULL;		
	if (0 != (bpf_probe_read_kernel(&filp_arr, sizeof(filp_arr), (void*) &fdt->fd))) {
		BPF_PRINT("Error obtainig file pointer array.");
		return 0;
	}

//-----------------------Start assembling a path for every fd in fds[] up to MAX_FDS-------------------------
	
	/* fd loop */
	for (fd = 0; fd < cnt; fd++) {
					
		if (0 != (bpf_probe_read_kernel(&filp, sizeof(filp), (void*) &filp_arr[fds[fd]]))) {
			BPF_PRINT("Error obtainig filep@%u.", fds[fd]);
			continue;
		}
		/* check file type */
		umode_t ftype = 0; 
		ftype = BPF_CORE_READ(filp, f_inode, i_mode );
		if (!ftype) {
			BPF_PRINT("ftype (i_mode) not available for fd: %u.", fds[fd]);
			continue;
		}
		if (!S_ISREG(ftype)) {
			BPF_PRINT("ftype for fd %u not regular: 0x%x.", fds[fd], ftype);
			continue;
		}
		/* if file type is regular, check if fs_type is nfs4 */
		struct inode* inode = NULL;
		inode =  BPF_CORE_READ(filp, f_inode);
		if (!inode) {
			BPF_PRINT("Error obtaining inode");
			continue;
		}
		struct super_block* sb = NULL;
		sb =  BPF_CORE_READ(inode, i_sb);
		if (!sb) {
			BPF_PRINT("Error obtaining superblock");
			continue;
		}
		struct file_system_type* fs_type = NULL;
		fs_type = BPF_CORE_READ(sb, s_type);
		if (!fs_type) {
			BPF_PRINT("Error obtaining fs_type");
			continue;
		}
		const char* fs_name = NULL;
		fs_name = BPF_CORE_READ(fs_type, name);
		if (!fs_name) {
			BPF_PRINT("Error obtaining fs_name");
			continue;
		}
		
		char nfs4[5];
		if (0 > (bpf_probe_read_kernel_str(nfs4, sizeof(nfs4), fs_name))) {
			BPF_PRINT("Error copying fs_name to array.");
			continue;
		}
		
		BPF_PRINT("ftype for fd %u is  regular: 0x%x, fs_type: %s.", fds[fd], ftype, nfs4);
		
		/* check if filesystem type is nfs4 */
		if (!str_cmp(nfs4)) {
			continue;
		}		
				
		/* obtain file's path struct */			
		if (0 != (bpf_probe_read_kernel(&path, sizeof(path), &filp->f_path))) { 
			BPF_PRINT("Error obtaining path struct");
			continue;
		}
		/* obtain path struct's dentry struct */
		if (0 != (bpf_probe_read_kernel(&dentry, sizeof(dentry), &path.dentry))) { 
			BPF_PRINT("Error obtaining dentry struct");
			continue;
		}
		/* obtain qstr struct within dentry */
		if (0 != (bpf_probe_read_kernel(&dname, sizeof(dname), &dentry->d_name))) { 
			BPF_PRINT("Error obtaining denty name");
			continue;
		}
		/* finally obtain dentry name (string of path component) */
		if (0 != (bpf_core_read(&kern_p, sizeof(kern_p), &dname.name))) {
			BPF_PRINT("Error copying dentry->dname.name");
			continue;
		}
		
		/* reserve ring buffer space for path metrics struct*/
		path_event = bpf_ringbuf_reserve(&ring_events, sizeof(*path_event), 0);				
		if (!path_event) {
			BPF_PRINT(" Error in first path_lookup1: Ring_buffer mem could not be reserved.");
			return 0;
		}
		
		/* start filling the first path_metrics struct with treats */
		if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_1, sizeof(path_event->dir_entry_1), "0"))
		 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_0, sizeof(path_event->dir_entry_0), kern_p))))) {
			BPF_PRINT("Error copying 1st dentry to path_event struct.");
			path_event->err = 1;
			bpf_ringbuf_submit(path_event, 0);
			continue;
		}
		BPF_PRINT("First d_entry of fd_%d: %s", fds[fd], path_event->dir_entry_0);

		path_event->err = 0;
		/* save timestamp in us */ 
		path_event->time_stp = bpf_ktime_get_ns() / 1000;
		/* save name of current task */
		if (0 == (bpf_get_current_comm(path_event->cmd_name, sizeof(path_event->cmd_name)))) {
		} else {bpf_probe_read_kernel_str(path_event->cmd_name, sizeof(path_event->cmd_name), "null");}
		/* be greedy...*/
		path_event->cpu = cpu;
		path_event->pid = pid;
		path_event->tgid = tgid;
		path_event->uid = uid;
		path_event->gid = gid;
		path_event->cgid = cgid;
		path_event->fd = fds[fd];

//--------------Start the search of d_entry names until we arrive at root dir----------------------

		/* path loop */
		for (int i = 1; i < MAX_PATH_DEPTH; i++) {
			
			const unsigned char* prev_name = NULL; 
			prev_name = BPF_CORE_READ(dentry, d_parent, d_name.name);
			if (!prev_name) {
				path_event->err = 1;
				BPF_PRINT("Error obtaining dentry name.");
				break;
			}	
			if (i == 1) {
				if (kern_p == prev_name) {
					BPF_PRINT("Path walk completed, bailing out...!");
					break;
				}
			}
			
			switch (i) {

				case 1:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_2, sizeof(path_event->dir_entry_2), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_1, sizeof(path_event->dir_entry_1), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_1.");
						path_event->err = 1;
					} break;
				case 2:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_3, sizeof(path_event->dir_entry_3), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_2, sizeof(path_event->dir_entry_2), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_2.");
						path_event->err = 1;
					} break;
				case 3:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_4, sizeof(path_event->dir_entry_4), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_3, sizeof(path_event->dir_entry_3), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_3.");
						path_event->err = 1;
					} break;	
				case 4:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_5, sizeof(path_event->dir_entry_5), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_4, sizeof(path_event->dir_entry_4), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_4.");
						path_event->err = 1;
					} break;
				case 5:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_6, sizeof(path_event->dir_entry_6), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_5, sizeof(path_event->dir_entry_5), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_5.");
						path_event->err = 1;
					} break;
				case 6:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_7, sizeof(path_event->dir_entry_7), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_6, sizeof(path_event->dir_entry_6), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_6.");
						path_event->err = 1;
					} break;
				case 7:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_8, sizeof(path_event->dir_entry_8), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_7, sizeof(path_event->dir_entry_7), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_7.");
						path_event->err = 1;
					} break;
				case 8:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_9, sizeof(path_event->dir_entry_9), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_8, sizeof(path_event->dir_entry_8), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_8.");
						path_event->err = 1;
					} break;
				case 9:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_10, sizeof(path_event->dir_entry_10), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_9, sizeof(path_event->dir_entry_9), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_9.");
						path_event->err = 1;
					} break;
				case 10:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_11, sizeof(path_event->dir_entry_11), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_10, sizeof(path_event->dir_entry_10), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_10.");
						path_event->err = 1;
					} break;
				case 11:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_12, sizeof(path_event->dir_entry_12), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_11, sizeof(path_event->dir_entry_11), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_11.");
						path_event->err = 1;
					} break;
				case 12:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_13, sizeof(path_event->dir_entry_13), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_12, sizeof(path_event->dir_entry_12), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_12.");
						path_event->err = 1;
					} break;
				case 13:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_14, sizeof(path_event->dir_entry_14), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_13, sizeof(path_event->dir_entry_13), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_13.");
						path_event->err = 1;
					} break;
				case 14:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_15, sizeof(path_event->dir_entry_15), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_14, sizeof(path_event->dir_entry_14), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_14.");
						path_event->err = 1;
					} break;
				case 15:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_16, sizeof(path_event->dir_entry_16), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_15, sizeof(path_event->dir_entry_15), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_15.");
						path_event->err = 1;
					} break;
				case 16:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_17, sizeof(path_event->dir_entry_17), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_16, sizeof(path_event->dir_entry_16), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_16.");
						path_event->err = 1;
					} break;
				case 17:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_18, sizeof(path_event->dir_entry_18), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_17, sizeof(path_event->dir_entry_17), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_17.");
						path_event->err = 1;
					} break;
				case 18:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_19, sizeof(path_event->dir_entry_19), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_18, sizeof(path_event->dir_entry_18), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_18.");
						path_event->err = 1;
					} break;
				case 19:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_20, sizeof(path_event->dir_entry_20), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_19, sizeof(path_event->dir_entry_19), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_15.");
						path_event->err = 1;
					} break;
				case 20:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_21, sizeof(path_event->dir_entry_21), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_20, sizeof(path_event->dir_entry_20), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_20.");
						path_event->err = 1;
					} break;
				case 21:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_22, sizeof(path_event->dir_entry_22), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_21, sizeof(path_event->dir_entry_21), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_21.");
						path_event->err = 1;
					} break;
				case 22:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_23, sizeof(path_event->dir_entry_23), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_22, sizeof(path_event->dir_entry_22), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_22.");
						path_event->err = 1;
					} break;
				case 23:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_24, sizeof(path_event->dir_entry_24), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_23, sizeof(path_event->dir_entry_23), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_23.");
						path_event->err = 1;
					} break;
				case 24:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_25, sizeof(path_event->dir_entry_25), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_24, sizeof(path_event->dir_entry_24), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_24.");
						path_event->err = 1;
					} break;
				case 25:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_26, sizeof(path_event->dir_entry_26), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_25, sizeof(path_event->dir_entry_25), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_25.");
						path_event->err = 1;
					} break;
				case 26:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_27, sizeof(path_event->dir_entry_27), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_26, sizeof(path_event->dir_entry_26), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_26.");
						path_event->err = 1;
					} break;
				case 27:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_28, sizeof(path_event->dir_entry_28), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_27, sizeof(path_event->dir_entry_27), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_27.");
						path_event->err = 1;
					} break;
				case 28:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_29, sizeof(path_event->dir_entry_29), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_28, sizeof(path_event->dir_entry_28), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_28.");
						path_event->err = 1;
					} break;
				case 29:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_30, sizeof(path_event->dir_entry_30), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_29, sizeof(path_event->dir_entry_29), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_29.");
						path_event->err = 1;
					} break;
				case 30:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_31, sizeof(path_event->dir_entry_31), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_30, sizeof(path_event->dir_entry_30), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_30.");
						path_event->err = 1;
					} break;
				case 31:
					if ((0 > (bpf_probe_read_kernel_str(path_event->dir_entry_32, sizeof(path_event->dir_entry_32), "0"))
					 || (0 > (bpf_probe_read_kernel_str(path_event->dir_entry_31, sizeof(path_event->dir_entry_31), prev_name))))) {
						BPF_PRINT("Error copying dentry to path_event->dir_entry_31.");
						path_event->err = 1;
					} break;

				default: 
					path_event->err = 1;
					BPF_PRINT("Switch case error: case %u not found", i);
					break;
			}

			if (path_event->err) {
				BPF_PRINT("Error in switch case.");
				break;
			}

			BPF_PRINT("Next path component for fd_%d: %s", fds[fd], prev_name);
			
			/* check if root d_entry is hit, if so, bail out! */ 
			struct dentry* dentry_parent = NULL;
			dentry_parent = BPF_CORE_READ(dentry, d_parent);
			if (!dentry_parent) {
				path_event->err = 1;
				BPF_PRINT("Error obtaining dentry_parent.");
				break;
			}
			
			struct dentry* dentry_grandparent = NULL;
			dentry_grandparent = BPF_CORE_READ(dentry_parent, d_parent);
			if (!dentry_grandparent) {
				path_event->err = 1;
				BPF_PRINT("Error obtaining dentry_grandparent.");
				break;
			}
			/* are parent and grandparent the same? If yes, then root is hit! */
			if (dentry_grandparent == dentry_parent) {
				BPF_PRINT("Path walk completed, bailing out...!");
				break;
			}
		  	/* this corresponds to: dentry = dentry_parent */ 
			if (0 != (bpf_probe_read_kernel(&dentry, sizeof(dentry), &dentry_parent))) { 
				path_event->err = 1;
				BPF_PRINT("Error copying dentry_parent to dentry");
				break;
			}
		}//end path loop
	/* send the path_metrics struct up to userland */
	bpf_ringbuf_submit(path_event, 0);
	}//end fd loop
	return 0;
}

