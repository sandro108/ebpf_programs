
#ifndef __NFS4_PATH_FINDER_V2
#define __NFS4_PATH_FINDER_V2

#define MSG_TYPE_FIRST_ENTRY 1
#define MSG_TYPE_DIR_ENTRIES 2
#define MSG_TYPE_ROOT_ENTRY 3

#define NAME_MAX 255 /* as defined in include/uapi/linux/limits.h */
#define MAX_FDS 13 /*temporary limit due to verifier's path verification limit of 1E6 instructions */
#define MAX_PATH_DEPTH 32 /* number of dentries in a path, self defined. Chars in path must not exceed 4096 incl. '\0' */
#define TASK_COMM_LEN 16

struct path_metrics {
	
	char cmd_name[TASK_COMM_LEN];
	__u64 time_stp;
	__u32 cpu;
	pid_t pid;
	pid_t tgid;
	__u32 uid;
	__u32 gid;
	__u16 fd;
	__u64 cgid;
	char dir_entry_0[NAME_MAX];
	char dir_entry_1[NAME_MAX];	
	char dir_entry_2[NAME_MAX];
	char dir_entry_3[NAME_MAX];	
	char dir_entry_4[NAME_MAX];
	char dir_entry_5[NAME_MAX];
	char dir_entry_6[NAME_MAX];
	char dir_entry_7[NAME_MAX];
	char dir_entry_8[NAME_MAX];
	char dir_entry_9[NAME_MAX];
	char dir_entry_10[NAME_MAX];
	char dir_entry_11[NAME_MAX];
	char dir_entry_12[NAME_MAX];
	char dir_entry_13[NAME_MAX];
	char dir_entry_14[NAME_MAX];
	char dir_entry_15[NAME_MAX];
	char dir_entry_16[NAME_MAX];
	char dir_entry_17[NAME_MAX];
	char dir_entry_18[NAME_MAX];	
	char dir_entry_19[NAME_MAX];
	char dir_entry_20[NAME_MAX];	
	char dir_entry_21[NAME_MAX];
	char dir_entry_22[NAME_MAX];
	char dir_entry_23[NAME_MAX];
	char dir_entry_24[NAME_MAX];
	char dir_entry_25[NAME_MAX];
	char dir_entry_26[NAME_MAX];
	char dir_entry_27[NAME_MAX];
	char dir_entry_28[NAME_MAX];
	char dir_entry_29[NAME_MAX];
	char dir_entry_30[NAME_MAX];
	char dir_entry_31[NAME_MAX];
	char dir_entry_32[NAME_MAX];
	__u8  err;	
}; 


#endif /* __NFS4_PATH_FINDER_V2 */



