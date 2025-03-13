
#ifndef __NFS4_BYTE_PICKER
#define __NFS4_BYTE_PICKER

#define TASK_COMM_LEN 16
#define UNX_MAXNODENAME 64 /* /include/linux/sunrpc/auth.h --> /include/uapi/linux/utsname.h */

struct nfs4_rpc_metrics {
	__u64 tsp_xmit_start;
	__u64 tsp_xmit_end;
    
	char cmd_name[TASK_COMM_LEN];
    
	__u32 cpu;
    
	pid_t pid;
    pid_t tgid;
    
	pid_t rpc_task_owner_pid;
    __u32 rpc_task_owner_uid;
	__u32 rpc_task_owner_gid;
	
	__u32 uid;
    __u32 gid;
    __u64 cgid;
    
	__u64 xid_call;
	__u64 xid_rply;
    
	__u32 xprt_protocol;
    
	char protocolname[8];
    __u32 protocol_number;
    __u32 protocol_version;
	
	char servername[UNX_MAXNODENAME+1];
    char serverport[8];
    char server_ip_addr[48];
    
	char clientname[UNX_MAXNODENAME+1];
    __u32 rpc_client_id;

    size_t rcvd_bytes;
    size_t total_bytes_sent;
	__u8   first_round; /* check if we've been in xprt_transmit with the same xid before */
};

#endif /*__NFS4_BYTE_PICKER*/

