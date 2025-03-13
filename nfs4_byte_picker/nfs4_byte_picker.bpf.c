#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "nfs4_byte_picker.h"

char LICENSE[] SEC("license") = "GPL";

pid_t rqst_pid  = 0;
uid_t rqst_uid  = 0;
__u8  set_debug = 0;

#define BPF_PRINT(...)               \
    do {                                  \
        if (set_debug)                    \
            bpf_printk(__VA_ARGS__); \
    	else							  \
			do {} while (0);			  \
	} while (0)


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct nfs4_rpc_metrics);
}  metrics_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_events SEC(".maps");



//------------------------This is called 2nd--------------------------------------------

/*
 * this tracepoint is found in 
 * '/net/sunrpc/xprt.c' 
 * in function:
 * 'static int xprt_request_transmit(struct rpc_rqst *req, struct rpc_task *snd_task)'
 *
 * */
SEC("raw_tracepoint/xprt_transmit")
int rtp__xprt_transmit(struct bpf_raw_tracepoint_args* ctx) 
{

	BPF_PRINT("This is: %s",__func__);
	
	struct rpc_rqst* rpc_req = NULL;
    rpc_req = (struct rpc_rqst*)ctx->args[0];
    if (!rpc_req) {
        BPF_PRINT("rpc_req is NULL!");
        return 0;
    }
	
	/* obtain rpc_task_owner's UID/GID/PID */
    struct rpc_cred *cred = NULL;
    kgid_t tsk_gid; 
	__u32 tsk_owner_gid = 0;
	pid_t tsk_owner_pid = 0;
	__u32 tsk_owner_uid = 0;
    if (0 != (bpf_probe_read_kernel(&cred, sizeof(cred), &rpc_req->rq_cred))) {
        goto try_pid_filter;
    }
    if (!cred) {
        goto try_pid_filter;
    }
    kuid_t tsk_uid = BPF_CORE_READ(cred, cr_cred, fsuid);
    if (0 != (bpf_probe_read_kernel(&tsk_owner_uid, sizeof(tsk_owner_uid), &tsk_uid.val))) {
        goto try_pid_filter;
    }
    BPF_PRINT("tsk_owner_uid: %u", tsk_owner_uid);
	
	 /* filter by tsk_owner_uid: */
    if (rqst_uid && rqst_uid != tsk_owner_uid) {
        return 0;
    }
	
try_pid_filter:

	/* obtain rpc_task owner's PID */
    tsk_owner_pid = BPF_CORE_READ(rpc_req, rq_task, tk_owner);
    if (tsk_owner_pid <= 0) {
		BPF_PRINT("ERROR obtaining rpc_tsk_owner_pid");
		goto no_filter;
	} 
	BPF_PRINT("rpc_tsk_owner_pid: %u", tsk_owner_pid);
	
	/* filter by task_owner_pid */
	if (rqst_pid && rqst_pid != tsk_owner_pid) {
        return 0;
    }

no_filter:

	/* once we're here we grab the owner's GID too */
	tsk_gid = BPF_CORE_READ(cred, cr_cred, fsgid);
	if (0 == (bpf_probe_read_kernel(&tsk_owner_gid, sizeof(tsk_owner_gid), &tsk_gid.val))) {
		BPF_PRINT("tsk_owner_gid: %u", tsk_owner_gid);
	}

	/* obtain rpc_client */
    struct rpc_clnt* rpc_clnt = NULL;
    if (NULL == (rpc_clnt = BPF_CORE_READ(rpc_req, rq_task, tk_client))) {
        BPF_PRINT("rpc_clnt_p is null");
    }
    
	/* verify that rpc program is NFS (100003) version 4 */
	__u32 prot_number = 0;
    if (0 == (bpf_probe_read_kernel(&prot_number, sizeof(prot_number), &rpc_clnt->cl_prog))) {
        BPF_PRINT("rpc prot_num: %u", prot_number);
    }
 	 __u32 prot_version = 0;
    if (0 == (bpf_probe_read_kernel(&prot_version, sizeof(prot_version), &rpc_clnt->cl_vers))) {
        BPF_PRINT("rpc prot_num: %u", prot_version);
    }
	if (prot_number != 100003 || prot_version < 4) {
		BPF_PRINT("RPC call does not carry NFSv4+ payload. Skipped!");
		return 0;
	}
	
	/* xid is key in the metrics_map */   
	__be32 xid = 0; 
    if (0 > (xid = BPF_CORE_READ(rpc_req, rq_xid))) {
        BPF_PRINT("ERROR obtaining xid.");
		return 0;
	}
    BPF_PRINT("xid_call: %lu", bpf_ntohl(xid));

	/* if key xid is in map, start collecting goodies, else bail out */
    struct nfs4_rpc_metrics* rpc_metrics = NULL;
	struct nfs4_rpc_metrics rpc_metrics_map;
    rpc_metrics = bpf_map_lookup_elem(&metrics_map, &xid);
    if (!rpc_metrics) {
    	BPF_PRINT("No rpc_metrics in map for key: %u", xid);
        BPF_PRINT("");
		return 0;
    }

	/* check if we're in here the first time for a xmission with given xid, 
	 * else skip the next block (for efficiency) 
	 */
    if (rpc_metrics->first_round)  {
		rpc_metrics->first_round = 0;	
		rpc_metrics->pid = bpf_get_current_pid_tgid();
		rpc_metrics->rpc_task_owner_pid = tsk_owner_pid;
		rpc_metrics->rpc_task_owner_uid = tsk_owner_uid;
		rpc_metrics->rpc_task_owner_gid = tsk_owner_gid;
		rpc_metrics->tgid = bpf_get_current_pid_tgid() >> 32;
		rpc_metrics->uid = bpf_get_current_uid_gid();
		rpc_metrics->gid = bpf_get_current_uid_gid() >> 32;
		rpc_metrics->cgid = bpf_get_current_cgroup_id();
		rpc_metrics->cpu = bpf_get_smp_processor_id();
		BPF_PRINT("cpu: %u", rpc_metrics->cpu);
		
		if (0 == (bpf_get_current_comm(rpc_metrics->cmd_name, sizeof(rpc_metrics->cmd_name)))) {
		} else { bpf_probe_read_kernel_str(rpc_metrics->cmd_name, sizeof(rpc_metrics->cmd_name), "null"); }
	}

    /* collect amount of bytes every time we're here and update the previous value in struct rpc_metrics */
    size_t bytes_sent = 0;
    bytes_sent = BPF_CORE_READ(rpc_req, rq_xmit_bytes_sent);
    if (0 < bytes_sent) {
        BPF_PRINT("total_bytes_sent: %u", bytes_sent);
        rpc_metrics->total_bytes_sent = bytes_sent;
    }

	__builtin_memcpy(&rpc_metrics_map, rpc_metrics, sizeof(struct nfs4_rpc_metrics));
    
	s8 ret = 0;
    if(0 > (ret = bpf_map_update_elem(&metrics_map, &xid, &rpc_metrics_map, BPF_ANY))) {
        BPF_PRINT("ERROR: updating map value for key: %u failed!", xid);
    }

    BPF_PRINT("");

    return 0;
}

//----------------------------this is called 1st---------------

SEC("kprobe/xs_tcp_send_request")
int kp__xs_tcp_send_request(struct pt_regs *ctx) {
	

	BPF_PRINT("This is: %s",__func__);
   
     /* obtain rpc_request from args */
    struct rpc_rqst* req = NULL;
	req = (struct rpc_rqst *) PT_REGS_PARM1(ctx);
    if (!req) {
        BPF_PRINT("rpc_req is NULL!");
        return 0;
    }

/* NOTE: tried to write goto label error handling (instead of nested if statements) in the following two blocks
 * but the bpf verifier rejected my approach at this very position...!
 */	
	/* obtain rpc_task_owner's UID */
    struct rpc_cred *cred = NULL;
    __u32 tsk_owner_uid = 0;
    if (0 == (bpf_probe_read_kernel(&cred, sizeof(cred), &req->rq_cred))) {
		kuid_t tsk_uid = BPF_CORE_READ(cred, cr_cred, fsuid);
		if (0 == (bpf_probe_read_kernel(&tsk_owner_uid, sizeof(tsk_owner_uid), &tsk_uid.val))) {
			BPF_PRINT("tsk_owner_uid: %u", tsk_owner_uid);
			
			/* filter by tsk_owner_uid */    
			if (rqst_uid && rqst_uid != tsk_owner_uid) {
				return 0;
			}   
		}
	}

	/* obtain rpc_task_owner's PID */
	pid_t tsk_owner_pid = 0;
	tsk_owner_pid = BPF_CORE_READ(req, rq_task, tk_owner);
    if (tsk_owner_pid > 0) {
		BPF_PRINT("rpc_tsk_owner_pid: %u", tsk_owner_pid);
		
		/* filter by task_owner_pid */
		if (rqst_pid && rqst_pid != tsk_owner_pid) {
			return 0;
		}
	}

	/* obtain rpc_client */
    struct rpc_clnt* rpc_clnt = NULL;
	if (NULL == (rpc_clnt = BPF_CORE_READ(req, rq_task, tk_client))) {
        BPF_PRINT("rpc_clnt_p is null");
        return 0;
    }
	
	/* verify that rpc program is NFS (100003) version 4 */
	__u32 prot_number = 0;
    if (0 == (bpf_probe_read_kernel(&prot_number, sizeof(prot_number), &rpc_clnt->cl_prog))) {
        BPF_PRINT("rpc prot_num: %u", prot_number);
    }
 	 __u32 prot_version = 0;
    if (0 == (bpf_probe_read_kernel(&prot_version, sizeof(prot_version), &rpc_clnt->cl_vers))) {
        BPF_PRINT("rpc prot_num: %u", prot_version);
    }
	if (prot_number != 100003 || prot_version < 4) {
		BPF_PRINT("RPC call does not carry NFSv4+ payload. Skipped!");
		return 0;
	}
	
	/* xid is key in the metrics_map */
	__be32 xid = 0; 
    if (0 > (xid = BPF_CORE_READ(req, rq_xid))) {
        BPF_PRINT("ERROR obtaining xid.");
		return 0;
	}
    BPF_PRINT("xid_call: %lu", bpf_ntohl(xid));
    
	/* if key xid is not in map, create an entry and start collecting goodies */
	s8 ret = 0;
	struct nfs4_rpc_metrics* rpc_metrics = NULL;
	struct nfs4_rpc_metrics rpc_metrics_map;
    rpc_metrics = bpf_map_lookup_elem(&metrics_map, &xid);
    if (rpc_metrics) {
		BPF_PRINT("Bailing out. Metrics_map has entry for key %lu", xid);
		return 0;
	}
	else {
        ret = 0;
        if (0 > (ret = bpf_map_update_elem(&metrics_map, &xid, &rpc_metrics_map, BPF_NOEXIST))) {
            BPF_PRINT("ERROR: updating map value for key: %u failed!", xid);
            return 0;
        }
        rpc_metrics = bpf_map_lookup_elem(&metrics_map, &xid);
		if (!rpc_metrics) {
            BPF_PRINT("Failed creating map entry for key: %u", xid);
            return 0;
        }
		rpc_metrics->first_round = 1;
	}
	rpc_metrics->xid_call = bpf_ntohl(xid);
   	rpc_metrics->tsp_xmit_start = bpf_ktime_get_ns() / 1000;

	/* obtain transport */
    struct rpc_xprt* xprt = NULL;
	if (NULL == (xprt = BPF_CORE_READ(req, rq_xprt))) {
        BPF_PRINT("rpc_xprt_p: is null");
        return 0;
    }
	
	/* save moment to declare these in advance */
   	char* serv_name_p = NULL;
	char* srv_ip_p = NULL;
  
    /* obtain client node_name */
    if (0 != (bpf_probe_read_kernel(&rpc_metrics->clientname, sizeof(rpc_metrics->clientname), &rpc_clnt->cl_nodename))) {
        bpf_probe_read_kernel_str(&rpc_metrics->clientname, sizeof(rpc_metrics->clientname), "null");
    }
	BPF_PRINT("clientname: %s", rpc_metrics->clientname);

    /* rpc_cl_clid */
    if(0 == (bpf_probe_read_kernel(&rpc_metrics->rpc_client_id, sizeof(rpc_metrics->rpc_client_id), &rpc_clnt->cl_clid))) {
        BPF_PRINT("rpc_client_id: %u", rpc_metrics->rpc_client_id);
    }

    /* obtain  protocol_name and number */
    const struct rpc_program* proc = NULL;
    if (NULL == (proc = BPF_CORE_READ(rpc_clnt, cl_program))) {
        BPF_PRINT("rpc_proc_p is null.");
        goto server_metrics;
    }
    char* prot_p = NULL;
    if (0 == (bpf_probe_read_kernel(&prot_p, sizeof(prot_p), &proc->name))) {
        BPF_PRINT("rpc_prot_p: %p", prot_p);
    }
    if (prot_p != NULL) {
        if (0 < (bpf_probe_read_kernel_str(&rpc_metrics->protocolname, sizeof(rpc_metrics->protocolname), prot_p))) {
            BPF_PRINT("rpc_clnt prot_name_str: %s", rpc_metrics->protocolname);
        }
    }
    else {
        bpf_probe_read_kernel_str(&rpc_metrics->protocolname, sizeof(rpc_metrics->protocolname), "null");
    }

	/* protocol number */
	rpc_metrics->protocol_number = prot_number;
    BPF_PRINT("rpc prot_num: %u", rpc_metrics->protocol_number);
    
	/* protocol version */
    rpc_metrics->protocol_version = prot_version;
    BPF_PRINT("rpc prot_num: %u", rpc_metrics->protocol_version);
    
server_metrics:
     
	/* obtain servername */
    if (0 == (bpf_probe_read_kernel(&serv_name_p, sizeof(serv_name_p), &xprt->servername))) {
 		BPF_PRINT("rpc_xprt srv_name_p: %p", serv_name_p);
    }
    if (serv_name_p != NULL) {
        if (0 < (bpf_probe_read_kernel_str(&rpc_metrics->servername, sizeof(rpc_metrics->servername), serv_name_p))) {
            BPF_PRINT("rpc_xprt srv_name_str: %s", rpc_metrics->servername);
        }
    }
    else {
        bpf_probe_read_kernel_str(&rpc_metrics->servername, sizeof(rpc_metrics->servername), "null");
    }
	
	/* server_ip_addr */	
	if (0 == (bpf_probe_read_kernel(&srv_ip_p, sizeof(srv_ip_p), &xprt->address_strings[RPC_DISPLAY_ADDR]))) {
           }
	if (srv_ip_p) {
		if (0 < (bpf_probe_read_kernel_str(&rpc_metrics->server_ip_addr, sizeof(rpc_metrics->server_ip_addr), srv_ip_p))) {
			BPF_PRINT("rpc_xprt server_ip_addr: %s", rpc_metrics->server_ip_addr );
		}
	}
    
	/* serverport */
    char* port_p = NULL;
    if (0 == (bpf_probe_read_kernel(&port_p, sizeof(port_p), &xprt->address_strings[RPC_DISPLAY_PORT]))) {
        BPF_PRINT("rpc_xprt port_p: %p", port_p);
    }
	if (port_p) {
    	if (0 < (bpf_probe_read_kernel_str(&rpc_metrics->serverport, sizeof(rpc_metrics->serverport), port_p))) {
        	BPF_PRINT("rpc_xprt serv_port_str: %s", rpc_metrics->serverport);
    	}
	}
    /* transport protocol */
    if (0 == (bpf_probe_read_kernel(&rpc_metrics->xprt_protocol, sizeof(rpc_metrics->xprt_protocol), &xprt->prot))) {
        BPF_PRINT("xprt protocol: %d", rpc_metrics->xprt_protocol);
    }
    
	__builtin_memcpy(&rpc_metrics_map, rpc_metrics, sizeof(struct nfs4_rpc_metrics));
	
	ret = 0;
    if(0 > (ret = bpf_map_update_elem(&metrics_map, &xid, &rpc_metrics_map, BPF_ANY))) {
        BPF_PRINT("ERROR: updating map value for key: %u failed!", xid);
    }
    BPF_PRINT("");

    return 0;
}

//----------------this is called 3rd------------------------

SEC("kprobe/xprt_complete_rqst")
int kp__xprt_complete_rqst(struct pt_regs* ctx) {

	BPF_PRINT("This is: %s", __func__);

    //obtain rpc task
	struct rpc_task* rpc_tsk = NULL;
    rpc_tsk =  (struct rpc_task*)PT_REGS_PARM1(ctx);
    if (!rpc_tsk) {
        BPF_PRINT("rpc_task is NULL!");
        return 0;
    }
	
	 struct rpc_clnt* rpc_clnt = NULL;

	//obtain rpc request
	struct rpc_rqst* rpc_req = NULL;
    rpc_req = BPF_CORE_READ(rpc_tsk, tk_rqstp);
    if (!rpc_req) {
        BPF_PRINT("rpc_req is NULL!");
        return 0;
    }
	
	// obtain rpc_task_owner's UID/GID
	struct rpc_cred *cred = NULL;
	pid_t tsk_owner_pid = 0;
	__u32 tsk_owner_uid = 0;
	if (0 != (bpf_probe_read_kernel(&cred, sizeof(cred), &rpc_req->rq_cred))) {
		goto try_pid_filter;
	}
	if (!cred) {
		goto try_pid_filter;
	}
	kuid_t tsk_uid = BPF_CORE_READ(cred, cr_cred, fsuid);
	if (0 != (bpf_probe_read_kernel(&tsk_owner_uid, sizeof(tsk_owner_uid), &tsk_uid.val))) {
		goto try_pid_filter;
	}
	BPF_PRINT("tsk_owner_uid: %u", tsk_owner_uid);
		
	/* filter by tsk_owner_uid  */   
    if (rqst_uid && rqst_uid != tsk_owner_uid) {
        return 0;
    }   
	
try_pid_filter:	
	
	/* obtain rpc_task_owner's PID */
       tsk_owner_pid = BPF_CORE_READ(rpc_tsk, tk_owner);
    if (tsk_owner_pid <= 0) {
        BPF_PRINT("ERROR obtaining rpc_tsk_owner_pid");
        goto no_filter;
    }
    BPF_PRINT("rpc_tsk_owner_pid: %u", tsk_owner_pid);
	
	/* filter by task_owner_pid */
	if (rqst_pid && rqst_pid != tsk_owner_pid) {
        return 0;
    }

no_filter:

	/* obtain rpc_client */
    if (NULL == (rpc_clnt = BPF_CORE_READ(rpc_tsk, tk_client))) {
        BPF_PRINT("rpc_clnt_p is null");
        return 0;
    }
	/* verify that rpc program is NFS (100003) version 4+ */ 
	__u32 prot_number = 0;
    if (0 == (bpf_probe_read_kernel(&prot_number, sizeof(prot_number), &rpc_clnt->cl_prog))) {
        BPF_PRINT("rpc prot_num: %u", prot_number);
    }
 	 __u32 prot_version = 0;
    if (0 == (bpf_probe_read_kernel(&prot_version, sizeof(prot_version), &rpc_clnt->cl_vers))) {
        BPF_PRINT("rpc prot_num: %u", prot_version);
    }
	if (prot_number != 100003 || prot_version < 4) {
		BPF_PRINT("RPC call does not carry NFSv4+ payload. Skipped!");
		return 0;
	}

	// xid is key in the metrics_map   
	__be32 xid = 0; 
    if (0 > (xid = BPF_CORE_READ(rpc_req, rq_xid))) {
        BPF_PRINT("ERROR obtaining xid.");
		return 0;
	}
    BPF_PRINT("xid_rply: %lu", bpf_ntohl(xid));

	struct nfs4_rpc_metrics* rpc_metrics = NULL;
	struct nfs4_rpc_metrics rpc_metrics_map;
    rpc_metrics = bpf_map_lookup_elem(&metrics_map, &xid);
    if (!rpc_metrics) {
        BPF_PRINT("No rpc_metrics in map for key: %u", xid);
        return 0;
    }
	rpc_metrics->xid_rply = bpf_ntohl(xid);
	rpc_metrics->tsp_xmit_end = bpf_ktime_get_ns() / 1000;

	/* reserve some ring buffer space */
    struct nfs4_rpc_metrics* rpc_event = NULL;
    rpc_event = bpf_ringbuf_reserve(&ring_events, sizeof(*rpc_metrics), 0);
    if (!rpc_event) {
        BPF_PRINT(" ERROR: Ring_buffer mem could not be reserved.");
        return 0;
    }
    
	/* this is the main reason why we're here: the amount of bytes returned from NFSv4+ server*/
    int rcvd_bytes = 0;
    rpc_metrics->rcvd_bytes = (int)PT_REGS_PARM2(ctx);
    BPF_PRINT("rq_reply_bytes_recvd: %u", rpc_metrics->rcvd_bytes);

    size_t rq_xmit_bytes_sent = 0;
    if (0 < (rq_xmit_bytes_sent = BPF_CORE_READ(rpc_req, rq_xmit_bytes_sent))) {
        BPF_PRINT("rq_xmit_bytes_sent: %u", rq_xmit_bytes_sent);
    }

    __builtin_memcpy(rpc_event, rpc_metrics, sizeof(struct nfs4_rpc_metrics));
	
	/* send all collected metrics to userland */
    bpf_ringbuf_submit(rpc_event, 0);
	
	/* since we're done with the xmission tagged with xid we delete entry from metrics_map */
    bpf_map_delete_elem(&metrics_map, &xid);

	BPF_PRINT("rpc_event submitted, map entry of key: %u deleted", xid);
    BPF_PRINT("");
    return 0;
}
