#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <signal.h>

#include "nfs4_byte_picker.h"
#include "nfs4_byte_picker.skel.h"

#define HOST_NAME_MAX 64 


static pid_t rqstd_pid  = 0;
static uid_t rqstd_uid  = 0;
static __u8  set_debug  = 0;
static volatile sig_atomic_t keep_running = 1;

static char hostname[HOST_NAME_MAX] = "null";
static bool file = false;
static FILE* f_desc = NULL;

static __u16 char_cnt = 0;

static size_t compose_out_filename(char* date_time_buf, size_t len) {

	time_t t = time(NULL);
	struct tm* tm = localtime(&t);
	size_t ret = strftime(&date_time_buf[len], sizeof(date_time_buf) - len, "%d-%m-%Y_%H-%M-%S", tm );
	return ret;
}



//-----------------------------arg parsing-------------------------------

const char argp_program_doc[] =
"Collect bytes sent and received via NFSv4+ by a process or user.\n"
"\n"
"USAGE: nfs4_byte_picker [-h] [-p PID] [-u UID] [-d DEBUG]\n"
"NOTE: Do only use one option at a time!\n"
"\n"
"EXAMPLES:\n"
"    ./nfs4_byte_picker           # trace all NFSv4+ calls\n"
"    ./nfs4_byte_picker -p 181    # only trace PID 181\n"
"    ./nfs4_byte_picker -u 1000   # only trace UID 1000\n"
"    ./nfs4_byte_picker -d DEBUG  # enable bpf_printk debug (call 'cat /sys/kernel/tracing/trace_pipe' to view debug output)\n"
"	 ./nfs4_byte_picker -f        # write trace output to /var/log/\n"
"";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "uid", 'u', "UID", 0, "User ID to trace", 0 },
	{ "debug", 'd', "DEBUG", 0, "Enable bpf_printk debug", 0 },
	{"file", 'f', NULL, 0, "write trace to /var/log/", 0},
	{},
};

static error_t parse_arg(int opt, char *arg, struct argp_state *state)
{
	static int pos_args;
	long int pid, uid;

	switch (opt) {
	case 'd':
		set_debug = 1;
		break;
	case 'h':
		argp_usage(state);
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		rqstd_pid  = pid;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno || uid < 0) {
			fprintf(stderr, "Invalid UID %s\n", arg);
			argp_usage(state);
		}
		rqstd_uid  = uid;
		break;
	case 'f':
		file = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

//---------------unlock memory--------------------------------------

static void bump_memlock_rlimit(void)
{
        struct rlimit rlim_new = {
                .rlim_cur       = RLIM_INFINITY,
                .rlim_max       = RLIM_INFINITY,
        };

        if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
                fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
                exit(1);
        }
}

//----------------------------signalling-------------------------

static void sig_int(int signo)
{
	printf("\nReceived signal: %d\n", signo);
	if (signo == 2) {
		keep_running = 0;
	}
}

//---------------------------handle each event---------------------------------

int handle_event(void* ctx, void* data, size_t data_sz)
{
	
	static char buff[1024] = {};    /* final formatted output buffer*/
	struct nfs4_rpc_metrics* rpc_metrics = NULL;

	rpc_metrics = (struct nfs4_rpc_metrics*)data;
	if (!rpc_metrics) {
		perror("rpc_metrics is NULL");
		return 1;
	}
	
	char xprt_prot[5];
	if (rpc_metrics->xprt_protocol == 6) {
		sprintf(xprt_prot, "%s", "TCP");
	}
	else {
		sprintf(xprt_prot, "%u", rpc_metrics->xprt_protocol);
	}
	


    char_cnt = snprintf(buff, sizeof(buff), "\{\"host\": \"%s\", \"cmd\": \"%s\", \"timestp_xmit_start[us]\": %llu, \"timestp_xmit_end[us]\": %llu, \"cpu\": %u, \"PID\": %u, \"TGID\": %u, \"UID\": %u, \"GID\": %u, \"cgroup_id\": %llu, "
                                            "\"rpc_task_owner_pid\": %u, \"rpc_task_owner_uid\": %u, \"rpc_task_owner_gid\": %u, \"xid_call\": %llu, \"xid_rply\": %llu, \"xprt_protocol\": \"%s\", \"protocol_name\": \"%s\", "
                                            "\"protocol_number\": %u, \"protocol_version\": %u, \"server_name\": \"%s\", \"server_port\": %s, \"server_ip_addr\": \"%s\", \"client_name\": \"%s\", "
                                            "\"rpc_client_id\": %u, \"bytes_sent\": %lu, \"bytes_rcvd\": %lu}\n",
						hostname,
						rpc_metrics->cmd_name,
						rpc_metrics->tsp_xmit_start,
					    rpc_metrics->tsp_xmit_end,	
						rpc_metrics->cpu,
						rpc_metrics->pid,
						rpc_metrics->tgid,
						rpc_metrics->uid,
						rpc_metrics->gid,
						rpc_metrics->cgid,
                        rpc_metrics->rpc_task_owner_pid,
                        rpc_metrics->rpc_task_owner_uid,
						rpc_metrics->rpc_task_owner_gid,
						rpc_metrics->xid_call,
						rpc_metrics->xid_rply,
                        xprt_prot,
                        rpc_metrics->protocolname,
                        rpc_metrics->protocol_number,
                        rpc_metrics->protocol_version,
						rpc_metrics->servername,
                        rpc_metrics->serverport,
                        rpc_metrics->server_ip_addr,
                        rpc_metrics->clientname,
                        rpc_metrics->rpc_client_id,
                        rpc_metrics->total_bytes_sent,
						rpc_metrics->rcvd_bytes
                        );


    if (char_cnt <= 0) {
        char_cnt = 0;
        return 1;
    }
	if (file) {
    	fprintf(f_desc, "%s", buff);
	}
	else {
		printf("%s", buff);
	}
	char_cnt = 0;
	return 0;
}


//------------------------------------main------------------------------------------

int main(int argc, char** argv)
{
	int err;
	bump_memlock_rlimit();

	static const struct argp argp = { 
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };  
    
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        perror("argparse");
		return err;	
	}
	
	struct ring_buffer* ring_buff = NULL;
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	/* in case of error hostname stays "null" */
	gethostname(hostname, HOST_NAME_MAX);
	
	if (file) {
		char date_time[64] = "/var/log/bpf_nfs4_byte_picker_";
		size_t len = strlen(date_time);
		size_t ret;
		if (0 > (ret = compose_out_filename(date_time, len))) {
			perror("out_filename");
			return 1;
		}
		
		char* file = date_time;

		if (NULL == (f_desc = fopen(file, "a"))) {
			perror("Could not open file for appending." );
			return EXIT_FAILURE;
		}
	}
    
	struct nfs4_byte_picker* skel = nfs4_byte_picker__open();
    if (!skel) {
        perror("bpf_skel_open failed!");
        return EXIT_FAILURE;
     }   

	err = nfs4_byte_picker__load(skel);
	if (err) {
        perror("bpf_skel_load failed!");
        goto cleanup;
    }   

	skel->bss->rqst_pid  = rqstd_pid;
	skel->bss->rqst_uid  = rqstd_uid;
	skel->bss->set_debug = set_debug;

	err = nfs4_byte_picker__attach(skel);
	if (err) {
        perror("bpf_skel_attach failed!");
        goto cleanup;
     }

	if (NULL == (ring_buff = ring_buffer__new(bpf_map__fd(skel->maps.ring_events), handle_event, NULL, NULL))) {
		perror("ring_buffer is NULL...");
		goto cleanup;

	}
	printf("Kprobe 'nfs4_byte_picker' attached to kernel hooks!\n");
	
	while(keep_running) 
	{
		
		err = ring_buffer__poll(ring_buff, 100); /* timeout in ms */ 
			
		/* Ctrl-C will cause -EINTR */
 		if (err == -EINTR) {
 			perror("ring_buffer_poll");
			err = 0;
 			break;
 		}
 		if (err < 0) {
 			perror("ring_buffer_poll");
			break;
 		}
	}// end while
	
cleanup:
	nfs4_byte_picker__destroy(skel);
	if (ring_buff)
		ring_buffer__free(ring_buff);
	if (file)
		fclose(f_desc);
	printf("Cleanup....done!\nBye :)\n");
	return err;
}


