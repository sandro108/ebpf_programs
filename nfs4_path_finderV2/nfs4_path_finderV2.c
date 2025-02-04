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

#include "nfs4_path_finderV2.h"
#include "nfs4_path_finderV2.skel.h"

#define DEBUG
#define HOST_NAME_MAX 64 

static pid_t rqstd_pid  = 0;
static uid_t rqstd_uid  = 0;
static __u64 rqstd_cgid = 0;
static __u8 set_debug   = 0;

static volatile sig_atomic_t keep_running = 1;

static char hostname[HOST_NAME_MAX] = "null";
static bool file = false;
static FILE* f_desc = NULL;

static size_t compose_out_filename(char* date_time_buf, size_t len) {

	time_t t = time(NULL);
	struct tm* tm = localtime(&t);
	size_t ret = strftime(&date_time_buf[len], sizeof(date_time_buf) - len, "%d-%m-%Y_%H-%M-%S", tm );
	return ret;
}



//-----------------------------arg parsing-------------------------------

const char argp_program_doc[] =
"Trace NFSv4 paths to open files and a bunch of other metrics of processes when scheduled.\n"
"\n"
"USAGE: ./nfs4_path_finderV2 [--help] | [-p PID] | [-u UID] | [-c CGROUP_ID] [-d DEBUG] [-f]\n"
"NOTE: Use -p|-u|-c options one at a time only!\n"
"\n"
"EXAMPLES:\n"
"    ./nfs4_path_finderV2           # trace paths with fs_type==nfs4\n"
"    ./nfs4_path_finderV2 -p 181    # only trace PID 181\n"
"    ./nfs4_path_finderV2 -u 1000   # only trace UID 1000\n"
"    ./nfs4_path_finderV2 -c 1234   # only trace cgroup with ID 1234\n"
"    ./nfs4_path_finderV2 -d DEBUG  # trace with debug output sent to /sys/kernel/tracing/trace_pipe\n"
"    ./nfs4_path_finderV2 -f        # write trace output to /var/log/\n"
"";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "uid", 'u', "UID", 0, "User ID to trace", 0 },
	{ "cgid", 'c', "CGROUP_ID", 0, "CGROUP ID to trace", 0 },
	{ "dbg", 'd', "DEBUG", 0, "trace with debug output", 0 },
		{ "file", 'f', NULL, 0, "write trace to /var/log/", 0 },
	{},
};

static error_t parse_arg(int opt, char *arg, struct argp_state *state)
{
	static int pos_args;
	long int pid, uid, cgid;

	switch (opt) {
	case 'h':
		argp_usage(state);
		break;
	case 'c':
		errno = 0;
		cgid = strtol(arg, NULL, 10);
		if (errno || cgid <= 0) {
			fprintf(stderr, "Invalid CGROUP_ID: %s\n", arg);
			argp_usage(state);
		}
		rqstd_cgid  = cgid;
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
	case 'd':
		set_debug = 1;
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
	
	struct path_metrics* path_event = NULL;

	path_event = (struct path_metrics*)data;	
	if (!path_event) {
		perror("path_event is NULL");
		return 1;
	}
	if (path_event->err != 0) {
		perror("path_event returned with error");
		return 1;
	}
	
	/* gather all array pointers into one array of char pointers */ 
	
	char* dir_entries[MAX_PATH_DEPTH * 2] = {
		path_event->dir_entry_0,
		path_event->dir_entry_1,
		path_event->dir_entry_2,
		path_event->dir_entry_3,
		path_event->dir_entry_4,
		path_event->dir_entry_5,
		path_event->dir_entry_6,
		path_event->dir_entry_7,
		path_event->dir_entry_8,
		path_event->dir_entry_9,
		path_event->dir_entry_10,
		path_event->dir_entry_11,
		path_event->dir_entry_12,
		path_event->dir_entry_13,
		path_event->dir_entry_14,
		path_event->dir_entry_15,
		path_event->dir_entry_16,
		path_event->dir_entry_17,
		path_event->dir_entry_18,
		path_event->dir_entry_19,
		path_event->dir_entry_20,
		path_event->dir_entry_21,
		path_event->dir_entry_22,
		path_event->dir_entry_23,
		path_event->dir_entry_24,
		path_event->dir_entry_25,
		path_event->dir_entry_26,
		path_event->dir_entry_27,
		path_event->dir_entry_28,
		path_event->dir_entry_29,
		path_event->dir_entry_30,
		path_event->dir_entry_31,
		path_event->dir_entry_32
	};
	
	char buff[512+4096];    /* final formatted output buffer*/
	__u16 cnt = 0;
	__u16 char_cnt = 0;

	while (strncmp(dir_entries[cnt], "0", 1) != 0) {
		++cnt;
	}
	
		
	int entry_len = 0;
	int pos = 0;
	char path[4096] = {};
	
	/* now assemble full path and save it to path buffer as string */ 

	for (int i = cnt-1; i >= 0; i--) {
		if (!dir_entries[i]) {
			printf("dir_entries[%u] is a NULL entry.", i);
			return 0;
		} 
		int len = strlen(dir_entries[i]);
		if (0 == strncmp(dir_entries[i], "/", 1)) 
			 snprintf(&path[pos], len + 2, "%s", dir_entries[i]);
		else 
			entry_len =	snprintf(&path[pos], len + 2, "/%s", dir_entries[i]);
		if (entry_len < 0) {
			break;
		}
		pos += entry_len;

	}
	
	/* this is executed after the full path is assembled */ 
	char_cnt = snprintf(buff, sizeof(buff), "\{\"host\": \"%s\", \"cmd\": \"%s\", \"timestp[us]\":%llu, \"cpu\": %u, \"PID\": %u, \"TGID\": %u, \"UID\": %u, \"GID\": %u, \"cgroup_id\": %llu, \"fd\": %u, \"path\":\"%s\"}\n", 
												hostname,
												path_event->cmd_name, 
												path_event->time_stp,
												path_event->cpu, 
												path_event->pid,
												path_event->tgid,
												path_event->uid,
												path_event->gid,
												path_event->cgid,
												path_event->fd,
												path);

	if (char_cnt <= 0) {
		perror("Path metrics could not be written into JSON format.");	
		return 1;		
	}
	if (file) {
		fprintf(f_desc, "%s", buff);
	}
	else {
		printf("%s", buff);

	}
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
		char date_time[64] = "/var/log/bpf_nfs4_path_finderV2_";
		size_t len = strlen(date_time);
		size_t ret;
		if (0 > (ret = compose_out_filename(date_time, len))) {
			perror("out_filename");
			return 1;
		}
		
		char* file = date_time;

		if (NULL == (f_desc = fopen(file, "a"))) {
			perror("Could not open file for appending." );
			return 1;
		}
	}
    struct nfs4_path_finderV2* skel = nfs4_path_finderV2__open();
    if (!skel) {
        perror("bpf_skel_open failed!");
        return 1;
     }   

	err = nfs4_path_finderV2__load(skel);
	if (err) {
        perror("bpf_skel_load failed!");
        goto cleanup;
    }   

	skel->bss->own_pid   = getpid();
	skel->bss->rqst_pid  = rqstd_pid;
	skel->bss->rqst_uid  = rqstd_uid;
	skel->bss->rqst_cgid = rqstd_cgid;
	skel->bss->set_debug = set_debug;
	
	err = nfs4_path_finderV2__attach(skel);
	if (err) {
        perror("bpf_skel_attach failed!");
        goto cleanup;
     }

	if (NULL == (ring_buff = ring_buffer__new(bpf_map__fd(skel->maps.ring_events), handle_event, NULL, NULL))) {
		perror("ring_buffer is NULL...");
		goto cleanup;

	}
	printf("Kprobe 'nfs4_path_finderV2' attached to kernel hook!\n");
	
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
	nfs4_path_finderV2__destroy(skel);
	if (ring_buff)
		ring_buffer__free(ring_buff);
	if (file)
		fclose(f_desc);
	printf("Cleanup....done!\nBye :)\n");
	return err;
}

