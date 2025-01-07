#include <argp.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <signal.h>

#include "socket_collector.h"
#include "socket_collector.skel.h"

#define HOST_NAME_MAX 64 

static pid_t rqstd_pid  = 0;
static uid_t rqstd_uid  = 0;
static __u8  set_debug  = 0;
static volatile sig_atomic_t keep_running = 1;

static char hostname[HOST_NAME_MAX] = "null";
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
"Collect socket information of a process or user.\n"
"\n"
"USAGE: socket_collector [-h] [-p PID] [-u UID] [-d DEBUG]\n"
"NOTE: Do only use one option at a time!\n"
"\n"
"EXAMPLES:\n"
"    ./socket_collector           # trace all processes and users\n"
"    ./socket_collector -p 181    # only trace PID 181\n"
"    ./socket_collector -u 1000   # only trace UID 1000\n"
"    ./socket_collector -d DEBUG  # enable bpf_printk debug (call 'cat /sys/kernel/tracing/trace_pipe' to view debug output)\n"
"";

static const struct argp_option opts[] = {
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
    { "pid", 'p', "PID", 0, "Process ID to trace", 0 },
    { "uid", 'u', "UID", 0, "User ID to trace", 0 },
    { "debug", 'd', "DEBUG", 0, "Enable bpf_printk debug", 0 },
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

int handle_sock_event(void* ctx, void* data, size_t data_sz) {
//	printf("Start ");	
	char sock_buff[512] = {};
	char ip_daddr_buff[64] = "null";
	char ip_saddr_buff[64] = "null";


	const struct sock_metrics* sock_event = NULL;
	sock_event = data;
	if(!sock_event) {
		perror("Error:");
		return 1;
	}
	
	if (sock_event->err != 0) {
		perror("Error:");
		return 1;
	}
	
	__u16 dst_port = sock_event->dst_port;
	__u16 src_port = sock_event->src_port;
	__u32 portpair = sock_event->portpair;
	__u16 s_p = portpair >> 16;
	__u16 d_p = portpair;

	char* sock_type;
	char* sock_state;
	char* sock_family;
	char type[3] = {};
    char state[3] = {};

	switch(sock_event->sock_type) {
		case 1:
			sock_type = "SOCK_STREAM";
				switch(sock_event->sock_state) {
					case 1:
						sock_state = "TCP_ESTABLISHED";
						break;
					case 7:
						sock_state = "TCP_CLOSE";
						break;
					case 10:
						sock_state = "TCP_LISTEN";
						break;
					default:
						sock_state = "no state yet";
						break;
				}
			break;
		case 2:
			sock_type = "SOCK_DGRAM";
			sock_state = "-";
			break;
			/* tbc */
		default:
            snprintf(type, sizeof(type), "%u",  sock_event->sock_type);
            sock_type = type;

		    snprintf(state, sizeof(state), "%u",  sock_event->sock_state);
            sock_state = state;
			break;
	}
	


	/*
	 * defined in  /include/net/tcp_states.h 
TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,
	TCP_NEW_SYN_RECV,
*/
/* as defined in /include/uapi/linux/net.h */
//  SS_FREE = 0,			/* not allocated		*/
//	SS_UNCONNECTED,			/* unconnected to any socket	*/
//	SS_CONNECTING,			/* in process of connecting	*/
//	SS_CONNECTED,			/* connected to socket		*/
//	SS_DISCONNECTING		/* in process of disconnecting	*/
	

	if (sock_event->sock_family == AF_UNIX) {

		sock_family = "AF_UNIX";
		char state[3] = {};

		switch(sock_event->sock_state) {
			case 1:
				sock_state = "UNCONNECTED";
				break;
			case 2:
				sock_state = "CONNECTING";
				break;
			case 3:
				sock_state = "CONNECTED";
				break;
			default:
				snprintf(state, sizeof(state), "%u",  sock_event->sock_state);
				sock_state = state;
				break;
		}
	}
	else if (sock_event->sock_family == AF_INET) {

		__u32 src_addr = sock_event->addr_pair >> 32;
		__u32 dst_addr = sock_event->addr_pair;
		__u8 octet;
		int idx = 0;
		int cnt = 0;

		if (dst_addr != 0) {
			octet = dst_addr;
			for (int i = 0; i < 3; i++) {
				dst_addr >>= 8;
				idx = snprintf(&ip_daddr_buff[cnt], sizeof(ip_daddr_buff), "%u.", octet);
				cnt += idx;
				if (idx < 0) { break;}
				octet = dst_addr;
			}
			snprintf(&ip_daddr_buff[cnt], sizeof(ip_daddr_buff) - cnt + 1, "%u", octet);
		}
			
		octet = src_addr;
		idx = 0;
		cnt = 0;
		for (int i = 0; i < 3; i++) {
			src_addr = src_addr >> 8;
			idx = snprintf(&ip_saddr_buff[cnt], sizeof(ip_saddr_buff), "%u.", octet);
			cnt += idx;
			if (idx < 0) {break;}
			octet = src_addr;
		}
		snprintf(&ip_saddr_buff[cnt],sizeof(ip_saddr_buff) - cnt + 1, "%u", octet);
		
		sock_family = "AF_INET";
	
	}

	else if (sock_event->sock_family == AF_INET6) {

	


		snprintf(ip_daddr_buff, sizeof(ip_daddr_buff), "%x:%x:%x:%x:%x:%x:%x:%x", 
												sock_event->ipv6_daddr[0],
												sock_event->ipv6_daddr[1],
												sock_event->ipv6_daddr[2],
												sock_event->ipv6_daddr[3],
												sock_event->ipv6_daddr[4],
												sock_event->ipv6_daddr[5],
												sock_event->ipv6_daddr[6],
												sock_event->ipv6_daddr[7]
												);
	
		snprintf(ip_saddr_buff, sizeof(ip_saddr_buff), "%x:%x:%x:%x:%x:%x:%x:%x", 
												sock_event->ipv6_saddr[0],
												sock_event->ipv6_saddr[1],
												sock_event->ipv6_saddr[2],
												sock_event->ipv6_saddr[3],
												sock_event->ipv6_saddr[4],
												sock_event->ipv6_saddr[5],
												sock_event->ipv6_saddr[6],
												sock_event->ipv6_saddr[7]
												);
	
		sock_family = "AF_INET6";


	}
	char_cnt = snprintf(sock_buff, sizeof(sock_buff), "{\"host\": \"%s\", \"cmd\": \"%s\", \"time_stp\": %llu, \"PID\": %u, \"TGID\": %u, \"UID\": %u, \"GID\": %u, \"fd\": %u, \"sock_type\": \"%s\",\"sock_state\": \"%s\",\"sock_family\": \"%s\",\"sock_src_addr\": \"%s\", \"src_port\": %u, \"sock_dst_addr\": \"%s\", \"dst_port\": %u}\n",  
                                             hostname,
											 sock_event->cmd_name,
											 sock_event->time_stp,
                                             sock_event->pid,   
                                             sock_event->tgid,
                                             sock_event->uid,
                                             sock_event->gid,
                                             sock_event->fd,
                                             sock_type,
                                             sock_state,
                                             sock_family,
                                             ip_saddr_buff,
											 src_port,
                                             ip_daddr_buff,
											 dst_port
											 );

	if (char_cnt <= 0) {
        	char_cnt = 0;
        	return 1;
    	}

	fprintf(f_desc, "%s", sock_buff);
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
    
    char date_time[64] = "bpf_socket_collector_metrics_";
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


    struct socket_collector* skel = socket_collector__open();
    if (!skel) {
        perror("bpf_skel_open failed!");
        return 1;
     }
    
	err = socket_collector__load(skel);
	if (err) {
            perror("bpf_skel_load failed!");
            goto cleanup;
    }

	skel->bss->rqst_pid  = rqstd_pid;
    	skel->bss->rqst_uid  = rqstd_uid;
    	skel->bss->set_debug = set_debug;
    
	err = socket_collector__attach(skel);
	if (err) {
            perror("bpf_skel_attach failed!");
            goto cleanup;
        }

	
	if (NULL == (ring_buff = ring_buffer__new(bpf_map__fd(skel->maps.ring_events), handle_sock_event, NULL, NULL))) {
		perror("ring_buffer is NULL...");
		goto cleanup;

	}
	printf("BPF probe 'socket_collector' attached to kernel hook!\n");
    err = 0;

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
    socket_collector__destroy(skel);
    ring_buffer__free(ring_buff);
    fclose(f_desc);
    printf("Cleanup....done!\nBye :)\n");
    return err;
}


