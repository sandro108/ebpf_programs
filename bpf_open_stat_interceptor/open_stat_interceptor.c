#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
//#include <bpf/trace_helpers.h>
#include <sys/resource.h>
#include <signal.h>

#include "open_stat_interceptor.h"
#include "open_stat_interceptor.skel.h"



#define HOST_NAME_MAX 64
#define O_CREAT 00000100



const char argp_program_doc[] =
"Trace open syscalls, that have the O_CREAT flag set, and all stat syscalls.\n"
"\n"
"USAGE: open_stat_interceptor [-h] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    open_stat_interceptor 	      # trace all stat syscalls\n"
"    open_stat_interceptor -p 1216     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help", 0 },
	{},
};

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
static pid_t rqstd_pid = 0;
static char hostname[HOST_NAME_MAX] = "null";
static volatile sig_atomic_t keep_running = 1;

static void sig_int(int signo)
{
    printf("\nReceived signal: %d\n", signo);
    if (signo == 2 || signo == 9) {
        keep_running = 0;
    }
}

static error_t parse_arg(int opt, char* arg, struct argp_state* state)
{
	long pid;

	switch (opt) {
		case 'p':
			errno = 0;
			pid = strtol(arg, NULL, 10);
			if (errno || pid <= 0) {
				printf("Invalid PID: %s\n", arg);
				argp_usage(state);
			}
			rqstd_pid = pid;
			break;
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
	int err, ret_code;
    struct event* event = NULL;
    event = data;
    if (event == NULL) {
        perror("event is NULL.");
        return 0;
    }

    if (event->ret >= 0) {
		ret_code = event->ret;
		err = 0;
	} else {
		ret_code = -1;
		err = -event->ret;
	}
	
	if (event->event_type == OPEN_EVENT) {
    	
	
		if (0 == (O_CREAT & event->flags)) {
	//		printf("flag: %d\n", (O_CREAT & event->flags));
			return 0;
		} 



		printf("%-35s %-18llu %-8u %-7u %-20s %-8s %-10s %-10d %-8d %-s\n",hostname, event->ts_us, event->uid, event->pid, event->comm, "open()", "O_CREAT", ret_code, err, event->pathname);
	
	}
	if (event->event_type == STAT_EVENT) {

		printf("%-35s %-18llu %-8u %-7u %-20s %-8s %-10s %-10d %-8d %-s\n",hostname, event->ts_us, event->uid, event->pid, event->comm, "stat()",      "-",  ret_code, err, event->pathname);
	}
	

	return EXIT_SUCCESS;

}



int main(int argc, char **argv)
{
    int err;
    bump_memlock_rlimit();

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;



    struct ring_buffer* ring_buff = NULL;
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    /* in case of error hostname stays "null" */
    gethostname(hostname, HOST_NAME_MAX);

     struct open_stat_interceptor* skel = open_stat_interceptor__open();
     if (!skel) {
        perror("bpf_skel_open failed!");
        return EXIT_FAILURE;
     }


     err = open_stat_interceptor__load(skel);
     if (err) {
        perror("bpf_skel_load failed!");
        goto cleanup;
     }

	skel->bss->rqstd_pid = rqstd_pid;

     err = open_stat_interceptor__attach(skel);
     if (err) {
        perror("bpf_skel_attach failed!");
        goto cleanup;
     }



     if (NULL == (ring_buff = ring_buffer__new(bpf_map__fd(skel->maps.ring_events), handle_event, NULL, NULL))) {
        perror("ring_buffer is NULL...");
        goto cleanup;
    }

    printf("Kprobe 'open_stat_interceptor' attached to kernel hook!\n");

    printf("%-35s %-18s %-8s %-7s %-20s %-8s %-10s %-10s %-8s %-s\n",
	       "HOST", "TIMESTAMP", "UID", "PID", "CMD", "CALL", "FLAGS", "FD/RET_VAL", "ERR", "PATH");


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


	/* cleanup yer mess */
cleanup:
    open_stat_interceptor__destroy(skel);
    ring_buffer__free(ring_buff);
    printf("Cleanup....done!\nBye :)\n");
    return err;
}
