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

#include "open_stat_interceptor.h"
#include "open_stat_interceptor.skel.h"



#define HOST_NAME_MAX 64
#define HASH_TABLE_SIZE 100


//TODO: 
//1. introduce filters for filesystem types (nfs4, ext4,...) in bpf.c
//5. decide on form of alarming



uint8_t set_debug = 0; 


/* debug print helper */
#define DEBUG_PRINT(...)               \
    do {                                  \
        if (set_debug)                    \
            printf(__VA_ARGS__); \
        else                              \
            do {} while (0);              \
    } while (0)


struct hash_node {
	pid_t pid;
	char* path;
	uint64_t time_stamp;
	struct hash_node* next;
};

const char argp_program_doc[] =
"\nTrace open() syscalls, that have the O_CREAT flag set, and all stat syscalls (for now, filter options are comming...).\n"
"Purpose is to find out whether processes call stat() on the parent directory of a file they have opened.\n"
"The optional MAX_CHAIN_LENGTH integer argument determines the number of entries per bucket of the hash table that the program will allocate (default is 100).\n"
"The total size of the hash table is MAX_CHAIN_LENGTH * 100 buckets.\n"
"USAGE: open_stat_interceptor [-h] [-p PID] [-m MAX_CHAIN_LENGTH] [-d] [-v]\n"
"\n"
"EXAMPLES:\n"
"    ./open_stat_interceptor 	      # trace all stat syscalls\n"
"    ./open_stat_interceptor -p 1216  # only trace process with PID 1216\n"
"    ./open_stat_interceptor -m 50    # number of entries in each bucket (default is 100)\n"
"    ./open_stat_interceptor -d       # enable debug output\n"
"    ./open_stat_interceptor -v	      # print version and exit\n\n";

static const struct argp_option opts[] = {
	{"max_chain_len", 'm', "MAX_CHAIN_LEN",0, "Max hash chain length",0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help", 0 },
	{"debug", 'd', NULL,0, "Enable debug output",0},
	{"version", 'v', NULL,0, "Print version and exit",0},
	{}
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
static struct hash_node* hash_table[HASH_TABLE_SIZE] = {NULL}; 
static uint64_t max_chain_len = 0;

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
	uint64_t max_chain_len_loc;
	switch (opt) {
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case 'v':
			printf("\nopen_stat_interceptor - version 2.1 -\n\n");
			exit(0);
		case 'p':
			errno = 0;
			pid = strtol(arg, NULL, 10);
			if (errno || pid <= 0) {
				printf("Invalid PID: %s\n", arg);
				argp_usage(state);
			}
			rqstd_pid = pid;
		case 'm':
			errno = 0;
			max_chain_len_loc = strtol(arg, NULL, 10);
			if (errno || max_chain_len_loc <= 0) {
				printf("Invalid -m argument!: %s\n", arg);
				argp_usage(state);
			}
			max_chain_len = max_chain_len_loc;
		case 'd':
			set_debug = 1;
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
    /* sanity checks */
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

	struct hash_node* node = NULL;
 	char* path = NULL;
	uint64_t time_stp = 0;

	if (event->event_type == OPEN_EVENT) {
	
		int i;
	  	uint8_t chain_len = 0;   
		long path_len = strlen(event->pathname);
		if (path_len < 1)
			return 0;

		char full_path[path_len + 1];
		memcpy(full_path, event->pathname, path_len + 1);
		
		/* cut off filename component from path */
		char* last = NULL;
		last = strrchr(full_path, '/');
		if (!last) {
			return 0;
		} 
		if (last < full_path) {
			return 0;
		}
		i = (int) (last - full_path);
		full_path[i] = '\0';	
		long path_len_trunc = strlen(full_path);
		
		/* allocate memory for the headless path */
		path = (char*) malloc(sizeof(char) * path_len_trunc + 1); 
		if (!path) {
			perror("malloc path:");
			return 0;
		}
		memcpy(path, full_path, path_len_trunc + 1);

		/* allocate memory for the hash table entry */	
		node = (struct hash_node*) malloc(sizeof(struct hash_node));
		if (!node) {
			perror("malloc hash_node:");
			goto free_path;
		}
		struct hash_node new_node = {.pid=event->pid, .time_stamp=event->ts_us, .path=path, .next=NULL};
		memcpy(node, &new_node, sizeof(struct hash_node));

		uint8_t hash = node->pid % HASH_TABLE_SIZE;
		struct hash_node* temp = NULL;
		
		temp = hash_table[hash];
		/* if bucket of hash table is empty */
		if (!temp) {
			hash_table[hash] = node;
		}
		else {
			while (temp) { /* check if entry with current PID and path is already in hash table */
				if (temp->pid == node->pid && (0 == strcmp(temp->path, node->path))) {
					goto out;
				}
				if (!temp->next) {
					break;
				}
				temp = temp->next;
				++chain_len;
			} /* if the new node is not in hash table append it at the end of the bucket's chain of entries*/
			temp->next = node;
			/* check whether MAX_CHAIN_LEN is reached. If so, kick out head entry of the bucket's chain */
			if (chain_len + 1 >= max_chain_len) {
				temp = hash_table[hash];
				hash_table[hash] = temp->next;
				free(temp->path);
				free(temp);
			}
		}
		
		
		/* below loop is for debugging purpose, only active when '-d' option was set */
		
		temp = hash_table[hash];
		DEBUG_PRINT("Hash table bucket no. %u:\n",hash);
		while (temp) {
			DEBUG_PRINT("node: %p, hash: %u, pid: %u, path: %s, next: %p\n", temp, hash, temp->pid, temp->path, temp->next);
			temp = temp->next;
		}
		DEBUG_PRINT("\n");
		/* if all went well print metrics of open(O_CREATE) syscall, if '-d' option was set  */
		DEBUG_PRINT("%-35s %-18s %-8s %-7s %-20s %-8s %-10s %-10s %-8s %-s\n",
	       "HOST", "TIMESTAMP", "UID", "PID", "CMD", "CALL", "FLAGS", "FD/RET_VAL", "ERR", "PATH");
		DEBUG_PRINT("%-35s %-18llu %-8u %-7u %-20s %-8s %-10s %-10d %-8d %-s \n\n",hostname, event->ts_us, event->uid, event->pid, event->comm, "open()", "O_CREAT", ret_code, err, event->pathname);
	}
	

	if (event->event_type == STAT_EVENT) {
		uint8_t hash = event->pid % HASH_TABLE_SIZE;
		struct hash_node* temp = NULL;
		
		temp = hash_table[hash];

		if (!temp) {
			return 0;
		}
		else {
			while (temp) {
				if (temp->pid == event->pid && (0 == strcmp(temp->path, event->pathname))) {
					printf("#################################################################################################################\n");
					printf("!!!!!Stat!!!!!: Match found: hash_entry->PID: %u, hash_entry->time_stamp: %lu, hash_entry->path: %s\n", temp->pid,temp->time_stamp, temp->path);
					time_stp = temp->time_stamp;
					goto alert;
				}
				temp = temp->next;
			}
		}
	}
	return 0;

free_path:
		free(path);
		return 0;
out:
		free(node->path);
		free(node);
		return 0;
alert:
		printf("%-35s %-18s %-8s %-7s %-20s %-8s %-10s %-10s %-8s %-s\n",
	       "HOST", "TIMESTAMP", "UID", "PID", "CMD", "CALL", "FLAGS", "FD/RET_VAL", "ERR", "PATH");
		printf("%-35s %-18llu %-8u %-7u %-20s %-8s %-10s %-10d %-8d %-s\n",hostname, event->ts_us, event->uid, event->pid, event->comm, "stat()",      "-",  ret_code, err, event->pathname);
		printf("!!!!!!!ALERT!!!!!! Stat on parent directory! By PID: %u, time_betw_open and_stat_us: %llu,  on path: %s\n\n", event->pid,(event->ts_us - time_stp), event->pathname);
		printf("#################################################################################################################\n\n");

		return 0;
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

	if (!max_chain_len) {
		max_chain_len = 100;	
	}

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

    printf("Kprobe 'open_stat_interceptor2' attached to kernel hook!\n");

   

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
    open_stat_interceptor__destroy(skel);
    ring_buffer__free(ring_buff);
	int hash = 0;
	struct hash_node* node;
	struct hash_node* temp;
	while (hash < HASH_TABLE_SIZE) {
		node = hash_table[hash];
		while(node) {
			temp = node;
			free(node->path);
			node = node->next;
			free(temp);
		}
		++hash;
	}
	printf("Cleanup....done!\nBye :)\n");
    return err;
}
