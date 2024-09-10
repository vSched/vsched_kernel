// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Jianchen Shan 
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cpucfscapacity.h"
#include "cpucfscapacity.skel.h"
//#include "trace_helpers.h"
//#include "compat.h"

static struct env {
	bool verbose;
	int cpuid_min;
	int cpuid_max;
} env = {
	.verbose = false,
	.cpuid_min = 0,
	.cpuid_max = 1000
};

static volatile bool exiting;

const char *argp_program_version = "cpucfscapacity 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"show cfs capacity of a cpu when it is updated\n"
"\n"
"USAGE: cpucfscapacity [--help]\n"
"\n"
"EXAMPLES:\n"
"    cpucfscapacity 5 10              # Show updated cfs capacity of cpu5-cpu10";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
        const struct event *e = data;
        struct tm *tm;
        char ts[32];
        time_t t;

        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%-8s capacity: %4d cpu: %2d pid: %-7d task: %-16s\n", ts, e->capacity, e->cpu, e->pid, e->task);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
        printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.cpuid_min = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid cpuid_min\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.cpuid_max = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid cpuid_max\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	//if (level == LIBBPF_DEBUG && !env.verbose)
	//	return 0;
	return vfprintf(stdout, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct cpucfscapacity_bpf *obj;
	struct perf_buffer *pb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = cpucfscapacity_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/*
	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}
	*/

	err = cpucfscapacity_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	err = cpucfscapacity_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	/* Set up ring buffer polling */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 64,
                              handle_event, handle_lost_events, NULL, NULL);
        if (!pb) {
                err = -errno;
                fprintf(stderr, "failed to open perf buffer: %d\n", err);
                goto cleanup;
        }

	printf("updated cfs capacity........\n");
	while (1) {
		if(exiting) break;

		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
                /* Ctrl-C will cause -EINTR */
                if (err == -EINTR) {
                        err = 0;
                        break;
                }
                if (err < 0) {
                        printf("Error polling perf buffer: %d\n", err);
                        break;
                }

		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	cpucfscapacity_bpf__destroy(obj);
	return err != 0;
}
