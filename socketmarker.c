/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Sony Group Corporation */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "socketmarker.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	__u32 marker;
	char *cgpath;
} env;

const char *argp_program_version = "socketmarker 0.0.1";
const char *argp_program_bug_address = "https://github.com/KentaTada/socketmarker";
static const char args_doc[] = "SOCKETMARKER";
static const char program_doc[] =
"Add a marker to trace packets inside cgroup\n"
"\n"
"Usage: socketmarker [-h] [-m MARKER] CGROUPPATH\n"
"\v"
"Examples:\n"
"  ./socketmarker -m 1 /sys/fs/cgroup/markedcg\n"
;

static const struct argp_option opts[] = {
	{ "marker", 'm', "MARKER", 0, "Marker of the packet inside targetted cgroups" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	__u32 marker = 0;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'm':
		errno = 0;
		marker = strtoul(arg, NULL, 10);
		if (errno || marker <= 0) {
			warn("Invalid marker number: %s\n", arg);
			argp_usage(state);
		}
		env->marker = marker;
		break;
	case ARGP_KEY_ARG:
		if (env->cgpath) {
			warn("Too many cgroup paths: %s\n", arg);
			argp_usage(state);
		}
		env->cgpath = strdup(arg);
		if (!env->cgpath) {
			warn("strdup: %s\n", strerror(errno));
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (!env->cgpath) {
			warn("Need to specify the cgroup path\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static volatile int exiting = 0;

static void sig_hand(int signr)
{
	exiting = 1;
}

static struct sigaction sigact = {.sa_handler = sig_hand};

int main(int argc, char **argv)
{
	int cgroup_fd = -1;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct socketmarker_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	sigaction(SIGINT, &sigact, 0);

	/* To load thr bpf program for old kernels */
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	/* Open the traced cgroup dir */
	cgroup_fd = open(env.cgpath, O_RDONLY);
	if (cgroup_fd < 0) {
		warn("failed to open the specified cgroup path\n");
		return 1;
	}

	obj = socketmarker_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->marker = env.marker;

	err = socketmarker_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	obj->links.marker_handler = bpf_program__attach_cgroup(obj->progs.marker_handler, cgroup_fd);
	err = libbpf_get_error(obj->links.marker_handler);
	if (err) {
		warn("failed to attach the marker: %d\n", err);
		goto cleanup;
	}

	printf("socket in %s will be marked as %d\n", env.cgpath, env.marker);
	/* TODO: Just wait for the user to stop marking */
	while (!exiting)
		pause();

cleanup:
	free(env.cgpath);
	socketmarker_bpf__destroy(obj);

	return err != 0;
}
