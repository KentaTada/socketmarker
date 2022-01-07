/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Sony Group Corporation */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

const volatile __u32 marker = 0;

SEC("cgroup/sock_create")
int marker_handler(struct bpf_sock *ctx)
{
	ctx->mark = marker;
	return 1;
}

char _license[] SEC("license") = "GPL";
