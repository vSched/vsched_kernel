// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Jianchen Shan 
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cpucfscapacity.h"

/* BPF perfbuf map */
struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
SEC("raw_tracepoint/sched_cpu_capacity_tp")
int BPF_PROG(cpu_capacity, struct rq *rq)
{
	bpf_printk("capacity is %d\n", BPF_CORE_READ(rq, cpu_capacity));
	struct event *eventp;

	return 0;
}
*/

SEC("raw_tracepoint/sched_cpu_capacity_tp")
int BPF_PROG(cpu_capacity, struct rq *rq)
{

        struct event event = {};

        event.pid = bpf_get_current_pid_tgid() >> 32;
	event.cpu = bpf_get_smp_processor_id();
        event.capacity = BPF_CORE_READ(rq, cpu_capacity);
        bpf_get_current_comm(&event.task, sizeof(event.task));

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return 0;
}


char LICENSE[] SEC("license") = "GPL";
