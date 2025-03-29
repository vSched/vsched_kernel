// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// NOTE: set this suit your system
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
unsigned long tgidpid = 0;
unsigned long cgid = 0;
unsigned long allret = 0;
unsigned long max_exec_slice = 0;
#define fits_capacity(cap, max)   ((cap) * 1280 < (max) * 1024)
#define SCHED_FIXEDPOINT_SHIFT    10
#define SCHED_FIXEDPOINT_SCALE    (1L << SCHED_FIXEDPOINT_SHIFT)

/* Increase resolution of cpu_capacity calculations */
#define SCHED_CAPACITY_SHIFT      SCHED_FIXEDPOINT_SHIFT
#define SCHED_CAPACITY_SCALE      (1L << SCHED_CAPACITY_SHIFT)

#define debug(args...)

extern const struct rq runqueues __ksym; /* struct type global var. */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

//Function used to determine if CPU is idle
//If the only processes running on a CPU are sched-IDLE, core is considered idle
int idle_cpu(struct rq *rq)
{
    if (rq->nr_running && rq->curr->policy == 5)
        return 1; 
    if (rq->curr != rq->idle)
        return 0;
    if (rq->nr_running)
        return 0;
    if (rq->ttwu_pending)
        return 0;
    return 1;
}

//Function to get how long the current task has been running without interruption
//Interruptions include going idle, preemption, etc
u64 get_task_runtime(u64 now_time, struct rq *rq) 
{
	u64 ref;

if (rq->last_idle_tp > rq->last_preemption)
    ref = rq->last_idle_tp;
else
    ref = rq->last_preemption;

if (ref > now_time)
    return 0;

return now_time - ref;
}

//Hook to determine whether to initiate IVH
SEC("sched/cfs_sched_tick_end")
int BPF_PROG(test, struct rq *rq, u64 now, unsigned int idle_cpus)
{
    struct task_struct *curr = rq->curr;
    
    //if we have already decided to trigger IVH - no point in going through this again
    if (rq->preempt_migrate_locked == 1) {
        return 0;
    }

    //if there are more - or less! then one sched idle task running, not a good candidate for IVH
    if (rq->cfs.h_nr_running - rq->cfs.idle_h_nr_running != 1) {
        return 0;
    }

    //Checking to make sure task isn't idle
    if (curr == rq->idle) {
        return 0;
    }
    
    //Checking to make sure we aren't moving away from a good core
    if (rq->cpu_capacity > 900) {
        return 0;
    }

    //If there has never been any steal time, there's no reason to move
    if (rq->last_preemption == 0) {
        return 0;
    }

    //If there are no idle cpus in the system - why bother
    if (idle_cpus == 0) {
        return 0;
    }

    //Only tasks that have been running uninterrupted for over one MS are considered for IVH.
    u64 min_runtime_threshold = 1000000;
    if (min_runtime_threshold > get_task_runtime(now, rq)) {
        return 0;
    }
    
    //only tasks that are cpu intensive should be considered for IVH
    int util_percent = (curr->se.avg.util_avg * 100) / (1L << 10); 
    if (util_percent < 60) {
        return 0;
    }

    return 1;
}

//Function to check if a cpu is preempted
//returns amount of time between heartbeat mechanism and current time
int is_cpu_preempted(struct rq *rq, u64 now_time)
{
    u64 time_diff = now_time - rq->clock_preempt;
    
    if (rq->clock_preempt > now_time) {
        return 0;
    }
    
    if (time_diff < 300000) {
        return 0;
    }
    
    return time_diff;
}

struct task_ctx {
    struct task_struct *curr;          /* task that is to be moved */
    int *target_cpu_ptr;               /* result - where should the task be moved? */
    u64 now; 
    u64 *last_preempt_time_ptr;        /* pointer to track best preemption time */
    int start;                         /* starting CPU */
    int has_seen_sched_idle;           /* sched_idle task flag */
    u64 rq_last_preempt;               /* last preemption time of source runqueue */
    int *found_sched_idle_ptr;         /* indicator if we found a sched_idle CPU */
    int *best_capacity_ptr;            /* best CPU capacity found */
    int average_capacity;              /* system average capacity */
    int total_cpus;                    /* total number of CPUs in system */
};

static int process_cpu(u32 iter, struct task_ctx *ctx) 
{
    struct task_struct *curr = ctx->curr;

    //Current CPU
    int cpu = (iter + ctx->start) % ctx->total_cpus;

    //cpumask of curr cpu
    cpumask_t *cpumask = curr->cpus_ptr;
    unsigned long cpumask_bits = *(cpumask->bits);
    
    //is valid cpu for task?
    if (!(cpumask_bits & (1UL << cpu))) {
        return 0;
    }

    int *target_cpu_ptr = ctx->target_cpu_ptr;
    u64 *last_preempt_time_ptr = ctx->last_preempt_time_ptr;
    
    //RQ for current cpu
    struct rq *select_rq = bpf_per_cpu_ptr(&runqueues, cpu);

    //if RQ invalid, return
    if (!select_rq) {
        return 0;
    }

    //has this cpu been selected by other IVH threads?
    int is_locked = select_rq->prmpt_flags.counter & (1 << (2));
    if (is_locked) {
        return 0;
    }

    //if there are(non sched idle) tasks running at my destination - why should I move there?
    if (select_rq->cfs.h_nr_running - select_rq->cfs.idle_h_nr_running > 0) {
        return 0;
    }

    //is a SCHED IDLE cpu
    if (select_rq->nr_running > 0 && select_rq->curr->policy == 5) {
        //Sched IDLE cpus are the best targets!
        *(ctx->found_sched_idle_ptr) = 1;

        u64 time_since_heartbeat = is_cpu_preempted(select_rq, ctx->now);
        
        //if cpu is preempted - we don't want it
        if (!time_since_heartbeat) {
            return 0;
        }

        //if target core has been active longer then current core - don't move
        if (select_rq->last_preemption <= ctx->rq_last_preempt) {
            return 0;
        }

        //we're looking for the core that has been active for the least amount of time
        if (time_since_heartbeat < select_rq->last_preemption && select_rq->cpu_capacity > 500) {
            *last_preempt_time_ptr = select_rq->last_preemption;
            *target_cpu_ptr = (int)(cpu);
        }
        return 0;
    // if the system has a previous valid sched_idle cpu and it's not this one - shouldn't bother
    } else if (*(ctx->found_sched_idle_ptr) && *target_cpu_ptr != -1) {
        return 0;
    }
    
    //select a core with "good enough" capacity
    if (select_rq->cpu_capacity > ctx->average_capacity || select_rq->cpu_capacity > 500) {
        *target_cpu_ptr = (int)(cpu);
        return 1;
    }
    return 0;
}

//Hook to decide on which core to land on
SEC("sched/cfs_select_run_cpu_spin")
int BPF_PROG(test3, struct rq *rq, struct task_struct *curr, u64 now_time, int average_capacity, int total_cpus)
{
    int start = 0;
    u32 nr_loops = total_cpus - 1;
    int target_cpu = -1;
    u64 last_preempt_time = 0xFFFFFFFFFFFFFFFFULL; // Using max u64 value
    int best_capacity = rq->cpu_capacity;
    int found_sched_idle = 0;

    struct task_ctx task_context = {
        .curr = curr,
        .target_cpu_ptr = &target_cpu,
        .now = now_time,
        .last_preempt_time_ptr = &last_preempt_time,
        .start = rq->cpu,
        .rq_last_preempt = rq->last_preemption,
        .found_sched_idle_ptr = &found_sched_idle,
        .best_capacity_ptr = &best_capacity,
        .average_capacity = average_capacity,
        .total_cpus = total_cpus
    };

    bpf_loop(nr_loops, &process_cpu, &task_context, 0);
    return target_cpu;
}

SEC("sched/cfs_should_spinlock")
int BPF_PROG(test4, int test)
{
    return 1;
}

SEC("sched/cfs_should_bias")
int BPF_PROG(test6, int test)
{
    return 1;
}

struct latency_ctx {
    struct task_struct *curr;          /* task to be placed */
    struct cpumask *idle_cpus;         /* mask of idle CPUs */
    int *target_cpu_ptr;               /* pointer to selected CPU */
    int start;                         /* CPU to start search from */
    u64 *min_latency_ptr;              /* pointer to track minimum latency */
    u64 *preemption_time_ptr;          /* pointer to track preemption time */
    int *found_good_cpu_ptr;           /* pointer to flag for good CPU found */
    u64 *max_bad_latency_ptr;          /* pointer to track max latency for bad CPUs */
    u64 now;                           /* current time */
    u64 *longest_runtime_ptr;          /* pointer to track longest runtime */
    int total_cpus;                    /* total CPUs in system */
    int average_capacity;              /* average CPU capacity in system */
};

static int search_latency(u32 iter, struct latency_ctx *ctx) 
{
    struct task_struct *curr = ctx->curr;
    int cpu = (iter + ctx->start) % ctx->total_cpus;
    
    //leave if we've checked each cpu
    if (iter >= ctx->total_cpus) {
        return 1;
    }
    
    const cpumask_t *cpumask_const = curr->cpus_ptr;
    unsigned long cpumask_bits = *(cpumask_const->bits);
    
    //check if task is allowed to run on said cpu
    if (!(cpumask_bits & (1UL << cpu))) {
        return 0;
    }
    
    struct rq *select_rq = bpf_per_cpu_ptr(&runqueues, cpu);
    if (!select_rq) { 
        return 0;
    }

    int *target_cpu_ptr = ctx->target_cpu_ptr;
    u64 *preemption_time_ptr = ctx->preemption_time_ptr;

    //if the target is uncontested - no reason to hesitate
    if (select_rq->cpu_capacity > 1000) {
        *target_cpu_ptr = cpu;
        return 1;
    }

    //path if there are only SCHED-IDLE tasks running
    if ((select_rq->nr_running == select_rq->cfs.idle_h_nr_running) && select_rq->nr_running > 0) {
        //if it's a better than average core - that's good enough!
        if (select_rq->cpu_capacity > (ctx->average_capacity)) {
            *target_cpu_ptr = cpu;
            return 1;
        }
        
        //if it has been running recently - good enough
        if (get_task_runtime(ctx->now, select_rq) < 2000000) {
            *target_cpu_ptr = cpu;
            return 1;
        }
        
        return 0;
    }
    
    if (idle_cpu(select_rq)) {
        //normal loop, if a cpu is less than the median - ignore it. Otherwise pick lowest latency
        if (select_rq->cpu_capacity > (ctx->average_capacity) && 
            select_rq->avg_latency <= *(ctx->min_latency_ptr)) {
            
            *(ctx->min_latency_ptr) = select_rq->avg_latency;
            *target_cpu_ptr = cpu;
            return 0;
        }
    }
    
    return 0;
}

SEC("sched/cfs_latency_select")
int BPF_PROG(test32, int prev, struct task_struct *curr, struct cpumask *idle_cpus, 
             int average_capacity, int total_cpus)
{
    int start = 0;
    int nr_loops = total_cpus;
    int target_cpu = -1;
    u64 preemption_time = 0;
    int util_percent = (curr->se.avg.util_avg * 100) / (1L << 10);
    
    if (util_percent > 10 || curr->policy == 5) {
        return -1;
    }
    
    u64 min_latency = 0xFFFFFFFFFFFFFFFFULL; // Using max u64 value
    u64 max_bad_latency = 0xFFFFFFFFFFFFFFFFULL; // Using max u64 value
    int found_good_cpu = 0;
    u64 longest_runtime = 0xFFFFFFFFFFFFFFFFULL; // Using max u64 value
    u64 now = 0;
    
    struct rq *current_rq = bpf_this_cpu_ptr(&runqueues);
    if (current_rq) {
        now = current_rq->clock_preempt;
    }
    
    struct latency_ctx latency_context = {
        .curr = curr,
        .target_cpu_ptr = &target_cpu,
        .idle_cpus = idle_cpus,
        .start = prev,
        .preemption_time_ptr = &preemption_time,
        .min_latency_ptr = &min_latency,
        .found_good_cpu_ptr = &found_good_cpu,
        .max_bad_latency_ptr = &max_bad_latency,
        .now = now,
        .longest_runtime_ptr = &longest_runtime,
        .total_cpus = total_cpus,
        .average_capacity = average_capacity
    };
    
    bpf_loop(256, &search_latency, &latency_context, 0);
    return target_cpu;
}
