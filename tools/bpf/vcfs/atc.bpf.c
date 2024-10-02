
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//#include <linux/sched.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <linux/sched.h>

#define NR_CPUS 12
#define for_each_cpu_wrap(cpu, mask, start)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)(start))
struct cpu_die_map_type {
    unsigned long data[317];
};
__u32 nr_migrating = 0;

static inline void increment_nr_migrating() {
    nr_migrating++;
}

static inline void decrement_nr_migrating() {
   nr_migrating--;
}


__u64 out__runqueues_addr = -1;
__u64 out__bpf_prog_active_addr = -1;
__u32 out__rq_cpu = -1; /* percpu struct fields */
int cpu_av=500;

int out__bpf_prog_active = -1; /* percpu int */
__u32 out__this_rq_cpu = -1;
int out__this_bpf_prog_active = -1;
__u32 out__cpu_0_rq_cpu = -1; /* cpu_rq(0)->cpu */
extern const struct rq runqueues __ksym; /* struct type global var. */
extern const int bpf_prog_active __ksym; /* int type global var. */
extern const int numa_node __ksym;
extern const cpumask_t *cpu_die_map __ksym;
int idle_cpu(u64 now_time,struct rq *rq)

{
//	if(rq->nr_running>0 && rq->curr->policy == 5)
//		return 1; 

	if(rq->curr != rq->idle)
		return 0;
	if (rq->nr_running)
		return 0;
	if (rq->ttwu_pending)
		return 0;
	return 1;
}



// Assuming you have a cpumask called 'cpu_mask'

char LICENSE[] SEC("license") = "Dual BSD/GPL";

unsigned long tgidpid = 0;
unsigned long cgid = 0;
unsigned long allret = 0;
unsigned long max_exec_slice = 0;



int simple_strcmp(const char *s1, const char *s2) {
    while (*s1 == *s2) {
        // If we reach the end of both strings, they are equal
        if (*s1 == '\0') {
            return 0;
        }
        s1++;
        s2++;
    }
    // Return the difference in ASCII values of the first differing characters
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}
#define INVALID_RET ((unsigned long) -1L)

//#define debug(args...) bpf_printk(args)
#define debug(args...)


//get time so far
u64 get_tsf(u64 now_time,struct rq *rq){
	u64 last_time;
	if(rq->last_idle_tp>rq->last_preemption){
		if(rq->last_idle_tp>now_time){
			return 0;
		}
		last_time=now_time-rq->last_idle_tp;
	}else{
		if(rq->last_preemption>now_time){
			return 0;
		}
		last_time=now_time-rq->last_preemption;
		
	}
	return last_time;

}



SEC("sched/cfs_sched_tick_end")
int BPF_PROG(test,struct rq *rq,u64 now,unsigned int idle_cpus)
{
	struct task_struct *curr = rq->curr;
	s64 delta_exec;
	if((rq->cfs.h_nr_running-rq->cfs.idle_h_nr_running == 1) && (curr != rq->idle) && rq->cpu_capacity<900){
		if(rq->last_preemption !=0 && idle_cpus>0){
			u64 prev_time_brk = 1000000;
			if(prev_time_brk < get_tsf(now,rq) && (rq->preempt_migrate_locked != 1)){
				int util_perc = (curr->se.avg.util_avg * 100) / (1L << 10) ; 
				if (util_perc > 60) {
	 				return 1;
				}
                        }
                }
	}
	return 0;
}

int is_cpu_preempted(struct rq *rq,u64 now_time)
{
        u64 time_diff;
        time_diff = now_time-rq->clock_preempt;
	if(rq->clock_preempt>now_time){
		return 0;
	}
        if(time_diff<100000){
                return 0;
       }

        return time_diff;
}


int select_run_cpu_cpu_util(struct rq *rq, struct rq *select_rq,u64 now_time,int max){
	if(!idle_cpu(now_time,select_rq)){
                return -1;
        }
        if(max == -1){
                return select_rq->cpu;
        }
        struct rq *last_max_rq = bpf_per_cpu_ptr(&runqueues, max);
        if(!last_max_rq){
                return -1;
        }
        if(select_rq->cfs.avg.util_est.enqueued < last_max_rq->cfs.avg.util_est.enqueued){
                return select_rq->cpu;
        }
        return -1;
}


int select_run_cpu_time(struct rq *rq, struct rq *select_rq,u64 now_time,int max)
{
        if(!idle_cpu(now_time,select_rq)){
                return -1;
        }
        if((now_time-select_rq->last_active_time) < 100000){
                return -1;
        }
        if(max == -1){
                return select_rq->cpu;
        }
        if(select_rq->last_active_time>now_time){
                return -1;

        }
        struct rq *last_max_rq = bpf_per_cpu_ptr(&runqueues, max);
        if(!last_max_rq){
                return -1;
        }
        if(select_rq->last_active_time < last_max_rq->last_active_time ){
                return select_rq->cpu;
        }
        return -1;
}
SEC("sched/cfs_select_run_cpu")
int BPF_PROG(test9, struct rq *rq, struct rq *select_rq,u64 now_time,int max)
{
	if(!idle_cpu(now_time,select_rq)){
                return -1;
        }
        if(max == -1){
                return select_rq->cpu;
        }
        return -1;
}

struct task_ctx {
    struct task_struct *curr;
    int *res_value;
    u64 now;
    u64 *preemption_val;
    int start;
    int has_seen_schedidle;
    u64 rq_lst_prmpt;
    int *has_sched_idle;
    int *best_cpc;
    unsigned long new_bits;
};


static int process_cpu(u32 iter, struct task_ctx *ctx1)
{
	struct task_struct *curr = ctx1->curr;
	int cpu = (iter+ctx1->start) % NR_CPUS;
	cpumask_t *cpumask = curr->cpus_ptr;
        unsigned long cpumask_bits = *(cpumask->bits);
	int test = cpumask_bits & (1UL << cpu);
	int *fin = ctx1->res_value;
	u64 *preemption_val = ctx1->preemption_val;
	u64 soon_preempt = 0;
	if(test){
		struct rq *select_rq = bpf_per_cpu_ptr(&runqueues,cpu);
		if(select_rq){
			int islocked = select_rq->prmpt_flags.counter & (1 << (2));
			if(islocked){
				return 0;
			}
			if(select_rq->cfs.h_nr_running-select_rq->cfs.idle_h_nr_running==1){
                               return 0;
                        }

			if(select_rq->nr_running>0 && select_rq->curr->policy == 5){
				ctx1->has_sched_idle = 1;
				u64 preemption_decider = is_cpu_preempted(select_rq,ctx1->now);
				if(preemption_decider<5000000 && preemption_decider !=0){
					return 0;
				}
				if(ctx1->now-select_rq->last_preemption>1000000 && preemption_decider == 0){
					return 0;
				}

				if((select_rq->last_preemption)<=(ctx1->rq_lst_prmpt) && preemption_decider==0){
					return 0;
				}

				if(*preemption_val<select_rq->last_preemption && select_rq->cpu_capacity>500){
					*preemption_val = select_rq->last_preemption;
					*fin = (int) (cpu);
					return 0;
				}
				return 0;
			}
			if(select_rq->cpu_capacity>cpu_av && idle_cpu(0,select_rq) && !(ctx1->has_sched_idle == 0)){
				  *(ctx1->preemption_val)=select_rq->idle_stamp;

                                        *fin = (int) (cpu);
                                        return 1;
			}

		}
	};
	return 0;
}


static int process_cpu_numa(u32 iter, struct task_ctx *ctx1)
{
        struct task_struct *curr = ctx1->curr;
        int cpu = (iter+ctx1->start) % NR_CPUS;
        unsigned long cpumask_bits = ctx1->new_bits;
        int test = cpumask_bits & (1UL << cpu);
        int *fin = ctx1->res_value;
        u64 *preemption_val = ctx1->preemption_val;
        u64 soon_preempt = 0;
        if(test){
                struct rq *select_rq = bpf_per_cpu_ptr(&runqueues,cpu);
                if(select_rq){
                        int islocked = select_rq->prmpt_flags.counter & (1 << (2));
                        if(islocked){
                                return 0;
                        }
                        if(select_rq->cfs.h_nr_running-select_rq->cfs.idle_h_nr_running==1){
                               return 0;
                        }

                        if(select_rq->nr_running>0 && select_rq->curr->policy == 5){
                                ctx1->has_sched_idle = 1;
                                u64 preemption_decider = is_cpu_preempted(select_rq,ctx1->now);
                                if(preemption_decider<5000000 && preemption_decider !=0){
                                        return 0;
                                }
                                if(ctx1->now-select_rq->last_preemption>1000000 && preemption_decider == 0){
                                        return 0;
                                }

                                if((select_rq->last_preemption)<=(ctx1->rq_lst_prmpt) && preemption_decider==0){
                                        return 0;
                                }

                                if(*preemption_val<select_rq->last_preemption && select_rq->cpu_capacity>500){
                                        *preemption_val = select_rq->last_preemption;
                                        *fin = (int) (cpu);
                                        return 0;
                                }
                                return 0;
                        }
                        if(select_rq->cpu_capacity>500 && idle_cpu(0,select_rq) && !(ctx1->has_sched_idle == 0)){
                                  *(ctx1->preemption_val)=select_rq->idle_stamp;

                                        *fin = (int) (cpu);
                                        return 0;
                        }

                }
        };
        return 0;
}

static int test_preemption(u32 iter, struct task_ctx *ctx1)
{
	struct task_struct *curr = ctx1->curr;
        int cpu = (iter+ctx1->start) % NR_CPUS;
	if(cpu>5){
		return 0;
	}
        cpumask_t *cpumask = curr->cpus_ptr;
        unsigned long cpumask_bits = *(cpumask->bits);
        int test = cpumask_bits & (1UL << cpu);

        int *fin = ctx1->res_value;
	u64 *preemption_val = ctx1->preemption_val;
        u64 min_tsf = 99999999;
        if(test){
                struct rq *select_rq = bpf_per_cpu_ptr(&runqueues,cpu);
                if(select_rq){
                        if(is_cpu_preempted(select_rq,ctx1->now)){
                                        *fin += 1;
                                   	return 0;
                        }

                }
        }else{
                bpf_printk("restrained%u",cpu);
        }
        //bpf_printk("it worked, thank god%d",test);
        return 0;
}

SEC("sched/cfs_select_run_cpu_spin")
int BPF_PROG(test3, struct rq *rq, struct task_struct *curr, u64 now_time, unsigned long cpu_bitmap)
{
    int start = 0;
    u32 nr_loops = NR_CPUS-1;
    int re_value = -1;
    u64 preemption_val = 9999999999999999999;
    int best_non_numa=-1;
    int best_cpc = rq->cpu_capacity;
    int src_numa=-1;
    unsigned long numa_bits;
    unsigned long *numa_mask = bpf_per_cpu_ptr(&cpu_die_map, rq->cpu);
    int has_sched_idle=0;
    struct task_ctx ctx1 = {
	.curr = curr,
	.res_value = &re_value,
        .now = now_time,
	.preemption_val = &preemption_val,
	.start = rq->cpu,
	.rq_lst_prmpt = rq->last_preemption,
	.has_sched_idle=&has_sched_idle,
	.best_cpc=&best_cpc,
        .new_bits=cpu_bitmap
    };
     //if (curr->policy == 5) {
      //        return -1;
     //}
  //   bpf_loop(nr_loops,&process_cpu_numa,&ctx1,0);

     bpf_loop(nr_loops, &process_cpu, &ctx1, 0);
//     decrement_nr_migrating();
    //__sync_fetch_and_sub(&nr_migrating, 1);
	return re_value;
}

SEC("sched/cfs_should_spinlock")
int BPF_PROG(test4,int test)
{
	return 1;
}

SEC("sched/cfs_should_bias")
int BPF_PROG(test6,int test)
{
//	bpf_printk("should bias");
        return 0;
}

struct latency_ctx {
    struct task_struct *curr;
    struct cpumask *idle_cpus;
    u64 util_min;
    u64 util_max;
    int *res_value;
    int start;
    u64 *max_latency;
    u64 *preemption_val;
    int *has_good_cpu;
    u64 *max_latency_bad;
    u64 now;
    u64 *long_at;
};


#define fits_capacity(cap, max)	((cap) * 1280 < (max) * 1024)
# define SCHED_FIXEDPOINT_SHIFT		10
# define SCHED_FIXEDPOINT_SCALE		(1L << SCHED_FIXEDPOINT_SHIFT)

/* Increase resolution of cpu_capacity calculations */
# define SCHED_CAPACITY_SHIFT		SCHED_FIXEDPOINT_SHIFT
# define SCHED_CAPACITY_SCALE		(1L << SCHED_CAPACITY_SHIFT)



static int search_latency(u32 iter, struct latency_ctx *ctx1)
{
	struct task_struct *curr = ctx1->curr;
        int cpu = (iter+ctx1->start) % NR_CPUS;
        cpumask_t *cpumask = curr->cpus_ptr;
        unsigned long cpumask_bits = *(cpumask->bits);
        int test = cpumask_bits & (1UL << cpu);

        int *fin = ctx1->res_value;
	u64 *preemption_val = ctx1->preemption_val;
	struct rq *select_rq = bpf_per_cpu_ptr(&runqueues,cpu);
        if(test){

		if(select_rq){ 
//		if(0){
		if((select_rq->nr_running == select_rq->cfs.idle_h_nr_running) && select_rq->nr_running > 0){
				if(select_rq->cpu_capacity>1000){
                                	*fin=cpu;
                                	return 1;
                                }
				//Active Pass
				//ctx1 now is the current cpus clock_preempt value
				if(1){
				if(select_rq->cpu_capacity>300 &&
				(ctx1->now < select_rq->last_preemption || ctx1->now-select_rq->last_preemption<1000000)){
                               			*(ctx1->long_at) = select_rq->last_active_time;
                                		*fin = cpu;
                                		return 1;
                        		}
				}
				//(can't find an active core?)
				if(select_rq->cpu_capacity>300
							&& select_rq->avg_latency<=*(ctx1->max_latency)){
                                	*(ctx1->max_latency) = select_rq->avg_latency;
                                	*fin = cpu;
                     			*(ctx1->has_good_cpu)=1;
                                	return 0;
                   		}


                               return 0;
                }
		if(idle_cpu(1,select_rq)){
			//if a cpu is uncontested, just pick it
			if(select_rq->cpu_capacity>1000){
			        *fin=cpu;
				return 1;
			}
			//normal loop, if a cpu is less then the median - ignore it. Otherwise pick lowest latency
			//TODO set up proper median logic
			if(select_rq->cpu_capacity>500 && select_rq->avg_latency<=*(ctx1->max_latency)){
				*(ctx1->max_latency) = select_rq->avg_latency;
				*fin = cpu;
				*(ctx1->has_good_cpu)=1;
               			return 0;
			}
			//if(*(ctx1->has_good_cpu)==0){
			//	if(select_rq->avg_latency<=*(ctx1->max_latency_bad)){
					//*(ctx1->max_latency_bad) = select_rq->avg_latency;
					//*fin = cpu;
					return 0;
			//	}
			//}

		}
		}
        }
        return 0;
}



SEC("sched/cfs_latency_select")
int BPF_PROG(test5,int prev,struct task_struct *curr,struct cpumask *idle_cpus,unsigned long util_min,unsigned long util_max)
{
    	int start = 0;
    	u32 nr_loops =NR_CPUS-1;
    	int re_value = -1;
	u64 preemption_val = 0;
	int util_perc = (curr->se.avg.util_avg * 100) / (1L << 10) ;
        if (util_perc > 10 || curr->policy == 5 ) {
              return -1;
        }
	u64 max_latency = 9999999999999;
        u64 max_latency_bad = 9999999999999;
    	int best_non_numa=-1;
        int has_good_cpu=0;
    	int best_cpc = 0;
	u64 long_at = 9999999999999999;
	u64 now = 0;
        struct rq *select_rq = bpf_this_cpu_ptr(&runqueues);
	if(select_rq){
		now = select_rq->clock_preempt;
		//if(select_rq->nr_running>3){
		//	return -1;
		//}
	//	now = 0;
	}
    	int src_numa=-1;
        int has_good_core=0;
    	unsigned long numa_bits;
    	int has_sched_idle=0;
    	struct latency_ctx ctx1 = {
        	.curr = curr,
        	.res_value = &re_value,
        	.util_min = util_min,
		.util_max = util_max,
		.idle_cpus = idle_cpus,
        	.start = prev,
		.preemption_val = &preemption_val,
		.max_latency = &max_latency,
		.has_good_cpu = &has_good_cpu,
                .max_latency_bad = &max_latency_bad,
		.now = now,
		.long_at = &long_at
	};

	bpf_loop(nr_loops, &search_latency, &ctx1, 0);
	//bpf_printk("found one %d",re_value);
	return re_value;
}

SEC("sched/cfs_latency_profile")
int BPF_PROG(test7,int cpu_select,u64 clock_now)
{
        return 1;
}

SEC("sched/cfs_correct_migration")
int BPF_PROG(test8,int cpu_select)
{
        return 1;
}

SEC("sched/cfs_spin_len")
int BPF_PROG(test20,int cpu_select)
{
        return 400000;
}
