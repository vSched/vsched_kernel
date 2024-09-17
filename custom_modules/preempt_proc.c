#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#define BUFSIZE  6000
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/cpumask.h>
#include <linux/sched/topology.h>
#include <linux/types.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Liran B.H");
static struct proc_dir_entry *get_info_ent;
static struct proc_dir_entry *capacity_ent;
static struct proc_dir_entry *topo_ent;
static struct proc_dir_entry *latency_ent;

extern void get_fine_stl_preempts(int cpunum,u64* preempt,u64* steal_time);
extern void reset_max_latency(u64 max_latency);
extern void get_max_latency(int cpunum,u64* max_latency);
extern void set_custom_capacity(unsigned long capacity, int cpu);
extern void set_avg_latency(unsigned long latency,int cpu);


extern cpumask_var_t cpu_l2c_shared_map;
extern void set_l2c_shared_mask(int cpu,struct cpumask new_mask);
extern void set_llc_shared_mask(int cpu,struct cpumask new_mask);
struct cpumask cpuset_array[NR_CPUS];
static int test_integer = 3;
EXPORT_SYMBOL(cpuset_array);




static ssize_t blank_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	printk( KERN_DEBUG "write handler\n");
	return -1;
}

static ssize_t blank_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
	printk( KERN_DEBUG "read handler\n");
    return -1;
}


void set_capacities(char *data) 
{
	char *token, *cur;
	char *data_copy;
	int index = 0;
	long number;

	data_copy = kstrdup(data, GFP_KERNEL);
	if (!data_copy)
        return;
            
 	cur = data_copy;
 	while ((token = strsep(&cur, ";")) != NULL) {
        if (*token == '\0')
            continue;
        kstrtol(token, 10, &number);
	    printk("Capacity:%lu Cpu%d:",(unsigned long)number,index);
        set_custom_capacity((unsigned long)number, index);
	    set_avg_latency(1,1);
	    index=index+1;
    }
    kfree(data_copy);
    return;
}

ssize_t capacity_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
    char *procfs_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

    if (count > BUFFER_SIZE) {
        count = BUFFER_SIZE;
    }

    if (copy_from_user(procfs_buffer, buffer, count)) {
        kfree(procfs_buffer);
        return -EFAULT;
    }


    set_capacities(procfs_buffer);
    kfree(procfs_buffer);
    return count;
}

void set_latencies(char *data) {
	char *token, *cur;
	char *data_copy;
	int index = 0;
	long number;
    u64 i;
	data_copy = kstrdup(data, GFP_KERNEL);
	if (!data_copy)
        return;
    reset_max_latency(i);
 	cur = data_copy;
 	while ((token = strsep(&cur, ";")) != NULL) {
        if (*token == '\0')
            continue;
        kstrtol(token, 100, &number);
        set_avg_latency(index,(unsigned long long)number);
        index=index+1;
    }

    kfree(data_copy);
    return;
}

ssize_t latency_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
    char *procfs_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

    if (count > BUFFER_SIZE) {
        count = BUFFER_SIZE;
    }

    if (copy_from_user(procfs_buffer, buffer, count)) {
        kfree(procfs_buffer);
        return -EFAULT;
    }
    set_latencies(procfs_buffer);
    kfree(procfs_buffer);
    return count;
}



void set_topology(char *data) {
    struct sched_domain_topology_level *topology = get_sched_topology();
    if (topology == NULL) {
        printk(KERN_WARNING "Failed to retrieve Scheduling Domain Topology.\n");
        return;
    }

    cpumask_t use_cpumask;
    cpumask_clear(&use_cpumask);
    int sched_domain=0;
    int comp_cpu=0;
    int cpu=0;
    char currentChar = *data;

    while(*data != '\0') {
        currentChar = *data;
        if(currentChar == ';') {
		    if(sched_domain==0) {
			    cpumask_copy(&cpuset_array[cpu],&use_cpumask);
		    }
		    cpumask_copy(topology[sched_domain].mask(cpu),&use_cpumask);
		    cpumask_clear(&use_cpumask);
		    cpu++;
            comp_cpu=0;
        } else if(currentChar == ':') {
		    sched_domain++;
            comp_cpu=0;
            cpu=0;
        }else{
            if(currentChar=='1') {
                cpumask_set_cpu(comp_cpu,&use_cpumask);
		    }
            comp_cpu++;
            }
	    data++;
    }
    set_live_topology(topology);
   
}


ssize_t topology_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
    char *procfs_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

    if (count > BUFFER_SIZE) {
        count = BUFFER_SIZE;
    }

    if (copy_from_user(procfs_buffer, buffer, count)) {
        kfree(procfs_buffer);
        return -EFAULT;
    }

    set_topology(procfs_buffer);
    kfree(procfs_buffer);
    return count;
}


static ssize_t get_info_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
    char buf[BUFSIZE];
    int len = 0;
    int cpu;
    u64 preempt,steal_time,max_latency;

    for_each_online_cpu(cpu) {
	    get_fine_stl_preempts(cpu,&preempt,&steal_time);   
        get_max_latency(cpu,&max_latency);
        len += snprintf(buf + len, sizeof(buf) - len, "CPU %d:\n%llu\n%llu\n%llu\n", cpu, preempt,steal_time,max_latency);
        if (len >= sizeof(buf)) {
            len = sizeof(buf);
            break;
        }
    }

    if (*ppos > 0 || count < len)
        return 0;  

    if (copy_to_user(ubuf, buf, len))
        return -EFAULT;

    *ppos = len;

    return len;
}


static struct proc_ops get_information_ops = 
{
	.proc_read = get_info_read,
	.proc_write = blank_write,
}


static const struct proc_ops cust_capacity_ops = 
{
	.proc_read = blank_read,
	.proc_write = capacity_write,
}

static const struct proc_ops cust_latency_ops = 
{
	.proc_read = blank_read,
	.proc_write = latency_write,
}


static const struct proc_ops cust_topo_ops = 
{
	.proc_read = blank_read,
	.proc_write = blank_write,
}


static int vsched_init(void)
{
    
    get_info_ent = proc_create("vcap_info", 0666, NULL, &proc_file_fops);
	capacity_ent = proc_create("vcapacity_write",0660,NULL,&get_information_ops);
    latency_ent = proc_create("vlatency_write",0660,NULL,&cust_capacity_ops);
	topo_ent = proc_create("vtopology_write",0660,NULL,&cust_latency_ops);

    if (get_info_ent == NULL || capacity_ent == NULL || topo_ent == NULL || latency_ent == NULL) {
        proc_remove(get_info_ent);
        proc_remove(capacity_ent);
        proc_remove(latency_ent);
        proc_remove(topo_ent);*

        printk(KERN_ALERT "Error: Could not successfully initialize vSched's kernel modules - check your kernel version\n");
        return 0;
    }
    printk(KERN_ALERT "Sucessfully initalized vSched's Kernel modules\n");
	return 0;
}


static void vsched_cleanup(void)
{
	proc_remove(get_info_ent);
    proc_remove(capacity_ent);
    proc_remove(latency_ent);
    proc_remove(topo_ent);*
}

module_init(vsched_init);
module_exit(vsched_cleanup);









