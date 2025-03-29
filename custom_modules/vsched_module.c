#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/sched/topology.h>
#include <linux/cpumask.h>
#include <linux/types.h>
#include <linux/slab.h>
#define MAX_TOPOLOGY_LEVEL 3

#define BUFSIZE 6000

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Liran B.H");

static struct proc_dir_entry *get_info_ent;
static struct proc_dir_entry *capacity_ent;
static struct proc_dir_entry *av_capacity_ent;
static struct proc_dir_entry *topo_ent;
static struct proc_dir_entry *latency_ent;

/* External function declarations */
extern void get_steal_and_preemptions(int cpunum, u64* preempt, u64* steal_time);
extern void reset_max_latency(u64 max_latency);
extern void get_max_latency(int cpunum, u64* max_latency);
extern void set_custom_capacity(unsigned long capacity, int cpu);
extern void set_avg_latency(unsigned long latency, int cpu);
extern void set_live_topology(struct sched_domain_topology_level *topology);
extern void set_average_capacity_all(int value);
extern int get_average_capacity_all;
extern struct sched_domain_topology_level *get_sched_topology(void);
extern cpumask_var_t cpu_l2c_shared_map;
extern void set_l2c_shared_mask(int cpu, struct cpumask new_mask);
extern void set_llc_shared_mask(int cpu, struct cpumask new_mask);

/* Global variables */
struct cpumask cpuset_array[NR_CPUS];
EXPORT_SYMBOL(cpuset_array);

/* Function declarations */
static ssize_t blank_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos);
static ssize_t blank_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos);
static ssize_t get_info_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos);
static ssize_t capacity_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset);
static ssize_t latency_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset);
static ssize_t topology_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset);
static ssize_t av_capacity_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset);
static void set_capacities(char *data);
static void set_av_capacity(char *data);
static void set_latencies(char *data);
static void set_topology(const char *data, size_t count);

/* Function implementations */
static ssize_t blank_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    printk(KERN_DEBUG "write handler\n");
    return -1;
}

static ssize_t blank_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    printk(KERN_DEBUG "read handler\n");
    return -1;
}

static void set_capacities(char *data) 
{
    char *token, *cur;
    char *data_copy;
    int cpu_index = 0;
    long capacity_value;

    data_copy = kstrdup(data, GFP_KERNEL);
    if (!data_copy)
        return;
            
    cur = data_copy;
    while ((token = strsep(&cur, ";")) != NULL) {
        if (*token == '\0')
            continue;
        if (kstrtol(token, 10, &capacity_value) == 0) {
            printk("Capacity:%lu Cpu%d:", (unsigned long)capacity_value, cpu_index);
            set_custom_capacity((unsigned long)capacity_value, cpu_index);
            cpu_index++;
        }
    }
    kfree(data_copy);
}

static ssize_t capacity_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) 
{
    char *input_buffer;
    ssize_t status = count;

    if (count > BUFSIZE) {
        count = BUFSIZE;
    }

    input_buffer = kmalloc(count + 1, GFP_KERNEL);
    if (!input_buffer)
        return -ENOMEM;

    if (copy_from_user(input_buffer, buffer, count)) {
        kfree(input_buffer);
        return -EFAULT;
    }
    
    input_buffer[count] = '\0';
    set_capacities(input_buffer);
    kfree(input_buffer);
    
    return status;
}

static void set_av_capacity(char *data) 
{
    long capacity_value;
    
    if (kstrtol(data, 10, &capacity_value) == 0) {
        printk(KERN_INFO "Setting average capacity to: %ld\n", capacity_value);
        set_average_capacity_all((unsigned int)capacity_value);
    } else {
        printk(KERN_ERR "Invalid input for average capacity\n");
    }
}

static ssize_t av_capacity_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) 
{
    char *input_buffer;
    ssize_t status = count;

    if (count > BUFSIZE) {
        count = BUFSIZE;
    }

    input_buffer = kmalloc(count + 1, GFP_KERNEL);
    if (!input_buffer)
        return -ENOMEM;

    if (copy_from_user(input_buffer, buffer, count)) {
        kfree(input_buffer);
        return -EFAULT;
    }
    
    input_buffer[count] = '\0';
    set_av_capacity(input_buffer);
    kfree(input_buffer);
    
    return status;
}

static void set_latencies(char *data) 
{
    char *token, *cur;
    char *data_copy;
    int cpu_index = 0;
    long latency_value;

    data_copy = kstrdup(data, GFP_KERNEL);
    if (!data_copy)
        return;

    reset_max_latency(0);
    cur = data_copy;
    
    while ((token = strsep(&cur, ";")) != NULL) {
        if (*token == '\0')
            continue;
            
        if (kstrtol(token, 10, &latency_value) == 0) {
            printk("cpu at %d has latency: %llu", cpu_index, (unsigned long long)latency_value);
            set_avg_latency(cpu_index, (unsigned long long)latency_value);
            cpu_index++;
        }
    }
    kfree(data_copy);
}

static ssize_t latency_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) 
{
    char *input_buffer;
    ssize_t status = count;

    if (count > BUFSIZE) {
        count = BUFSIZE;
    }

    input_buffer = kmalloc(count + 1, GFP_KERNEL);
    if (!input_buffer)
        return -ENOMEM;

    if (copy_from_user(input_buffer, buffer, count)) {
        kfree(input_buffer);
        return -EFAULT;
    }
    
    input_buffer[count] = '\0';
    set_latencies(input_buffer);
    kfree(input_buffer);
    
    return status;
}

static void set_topology(const char *data, size_t count) 
{
    struct sched_domain_topology_level *topology = get_sched_topology();
    int sched_domain = 0;
    int cpu = 0;
    size_t bit_index = 0;
    static cpumask_t use_cpumask;  /* Static to avoid stack usage */
    int num_cpus;
    int comp_cpu;
    
    num_cpus = num_present_cpus();
    
    if (topology == NULL) {
        printk(KERN_WARNING "Failed to retrieve Scheduling Domain Topology.\n");
        return;
    }

    while (bit_index < count * 8 && sched_domain < MAX_TOPOLOGY_LEVEL) {
        cpumask_clear(&use_cpumask);

        /* Read bits for current CPU */
        for (comp_cpu = 0; comp_cpu < num_cpus && bit_index < count * 8; comp_cpu++, bit_index++) {
            if (test_bit(bit_index, (unsigned long *)data)) {
                cpumask_set_cpu(comp_cpu, &use_cpumask);
            }
        }

        if (sched_domain == 0) {
            cpumask_copy(&cpuset_array[cpu], &use_cpumask);
        }
        cpumask_copy(topology[sched_domain].mask(cpu), &use_cpumask);

        cpu++;

        /* If we've processed all CPUs for this level or reached end of data */
        if (cpu == num_cpus || bit_index >= count * 8) {
            sched_domain++;
            cpu = 0;
        }
    }

    set_live_topology(topology);
}

static ssize_t topology_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) 
{
    char *input_buffer;
    ssize_t status = count;

    input_buffer = kmalloc(count, GFP_KERNEL);
    if (!input_buffer)
        return -ENOMEM;

    if (copy_from_user(input_buffer, buffer, count)) {
        kfree(input_buffer);
        return -EFAULT;
    }

    set_topology(input_buffer, count);
    kfree(input_buffer);
    
    return status;
}

static ssize_t get_info_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) 
{
    static char buf[BUFSIZE];
    int len = 0;
    int cpu;
    u64 preempt, steal_time, max_latency;

    if (*ppos > 0)
        return 0;

    for_each_online_cpu(cpu) {
        get_steal_and_preemptions(cpu, &preempt, &steal_time);   
        get_max_latency(cpu, &max_latency);
        
        len += snprintf(buf + len, sizeof(buf) - len, 
                       "CPU %d:\n%llu\n%llu\n%llu\n", 
                       cpu, preempt, steal_time, max_latency);
                       
        if (len >= sizeof(buf) - 1) {
            break;
        }
    }

    if (count < len)
        return 0;

    if (copy_to_user(ubuf, buf, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static const struct proc_ops get_information_ops = {
    .proc_read = get_info_read,
    .proc_write = blank_write,
};

static const struct proc_ops cust_capacity_ops = {
    .proc_read = blank_read,
    .proc_write = capacity_write,
};

static const struct proc_ops cust_av_capacity_ops = {
    .proc_read = blank_read,
    .proc_write = av_capacity_write,
};

static const struct proc_ops cust_latency_ops = {
    .proc_read = blank_read,
    .proc_write = latency_write,
};

static const struct proc_ops cust_topo_ops = {
    .proc_read = blank_read,
    .proc_write = topology_write,
};

static int vsched_init(void)
{
    get_info_ent = proc_create("vcap_info", 0666, NULL, &get_information_ops);
    capacity_ent = proc_create("vcapacity_write", 0660, NULL, &cust_capacity_ops);
    latency_ent = proc_create("vlatency_write", 0660, NULL, &cust_latency_ops);
    topo_ent = proc_create("vtopology_write", 0660, NULL, &cust_topo_ops);
    av_capacity_ent = proc_create("vav_capacity_write", 0660, NULL, &cust_av_capacity_ops);

    if (!get_info_ent || !capacity_ent || !topo_ent || !latency_ent || !av_capacity_ent) {
        proc_remove(get_info_ent);
        proc_remove(capacity_ent);
        proc_remove(latency_ent);
        proc_remove(topo_ent);
        proc_remove(av_capacity_ent);

        printk(KERN_ALERT "Error: Could not successfully initialize vSched's kernel modules - check your kernel version\n");
        return -ENOMEM;
    }
    
    printk(KERN_ALERT "Successfully initialized vSched's Kernel modules\n");
    return 0;
}

static void vsched_cleanup(void)
{
    proc_remove(av_capacity_ent);
    proc_remove(get_info_ent);
    proc_remove(capacity_ent);
    proc_remove(latency_ent);
    proc_remove(topo_ent);
}

module_init(vsched_init);
module_exit(vsched_cleanup);
