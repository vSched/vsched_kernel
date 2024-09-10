#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/cpumask.h>
#include <linux/sched/topology.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define BUFSIZE 6000

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Liran B.H");

static struct proc_dir_entry **ent;
extern void get_fine_stl_preempts(int cpunum, u64* preempt, u64* steals_time);

static ssize_t mywrite(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    printk(KERN_DEBUG "write handler\n");
    return -1;
}

static ssize_t myread(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) 
{
    char buf[BUFSIZE];
    int len = 0;
    u64 preempt, steals_time;
    int cpu = (int)(long)pde_data(file_inode(file));

    printk(KERN_DEBUG "read handler for CPU %d\n", cpu);

    get_fine_stl_preempts(cpu, &preempt, &steals_time);
    len = snprintf(buf, sizeof(buf), "CPU %d:\n%llu\n%llu\n", cpu, preempt, steals_time);

    if (*ppos > 0 || count < len)
        return 0;

    if (copy_to_user(ubuf, buf, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static const struct proc_ops myops = 
{
    .proc_read = myread,
    .proc_write = mywrite,
};

static int simple_init(void)
{
    int cpu;
    int num_cpus = num_online_cpus();

    ent = kmalloc(sizeof(struct proc_dir_entry *) * num_cpus, GFP_KERNEL);
    if (!ent)
        return -ENOMEM;

    for_each_online_cpu(cpu) {
        char proc_name[20];
        snprintf(proc_name, sizeof(proc_name), "preempts_cpu%d", cpu);
        ent[cpu] = proc_create_data(proc_name, 0660, NULL, &myops, (void *)(long)cpu);
        if (!ent[cpu]) {
            printk(KERN_ERR "Failed to create proc entry for CPU %d\n", cpu);
            goto cleanup;
        }
    }

    return 0;

cleanup:
    while (--cpu >= 0) {
        if (ent[cpu])
            proc_remove(ent[cpu]);
    }
    kfree(ent);
    return -ENOMEM;
}

static void simple_cleanup(void)
{
    int cpu;
    for_each_online_cpu(cpu) {
        if (ent[cpu])
            proc_remove(ent[cpu]);
    }
    kfree(ent);
}

module_init(simple_init);
module_exit(simple_cleanup);
