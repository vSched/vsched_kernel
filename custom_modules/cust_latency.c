#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/topology.h>
#include <linux/arch_topology.h>
#include <linux/sched/topology.h>
#include <linux/cpumask.h>
#include <linux/proc_fs.h>
#include <linux/acpi.h>
#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <linux/cpuset.h>
#include <linux/cpufreq.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#define PROCFS_NAME "edit_latency"
#define BUFFER_SIZE 4096
static struct proc_dir_entry *capacity_proc;
extern void set_custom_capacity(unsigned long capacity, int cpu);
extern void set_avg_latency(int cpu,u64 number);



void set_capacities(char *data) {
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
        kstrtol(token, 100, &number);
	printk("This is the latency %lu of core %index",(unsigned long)number, index);
        set_avg_latency(index,(unsigned long long)number);
	index=index+1;
    }

    kfree(data_copy);
    return;
}

static ssize_t procfile_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
	printk( KERN_DEBUG "read handler\n");
        return -1;
}


ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
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

static const struct proc_ops proc_file_fops = {
    .proc_write = procfile_write,
    .proc_read = procfile_read,
};


static int __init sched_capacity_module_init(void) {
    capacity_proc = proc_create(PROCFS_NAME, 0666, NULL, &proc_file_fops);
    if (capacity_proc == NULL) {
        proc_remove(capacity_proc);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
    return 0;
}


static void __exit sched_capacity_module_exit(void)
{
    proc_remove(capacity_proc);
    printk(KERN_INFO "Exiting sched_capacity_module.\n");
}

module_init(sched_capacity_module_init);
module_exit(sched_capacity_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A Linux Module to set custom capacity");
