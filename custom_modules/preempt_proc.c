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
static struct proc_dir_entry *ent;

extern void get_fine_stl_preempts(int cpunum,u64* preempt,u64* steals_time);

static ssize_t mywrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	printk( KERN_DEBUG "write handler\n");
	return -1;
}

static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
    char buf[BUFSIZE];
    int len = 0;
    int cpu;
    u64 preempt,steals_time;
    printk(KERN_DEBUG "read handler\n");

    // Iterate over each online CPU
    for_each_online_cpu(cpu) {
	get_fine_stl_preempts(cpu,&preempt,&steals_time);
	printk("%d",cpu);
	printk("%llu",preempt);
	printk("steals");
	printk("%llu",steals_time);
        // Call your function for this CPU and append the result to the buffer
        len += snprintf(buf + len, sizeof(buf) - len, "CPU %d:\n%llu\n%llu\n", cpu, preempt,steals_time);

        // Check if the buffer is full
        if (len >= sizeof(buf)) {
            // The buffer is full, stop adding more data
            len = sizeof(buf);
            break;
        }
    }

    if (*ppos > 0 || count < len)
        return 0;  // All data has been read, or the buffer isn't big enough

    // Copy the data to user space
    if (copy_to_user(ubuf, buf, len))
        return -EFAULT;

    // Update the position
    *ppos = len;

    // Return the number of bytes read
    return len;
}


static struct proc_ops myops = 
{
	.proc_read = myread,
	.proc_write = mywrite,
	
};
static int simple_init(void)
{

	ent=proc_create("preempts",0660,NULL,&myops);
	return 0;
}

static void simple_cleanup(void)
{
	proc_remove(ent);
}

module_init(simple_init);
module_exit(simple_cleanup);









