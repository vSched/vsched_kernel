#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#define BUFSIZE  1024
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

extern void reset_max_latency(u64 max_latency);
extern void get_max_latency(int cpunum,u64* max_latency);
static ssize_t mywrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	int num,c;
    u64 i;
	char buf[BUFSIZE];
	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu",&i);
	if(num != 1)
		return -EFAULT;
    reset_max_latency(i);
	c = strlen(buf);
	*ppos = c;
	return c;
}

int procfs_close(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;		/* success */
}


int procfs_open(struct inode *inode, struct file *file)
{
    try_module_get(THIS_MODULE);
	return 0;
}

static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
    char buf[BUFSIZE];
    int len = 0;
    int cpu;
    u64 max_latency;
    printk(KERN_DEBUG "read handler\n");

    // Iterate over each online CPU
    for_each_online_cpu(cpu) {
	get_max_latency(cpu,&max_latency);
	printk("%d",cpu);
	printk("%llu",max_latency);
        // Call your function for this CPU and append the result to the buffer
        len += snprintf(buf + len, sizeof(buf) - len, "CPU %d:\n%llu\n", cpu, max_latency);
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
	.proc_open = procfs_open,
    .proc_release = procfs_close
};
static int simple_init(void)
{

	ent=proc_create("max_latency",0666,NULL,&myops);
	return 0;
}

static void simple_cleanup(void)
{
	proc_remove(ent);
}

module_init(simple_init);
module_exit(simple_cleanup);









