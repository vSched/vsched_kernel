#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>


extern int get_asym_flag(int dummy);

static int __init asym_cpucapacity_init(void)
{
    printk(KERN_INFO "sched_asym_cpucapacity: %d\n", get_asym_flag(1));
    return 0;
}

static void __exit asym_cpucapacity_exit(void)
{
    // No cleanup needed
}

module_init(asym_cpucapacity_init);
module_exit(asym_cpucapacity_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Print sched_asym_cpucapacity value");
