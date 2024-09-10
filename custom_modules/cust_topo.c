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
#define PROCFS_NAME "edit_topology"
#define BUFFER_SIZE 8096

static struct proc_dir_entry *topology_proc;
extern cpumask_var_t cpu_l2c_shared_map;
extern void set_l2c_shared_mask(int cpu,struct cpumask new_mask);
extern void set_llc_shared_mask(int cpu,struct cpumask new_mask);
struct cpumask cpuset_array[NR_CPUS];
EXPORT_SYMBOL(cpuset_array);
static int test_integer = 3;

void iterate_cpus(const struct cpumask *mask) {
    int cpu;
    printk(KERN_INFO "ITERATING");
    // Iterate through the set CPUs in the mask
    for_each_cpu(cpu, mask) {
        // Do something with the CPU index (cpu)
        printk(KERN_INFO "CPU %d is set in the mask\n", cpu);
    }
}

void mass_iterate(struct sched_domain_topology_level *topology) {
	int level=0;
	while(topology[level].mask != NULL){
		printk("Name: %s", topology[level].name);
		printk("Level: %d",level);
		printk("Mask Address %p",topology[level].mask);
		for(int z=0;z<NR_CPUS;z++) {
			printk("    Return cMask Address %p,Cpu %d",topology[level].mask(z),z);
			int cpu;
			for_each_cpu(cpu,topology[level].mask(z)){
				printk(KERN_INFO "CPU %d is set in the mask\n", cpu);
			}
		}
		printk("\n");
		level++;
	}
}

const struct cpumask *stackingMask(int cpu) {
    static cpumask_t mask;
    //printk(KERN_INFO "test", test_integer);
    //iterate_cpus(&cpuset_array[index]);
    cpumask_clear(&mask);
    cpumask_copy(&mask,&cpuset_array[cpu]);

    // Set only the specified CPU bit
    if (cpu >= 0 && cpu < nr_cpu_ids) {
        cpumask_set_cpu(cpu, &mask);
    }

    return &mask;
}







struct sched_domain_topology_level *get_list_with_starting_stacking(struct sched_domain_topology_level *topology) {
    int size = 1;
    while (topology[size].mask != NULL) size++;  

    //cpuset_array = kmalloc(NR_CPUS * sizeof(struct cpumask), GFP_KERNEL);
    if(cpuset_array == NULL){
         printk("ABORT");
	 return NULL;
    }
    for (int i = 0; i < NR_CPUS; i++) {
        cpumask_clear(&cpuset_array[i]);
    }
    struct sched_domain_topology_level *new_top = kmalloc((size + 1) * sizeof(struct sched_domain_topology_level), GFP_KERNEL);
    if (new_top == NULL) {
        // Handle allocation failure
	printk("WARNING,WARING");
        return NULL;
    }
    //Initialize the first element
    new_top[0] = topology[0];
//  new_top[0].sd_flags =  SD_SHARE_CPUCAPACITY | SD_SHARE_PKG_RESOURCES;
    new_top[0].name=kmalloc(strlen("STK")+1,GFP_KERNEL);
    new_top[0].name="STK";

    // Copy the old elements, shifted by one
    for (int i = 0; i < size; i++) {
        new_top[i+1] = topology[i];
    }

    return new_top;
}



void my_custom_function(char *data) {
    printk(KERN_INFO "Registered Write to edit_topology...\n");
    struct sched_domain_topology_level *topology = get_sched_topology();
    if (topology != NULL) {
	printk(KERN_INFO "Scheduling Domain Topology retrieved.\n");
        printk(KERN_INFO "Data received: %s\n", data);
	cpumask_t use_cpumask;
	cpumask_clear(&use_cpumask);
//	if(strcmp(topology[0].name,"SMT")==0){
//		topology = get_list_with_starting_stacking(topology);
//	}
//	topology[0].mask = stackingMask;
        int sched_domain=0;

	int comp_cpu=0;

	int cpu=0;

	char currentChar = *data;

        while(*data != '\0') {
            currentChar = *data;
            if(currentChar == ';') {
		if(sched_domain==0){
			cpumask_copy(&cpuset_array[cpu],&use_cpumask);
		}else{
//			if(sched_domain==1){
//				cpumask_copy(topology[2].mask(cpu),&use_cpumask);
//			}
//			cpumask_copy(topology[sched_domain].mask(cpu),&use_cpumask);
		}
//		(topology[sched_domain].mask(cpu)) = use_cpumask;
		cpumask_copy(topology[sched_domain].mask(cpu),&use_cpumask);
		cpumask_clear(&use_cpumask);
		cpu++;
                comp_cpu=0;
            }else if(currentChar == ':') {
		sched_domain++;
//		if(sched_domain==2){
//			sched_domain++;
//		}
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
    } else {
        printk(KERN_WARNING "Failed to retrieve Scheduling Domain Topology.\n");
    }
}

static ssize_t procfile_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
        //iterate_cpus(get_cpuset(0));
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

    // Here, you'll need to parse procfs_buffer to convert it into a list of lists format
    // For now, it's just passed as a string
    my_custom_function(procfs_buffer);

    //kfree(procfs_buffer);
    return count;
}

static const struct proc_ops proc_file_fops = {
    .proc_write = procfile_write,
    .proc_read = procfile_read,
};


static int __init sched_topology_module_init(void) {
    topology_proc = proc_create(PROCFS_NAME, 0666, NULL, &proc_file_fops);
    if (topology_proc == NULL) {
        proc_remove(topology_proc);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
    return 0;
}


static void __exit sched_topology_module_exit(void)
{
    proc_remove(topology_proc);
    printk(KERN_INFO "Exiting sched_topology_module.\n");
}

module_init(sched_topology_module_init);
module_exit(sched_topology_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple Linux module using get_sched_topology.");

