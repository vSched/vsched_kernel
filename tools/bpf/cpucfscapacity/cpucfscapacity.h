/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __CPUCFSCAPACITY_H
#define __CPUCFSCAPACITY_H 

#define TASK_COMM_LEN 16

struct event {
	char task[TASK_COMM_LEN];
	pid_t pid;
	int cpu;
	int capacity;
};

#endif /* __CPUCFSCAPACITY_H */
