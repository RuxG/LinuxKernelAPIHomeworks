/*
 * SO2 kprobe based tracer header file
 *
 * this is shared with user space
 */

#ifndef TRACER_H__
#define TRACER_H__ 1

#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define TRACER_DEV_MINOR 42
#define TRACER_DEV_NAME "tracer"
#define TRACER_NR_MINORS 1
#define TRACER_DEV_MAJOR 10
#define TRACER_ADD_PROCESS	_IOW(_IOC_WRITE, 42, pid_t)
#define TRACER_REMOVE_PROCESS	_IOW(_IOC_WRITE, 43, pid_t)

#define KMALLOC_ENTRIES 5000
#define LINE_LENGTH 256
#define NUM_PROCS 300
#define TRACER_FILE_MODE 0000

#endif /* TRACER_H_ */
