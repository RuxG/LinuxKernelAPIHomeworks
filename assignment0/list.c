// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Ruxandra Grigorie  <ruxandra.grigorie@stud.acs.upb.ro>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE		512
#define CMD_LEN			4
#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

struct list_head head;

struct list_data {
	char element[PROCFS_MAX_SIZE - CMD_LEN + 1];
	struct list_head list;
};

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct list_data *d;

	list_for_each(p, &head) {
		d = list_entry(p, struct list_data, list);
		seq_puts(m, d->element);
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static struct list_data *list_data_alloc(char *element)
{
	struct list_data *ld;

	ld = kmalloc(sizeof(*ld), GFP_KERNEL);
	if (ld == NULL)
		return NULL;

	memset(ld->element, 0, PROCFS_MAX_SIZE - CMD_LEN);
	memcpy(ld->element, element, strlen(element));
	return ld;
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	if (memcmp(local_buffer, "addf", CMD_LEN) == 0) {
		struct list_data *ld = list_data_alloc(local_buffer + CMD_LEN + 1);

		if (ld == NULL)
			return -ENOMEM;

		list_add(&ld->list, &head);

	} else if (memcmp(local_buffer, "adde", CMD_LEN) == 0) {
		struct list_data *ld = list_data_alloc(local_buffer + CMD_LEN + 1);

		if (ld == NULL)
			return -EFAULT;

		list_add_tail(&ld->list, &head);

	} else if (memcmp(local_buffer, "delf", CMD_LEN) == 0) {
		struct list_head *p;
		struct list_head *q;
		struct list_data *ld;
		bool first = false;

		list_for_each_safe(p, q, &head) {
			ld = list_entry(p, struct list_data, list);
			if (!first && strlen(ld->element) == strlen(local_buffer + CMD_LEN + 1) &&
					(memcmp(ld->element, local_buffer + CMD_LEN + 1,
						strlen(ld->element)) == 0)) {
				first = true;
				list_del(p);
				kfree(ld);
			}
		}

	} else if (memcmp(local_buffer, "dela", CMD_LEN) == 0) {
		struct list_head *p;
		struct list_head *q;
		struct list_data *ld;

		list_for_each_safe(p, q, &head) {
			ld = list_entry(p, struct list_data, list);
			if (strlen(ld->element) == strlen(local_buffer + CMD_LEN + 1) &&
					(memcmp(ld->element, local_buffer + CMD_LEN + 1,
						strlen(ld->element)) == 0)) {
				list_del(p);
				kfree(ld);
			}
		}
	}
	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	INIT_LIST_HEAD(&head);

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Ruxandra Grigorie <ruxandra.grigorie@stud.acs.upb.ro>");
MODULE_LICENSE("GPL v2");
