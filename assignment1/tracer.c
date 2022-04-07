#include "tracer.h"

static const char *proc_file_header = "PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\tlock\tunlock\n";

struct kmalloc_memory_map {
	unsigned long address;
	size_t size;
	struct list_head list;	
	int index;
};

struct monitor_calls {
	pid_t pid;
	spinlock_t lock;
	struct list_head list;
	
	struct list_head kmalloc_list;

	u_int kmalloc_calls;
	ssize_t kmalloc_bytes;	

	u_int kfree_calls;
	ssize_t kfree_bytes;

	u_int sched_calls;
	u_int up_calls;
	u_int down_calls;
	u_int lock_calls;
	u_int unlock_calls;

};

struct tracer {
	struct miscdevice misc;

	u_int kmalloc_memory_entries;
	struct kmalloc_memory_map *entries;
	bool *occupied_entry;

	spinlock_t lock;
	
	u_int num_procs;

	struct list_head monitor_list_head;
};

struct kmalloc_data {
	ssize_t size;
	unsigned long address;
};

static struct tracer tr;

static int tracer_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int tracer_release(struct inode *inode, struct file *file)
{
	return 0;
}

static void clean_up_entries(void)
{
	struct list_head *p, *q;
	struct monitor_calls *mc;
	spin_lock(&tr.lock);
	list_for_each_safe(p, q, &tr.monitor_list_head) {
		mc = list_entry(p, struct monitor_calls, list);
		struct list_head *pm, *pq;
		struct kmalloc_memory_map *kd;

		list_for_each_safe(pm, pq, &mc->kmalloc_list) {
			kd = list_entry(pm, struct kmalloc_memory_map, list);
			list_del(pm);
		}

		list_del(p);   
		
		kfree(mc);
	}

	spin_unlock(&tr.lock);	
}

static long tracer_ioctl (struct file *file, unsigned int cmd, unsigned long arg) {

	pid_t pid = arg;
	struct list_head *p, *q, *pm, *pq;
	struct monitor_calls *mc;
	struct kmalloc_memory_map *kd;	
	struct monitor_calls *new_struct;

	switch(cmd) {
	
		case TRACER_ADD_PROCESS:
			new_struct = kmalloc(sizeof(struct monitor_calls), GFP_KERNEL);
			if (new_struct == NULL) {
				return ENOMEM;
			}

			spin_lock(&tr.lock);

			if (tr.num_procs >= NUM_PROCS) {
				spin_unlock(&tr.lock);
				pr_err("Process number limit exceeded.\n");
				return -1;
				kfree(new_struct);
			}

			list_for_each(p, &tr.monitor_list_head) {
				mc = list_entry(p, struct monitor_calls, list);
				if (mc->pid == pid) {
					spin_unlock(&tr.lock);
					kfree(new_struct);
					pr_err("Process is already being monitored.\n");
					return -1;
				}
			}
			
			new_struct->pid = pid;

			INIT_LIST_HEAD(&(new_struct->kmalloc_list));
			new_struct->kmalloc_calls = 0;
			new_struct->kmalloc_bytes = 0;
			new_struct->kfree_calls = 0;
			new_struct->kfree_bytes= 0;
			new_struct->sched_calls = 0;
			new_struct->up_calls = 0;
			new_struct->down_calls = 0;
			new_struct->lock_calls = 0;
			new_struct->unlock_calls = 0;

			list_add(&(new_struct->list), &(tr.monitor_list_head));

			tr.num_procs++;

			spin_unlock(&tr.lock);

			break;

		case TRACER_REMOVE_PROCESS:
			
			spin_lock(&tr.lock);

			bool found = false;

			list_for_each_safe(p, q, &tr.monitor_list_head) {
				mc = list_entry(p, struct monitor_calls, list);

				if (mc->pid == pid) {
					found = true;
					list_for_each_safe(pm, pq, &mc->kmalloc_list) {
						kd = list_entry(pm, struct kmalloc_memory_map, list);
						tr.occupied_entry[kd->index] = false;
						list_del_init(pm);
						tr.kmalloc_memory_entries--;
					}
					
					tr.num_procs--;

					list_del(p);

					break;
				}
				
			}
			spin_unlock(&tr.lock);

			if (found) kfree(mc);

			break;

		default:
			return -ENOTTY;
	}

	return 0;
}

static int tracer_read (struct seq_file *file, void *v) {

	spin_lock(&tr.lock);

	seq_puts(file, proc_file_header);

	struct list_head *p, *q;
	struct monitor_calls *mc;
	list_for_each_safe(p, q, &tr.monitor_list_head) {

		mc = list_entry(p, struct monitor_calls, list);

		seq_printf(file, "%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n", 
				mc->pid, mc->kmalloc_calls, mc->kfree_calls, mc->kmalloc_bytes,
			       	mc->kfree_bytes, mc->sched_calls, mc->up_calls, mc->down_calls, 
				mc->lock_calls, mc->unlock_calls);
	}
	
	spin_unlock(&tr.lock);

	return 0;
}

static int tracer_read_open(struct inode *inode, struct file *file) {
	return single_open(file, tracer_read, NULL);
}

static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.open = tracer_open,
	.release = tracer_release,
	.unlocked_ioctl= tracer_ioctl,
};

static const struct proc_ops tracer_pops = {
	.proc_open = tracer_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static int kmalloc_probe_entry_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {

	struct kmalloc_data *data = (struct kmalloc_data*) kretprobe->data;
	data->size = regs->ax;
	return 0;
}


static struct monitor_calls *find_process_monitor(pid_t pid) {
	struct list_head *p;
	struct monitor_calls *mc;

	list_for_each(p, &tr.monitor_list_head) {
	
		mc = list_entry(p, struct monitor_calls, list);
		if (mc->pid == pid) {
			return mc;
		}
	}

	return NULL;
}

static int kmalloc_probe_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {

	struct kmalloc_data *data = (struct kmalloc_data*) kretprobe->data;
	if (data == NULL) {
		return 0;
	}
	data->address = (unsigned long)regs_return_value(regs);

	spin_lock(&tr.lock);

	struct monitor_calls *process_monitor = find_process_monitor(current->pid);
	if (process_monitor == NULL) {
		spin_unlock(&tr.lock);
		return 0;
	}

	if (tr.kmalloc_memory_entries >= KMALLOC_ENTRIES) {
		spin_unlock(&tr.lock);
		return 0;
	}

	int i = 0;
	for (i = 0; i < KMALLOC_ENTRIES; i++) {
		if (!tr.occupied_entry[i]) {
			tr.occupied_entry[i] = true;
			break;
		}	
	}	
	tr.kmalloc_memory_entries++;

	struct kmalloc_memory_map *map = &(tr.entries[i]);

	map->index = i;
	map->address = data->address;
	map->size = data->size;
	process_monitor->kmalloc_bytes += data->size;
	process_monitor->kmalloc_calls += 1;
	
	list_add(&(map->list), &(process_monitor->kmalloc_list));
	spin_unlock(&tr.lock);

	return 0;
}

static int kfree_probe_entry_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {

	unsigned long p = (unsigned long)regs->ax;

	spin_lock(&tr.lock);

	struct monitor_calls *process_monitor = find_process_monitor(current->pid);
	if (process_monitor == NULL) {
		spin_unlock(&tr.lock);
		return 0;
	}

	struct list_head *pr;
	struct kmalloc_memory_map *mc;
	
	list_for_each(pr, &process_monitor->kmalloc_list) {
		mc = list_entry(pr, struct kmalloc_memory_map, list);

		if (mc->address == p) {
			process_monitor->kfree_calls++;
			process_monitor->kfree_bytes += mc->size;
			list_del_init(pr);
			tr.kmalloc_memory_entries--;
			tr.occupied_entry[mc->index] = false;
			break;
		}
	}

	spin_unlock(&tr.lock);

	return 0;
}
static int lock_probe_entry_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {

	spin_lock(&tr.lock);

	struct monitor_calls *process_monitor = find_process_monitor(current->pid);
	if (process_monitor == NULL) {
		spin_unlock(&tr.lock);
		return 0;
	}
	process_monitor->lock_calls++;	

	spin_unlock(&tr.lock);

	return 0;
}


static int unlock_probe_entry_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {

	spin_lock(&tr.lock);
	struct monitor_calls *process_monitor = find_process_monitor(current->pid);
	if (process_monitor == NULL) {
		spin_unlock(&tr.lock);
		return 0;

	}

	process_monitor->unlock_calls++;
	spin_unlock(&tr.lock);	
	return 0;
}

static int sched_probe_entry_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {

	spin_lock(&tr.lock);
	struct monitor_calls *process_monitor = find_process_monitor(current->pid);
	if (process_monitor == NULL) {
		spin_unlock(&tr.lock);
		return 0;
	}
	process_monitor->sched_calls++;	
	
	spin_unlock(&tr.lock);

	return 0;
}
static int up_probe_entry_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {
	
	spin_lock(&tr.lock);
	
	struct monitor_calls *process_monitor = find_process_monitor(current->pid);
	if (process_monitor == NULL) {
		spin_unlock(&tr.lock);
		return 0;

	}
	process_monitor->up_calls++;	
	
	spin_unlock(&tr.lock);

	return 0;
}

static int down_probe_entry_handler(struct kretprobe_instance *kretprobe, struct pt_regs *regs) {
	
	spin_lock(&tr.lock);
	struct monitor_calls *process_monitor = find_process_monitor(current->pid);
	if (process_monitor == NULL) {
		spin_unlock(&tr.lock);
		return 0;

	}

	process_monitor->down_calls++;	
	
	spin_unlock(&tr.lock);

	return 0;
}

static struct kretprobe kmalloc_probe = {
	.entry_handler = kmalloc_probe_entry_handler,
	.handler = kmalloc_probe_handler,
	.maxactive = 32,
	.data_size = sizeof(struct kmalloc_data),
};

static struct kretprobe kfree_probe = {
	.entry_handler = kfree_probe_entry_handler,
	.maxactive = 32,
};

static struct kretprobe sched_probe = {
	.entry_handler = sched_probe_entry_handler,
	.maxactive = 64,
};

static struct kretprobe lock_probe = {
	.entry_handler = lock_probe_entry_handler,
	.maxactive = 32,
};

static struct kretprobe unlock_probe = {
	.entry_handler = unlock_probe_entry_handler,
	.maxactive = 32,
};

static struct kretprobe up_probe = {
	.entry_handler = up_probe_entry_handler,
	.maxactive = 32,
};

static struct kretprobe down_probe = {
	.entry_handler = down_probe_entry_handler,
	.maxactive = 32,
};

static int tracer_init(void) {

	int err;

    	tr.misc.minor = TRACER_DEV_MINOR;
        tr.misc.name = TRACER_DEV_NAME;
	tr.misc.fops = &tracer_fops;
	INIT_LIST_HEAD(&tr.monitor_list_head);
	spin_lock_init(&(tr.lock));
	
	tr.num_procs = 0;

	tr.kmalloc_memory_entries = 0;
	tr.entries = kmalloc(KMALLOC_ENTRIES * sizeof(struct kmalloc_memory_map), GFP_KERNEL);	
	if (tr.entries == NULL) {
		pr_err("kmalloc failed\n");
		return ENOMEM;
	}

	tr.occupied_entry = kmalloc(KMALLOC_ENTRIES * sizeof(bool), GFP_KERNEL);
	if (tr.occupied_entry == NULL) {
		pr_err("kmalloc failed\n");
		kfree(tr.entries);
		return ENOMEM;
	}
	memset(tr.occupied_entry, 0, KMALLOC_ENTRIES * sizeof(bool));


	err = misc_register(&(tr.misc));
	if (err) {
		pr_err("register_region failed: %d\n", err);
		kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	}

	if (!proc_create(TRACER_DEV_NAME, TRACER_FILE_MODE, NULL, &tracer_pops)) {
		pr_info("Failed to create proc entry\n");
		misc_deregister(&(tr.misc));
		kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	}

	kmalloc_probe.kp.symbol_name = "__kmalloc";
	err = register_kretprobe(&kmalloc_probe);
	if (err < 0) {
		pr_err("register kretprobe kmalloc failed: %d\n", err);
	 	misc_deregister(&(tr.misc));
		remove_proc_entry(TRACER_DEV_NAME, NULL);
	 	kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	
	}

	kfree_probe.kp.symbol_name = "kfree";
	err = register_kretprobe(&kfree_probe);
	if (err < 0) {
		pr_err("register kretprobe kfree failed: %d\n", err);
		unregister_kretprobe(&kmalloc_probe);
	 	misc_deregister(&(tr.misc));
		remove_proc_entry(TRACER_DEV_NAME, NULL);
	 	kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	}

	lock_probe.kp.symbol_name = "mutex_lock_nested";
	err = register_kretprobe(&lock_probe);
	if (err < 0) {
		pr_err("register kretprobe lock failed: %d\n", err);
		unregister_kretprobe(&kmalloc_probe);
		unregister_kretprobe(&kfree_probe);
	 	misc_deregister(&(tr.misc));
		remove_proc_entry(TRACER_DEV_NAME, NULL);
	 	kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	}

	unlock_probe.kp.symbol_name = "mutex_unlock";
	err = register_kretprobe(&unlock_probe);
	if (err < 0) {
		pr_err("register kretprobe unlock failed: %d\n", err);
		unregister_kretprobe(&kmalloc_probe);
		unregister_kretprobe(&kfree_probe);
		unregister_kretprobe(&lock_probe);
	 	misc_deregister(&(tr.misc));
		remove_proc_entry(TRACER_DEV_NAME, NULL);
	 	kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	}

	sched_probe.kp.symbol_name = "schedule";
	err = register_kretprobe(&sched_probe);
	if (err < 0) {
		pr_err("register kretprobe schedule failed: %d\n", err);
		unregister_kretprobe(&kmalloc_probe);
		unregister_kretprobe(&kfree_probe);
		unregister_kretprobe(&lock_probe);
		unregister_kretprobe(&unlock_probe);
	 	misc_deregister(&(tr.misc));
		remove_proc_entry(TRACER_DEV_NAME, NULL);
	 	kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	}

	up_probe.kp.symbol_name = "up";
	err = register_kretprobe(&up_probe);
	if (err < 0) {
		pr_err("register kretprobe up failed: %d\n", err);
		unregister_kretprobe(&kmalloc_probe);
		unregister_kretprobe(&kfree_probe);
		unregister_kretprobe(&lock_probe);
		unregister_kretprobe(&unlock_probe);
		unregister_kretprobe(&sched_probe);
	 	misc_deregister(&(tr.misc));
		remove_proc_entry(TRACER_DEV_NAME, NULL);
	 	kfree(tr.entries);
		kfree(tr.occupied_entry);
		return err;
	}

	down_probe.kp.symbol_name = "down_interruptible";
	err = register_kretprobe(&down_probe);
	if (err < 0) {
		pr_err("register kretprobe down failed: %d\n", err);
		unregister_kretprobe(&kmalloc_probe);
		unregister_kretprobe(&kfree_probe);
		unregister_kretprobe(&lock_probe);
		unregister_kretprobe(&unlock_probe);
		unregister_kretprobe(&sched_probe);
		unregister_kretprobe(&up_probe);
	
		misc_deregister(&(tr.misc));
		remove_proc_entry(TRACER_DEV_NAME, NULL);
	 	kfree(tr.entries);
		kfree(tr.occupied_entry);
	}

	return err;
}

static void tracer_exit(void) {

	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	unregister_kretprobe(&unlock_probe);
	unregister_kretprobe(&lock_probe);
	unregister_kretprobe(&sched_probe);
	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);

	misc_deregister(&(tr.misc));
	remove_proc_entry(TRACER_DEV_NAME, NULL);
	clean_up_entries();
	kfree(tr.entries);
	kfree(tr.occupied_entry);
	pr_notice("Driver %s unloaded\n", TRACER_DEV_NAME);

}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_LICENSE("GPL");
