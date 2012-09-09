#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/sys_vector.h>
#include <asm/unistd_32.h>

struct syscall_vector_data {
	atomic_t refcount;
	char name[VECTOR_NAME_LEN];
	void *vecptr;
	int *b_wrap_override;
	struct list_head mylist;
};

struct rw_semaphore lock_vector;
struct syscall_vector_data sysVectors;


int kmalloc_check(void *data)
{
	int err = 0;
	if (!data) {
		err = -ENOMEM;
		printk(KERN_INFO "Error : kmalloc returned NULL.\n");
	}
	return err;
}

/* add_syscall_vector : initialization routine invoked when insmod is done.
 * A new entry is created in sysVectors list.
 */
int add_syscall_vector(char *name, void **vecptr, void *b_wrap_override)
{
	/* Grab a lock on the sysVectors list and add the vector. */
	int err = 0;
	struct syscall_vector_data *tmp;
	if (vecptr[__NR_exit] || vecptr[__NR_fork]
		|| vecptr[__NR_clone] || vecptr[__NR_exit_group]) {
		printk(KERN_INFO "Syscall is prohibited from overwriting!\n");
		return -1;
	}

	tmp = kmalloc(sizeof(struct syscall_vector_data), GFP_KERNEL);
	err = kmalloc_check((void *)tmp);
	if (err < 0)
		goto err_kmalloc;

	memcpy(tmp->name, name, VECTOR_NAME_LEN);
	tmp->vecptr = vecptr;
	tmp->b_wrap_override = (int *)b_wrap_override;
	atomic_set(&(tmp->refcount), 0);
	down_write(&lock_vector);
	list_add(&(tmp->mylist), &(sysVectors.mylist));
	up_write(&lock_vector);
	return 0;
err_kmalloc:
	return err;
}
EXPORT_SYMBOL(add_syscall_vector);

/* delete_syscall_vector : cleanup routine invoked when rmmod is successful.
 * The vector is freed from sysVectors.
 */
int delete_syscall_vector(char *name)
{
	/* Grab a lock on the sysVectors list and delete the vector. */
	struct list_head *pos, *q;
	struct syscall_vector_data *tmp;
	bool is_vector_found = false;
	down_write(&lock_vector);
	list_for_each_safe(pos, q, &sysVectors.mylist) {
		tmp = list_entry(pos, struct syscall_vector_data, mylist);
		if (memcmp(tmp->name, name, strlen(name)) == 0) {
			list_del(pos);
			kfree(tmp);
			is_vector_found = true;
			break;
		}
	}
	up_write(&lock_vector);
	if (!is_vector_found)
		printk(KERN_INFO "Error : Vector not loaded.\n");
	return 0;
}
EXPORT_SYMBOL(delete_syscall_vector);

/* Increase the refcount of a vector when a new process is created. */
int on_process_fork(void *ptr)
{
	/* Grab a lock on the sysVectors list and modify the refcount. */
	struct list_head *pos;
	struct syscall_vector_data *tmp;
	bool is_vector_found = false;
	down_read(&lock_vector);
	list_for_each(pos, &sysVectors.mylist) {
		tmp = list_entry(pos, struct syscall_vector_data, mylist);
		if (tmp->vecptr == ptr) {
			atomic_inc(&(tmp->refcount));
			try_module_get(find_module(tmp->name));
			is_vector_found = true;
			break;
		}
	}
	up_read(&lock_vector);
	if (!is_vector_found)
		printk(KERN_INFO "Error : Vector not loaded.\n");
	return 0;
}

/* Decrease the refcount of a vector when a process exits */
int on_process_exit(void *ptr)
{
	/* Grab a lock on the sysVectors list and modify the refcount. */
	struct list_head *pos;
	struct syscall_vector_data *tmp;
	bool is_vector_found = false;
	down_read(&lock_vector);
	list_for_each(pos, &sysVectors.mylist) {
		tmp = list_entry(pos, struct syscall_vector_data, mylist);
		if (tmp->vecptr == ptr) {
			atomic_dec(&(tmp->refcount));
			module_put(find_module(tmp->name));
			is_vector_found = true;
			break;
		}
	}
	up_read(&lock_vector);
	if (!is_vector_found)
		printk(KERN_INFO "Error : Vector not loaded.\n");
	return 0;
}

int on_process_exec(void *ptr)
{
	return 0;
}

long my_actual_call(int option, void *data)
{
	int count = 0, vec_count = 0;
	char *k_input = NULL;
	struct task_struct *ptr = NULL;
	struct list_head *pos;
	struct syscall_vector_data *tmp;
	bool is_vector_found = false;
	struct vector_names *vecnames = NULL;
	struct vector_names *k_vecnames = NULL;
	int err = 0;
	char **names_list = NULL;

	/* OPT_VECTOR_COUNT and OPT_VECTOR_LIST options are used together.
	 * OPT_VECTOR_COUNT returns the number of syscalls currently loaded.
	 * OPT_VECTOR_LIST returns a (char **) of vector names.
	 * This (char **) buffer is allocated by user program based on
	 * the number of syscall vectors loaded. We copy the vector names
	 * into the user buffer by copy_to_user().
	 */
	if (option == OPT_VECTOR_COUNT) {
		if (!(access_ok(VERIFY_WRITE, data, sizeof(int *)))) {
			err = -EACCES;
			printk(KERN_INFO "Error : access_ok returned FALSE."
					"Invalid user pointer data.\n");
			return -1;
		}
		down_read(&lock_vector);
		list_for_each(pos, &sysVectors.mylist) {
			tmp = list_entry(pos, struct syscall_vector_data,
					mylist);
			count++;
		}
		up_read(&lock_vector);
		*(int *)data = count;
	} else if (option == OPT_VECTOR_LIST) {
		vecnames = (struct vector_names *)data;

		/*verify the vector names struct area*/
		if (!(access_ok(VERIFY_READ, data,
						sizeof(struct vector_names)))) {
			err = -EACCES;
			printk(KERN_INFO "Error : access_ok returned FALSE."
					"Invalid user pointer data.\n");
			goto out;
		}

		k_vecnames = kmalloc(sizeof(struct vector_names), GFP_KERNEL);
		err = kmalloc_check(k_vecnames);
		if (err < 0)
			goto out;

		/*copy the vector names struct*/
		if (copy_from_user(k_vecnames, vecnames,
					sizeof(struct vector_names))) {
			err = -EFAULT;
			printk(KERN_INFO "Error : copy_from_user failed.\n");
			goto free_k_vecnames;
		}
		vec_count = k_vecnames->count;

		/*verify the ptr to the names list*/
		if (!(access_ok(VERIFY_READ, k_vecnames->list,
						vec_count * sizeof(char *)))) {
			err = -EACCES;
			printk(KERN_INFO "Error : access_ok returned FALSE."
					"Invalid user pointer data->list.\n");
			goto free_k_vecnames;
		}

		names_list = kmalloc(vec_count * sizeof(char *), GFP_KERNEL);
		err = kmalloc_check(names_list);
		if (err < 0)
			goto free_k_vecnames;

		/* copy the pointers to the names.*/
		if (copy_from_user(names_list, k_vecnames->list,
					vec_count * sizeof(char *))) {
			err = -EFAULT;
			printk(KERN_INFO "Error : copy_from_user failed.\n");
			goto free_names_list;
		}

		for (count = 0; count < vec_count; count++) {
			if (!(access_ok(VERIFY_WRITE, names_list[count],
							VECTOR_NAME_LEN))) {
				err = -EACCES;
				printk(KERN_INFO "Error: access_ok failed\n");
				goto free_names_list;
			}
		}

		count = 0;
		/* Take a read lock on sysVectors before accessing it */
		down_read(&lock_vector);
		list_for_each(pos, &sysVectors.mylist) {
			if (count >= vec_count)
				break;
			tmp = list_entry(pos, struct syscall_vector_data,
					mylist);
			if (tmp && tmp->name) {
				copy_to_user(names_list[count], tmp->name,
						VECTOR_NAME_LEN);
			}
			count++;
		}
		up_read(&lock_vector);

free_names_list:
		kfree(names_list);
free_k_vecnames:
		kfree(k_vecnames);

	} else if (option == OPT_VECTOR_LOAD) {
		/* OPT_VECTOR_LOAD sets the vector specified in data
		 * to the current process
		 */
		if (!(access_ok(VERIFY_READ, data, VECTOR_NAME_LEN))) {
			err = -EACCES;
			printk(KERN_INFO "Error : access_ok returned FALSE."
					"Invalid user pointer.\n");
			return -1;
		}

		k_input = kmalloc(VECTOR_NAME_LEN, GFP_KERNEL);
		err = kmalloc_check((void *)k_input);
		if (err < 0)
			goto err_kmalloc;

		if (copy_from_user(k_input, data, VECTOR_NAME_LEN)) {
			err = -EFAULT;
			printk(KERN_INFO "Error : copy_from_user failed.\n");
			goto err_kmalloc;
		}

		/* Get struct task_struct pointer of current process */
		ptr = get_current();

		/* Check if vector is already set in the current process.
		 * A process can set a vector only once during its lifetime.
		 * When a process is forked, the child process inherits
		 * the syscall vector from parent. But it can set its own
		 * vector.
		 */
		if (ptr->is_vector_set != 0) {
			printk(KERN_INFO "Vector already set!!\n");
			err = -EACCES;
			goto err_kmalloc;
		}

		/* If vector pointer is inherited from parent and if child
		 * wants to set its own vector, we must first reduce the
		 * refcount of the first vector, and then set the new vector
		 * to child.
		 */
		if (ptr->sys_vector_ptr)
			on_process_exit(ptr->sys_vector_ptr);

		/* Check if k_input is a valid vector name in sysVectors.
		 * Also, need a lock while accessing this array of sysVectors.
		 */
		down_read(&lock_vector);
		list_for_each(pos, &sysVectors.mylist) {
			tmp = list_entry(pos, struct syscall_vector_data,
					mylist);
			if (memcmp(tmp->name, k_input, strlen(k_input)) == 0) {
				try_module_get(find_module(tmp->name));
				atomic_inc(&(tmp->refcount));
				ptr->sys_vector_ptr = tmp->vecptr;
				ptr->wrap_override = tmp->b_wrap_override;
				ptr->is_vector_set = 1;
				is_vector_found = true;
				break;
			}
		}
		up_read(&lock_vector);

		if (!is_vector_found) {
			printk(KERN_INFO "Error : Vector not loaded.\n");
			err = -EINVAL;
		}

err_kmalloc:
		kfree(k_input);
	}
out:
	return err;
}

static int __init mysyscall_init(void)
{

	printk(KERN_INFO "Init Module. Assigning function ptr to mycall\n");

	if (my_syscall_ptr == NULL) {
		init_rwsem(&lock_vector);
		down_write(&lock_vector);
		INIT_LIST_HEAD(&sysVectors.mylist);
		up_write(&lock_vector);
		my_syscall_ptr = my_actual_call;
		my_exit_func_ptr = on_process_exit;
		my_fork_func_ptr = on_process_fork;
		my_exec_func_ptr = on_process_exec;
	} else {
		printk(KERN_ALERT "the syscall ptr is not NULL.\n");
	}
	return 0;
}

static void __exit mysyscall_exit(void)
{
	printk(KERN_INFO "Exit Module. Assigning function ptr to NULL\n");
	if (my_syscall_ptr == my_actual_call) {
		my_syscall_ptr = NULL;
		my_exit_func_ptr = NULL;
		my_fork_func_ptr = NULL;
		my_exec_func_ptr = NULL;
	} else {
		printk(KERN_ALERT "syscall ptr is invalid!!\n");
	}
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ram Maruthi Hema");
MODULE_DESCRIPTION("Syscall for modifying task struct");

module_init(mysyscall_init);
module_exit(mysyscall_exit);

