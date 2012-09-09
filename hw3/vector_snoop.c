#include <linux/module.h>
#include <linux/sys_vector.h>
#include <linux/cred.h>
#include <linux/types.h>
#include <asm/unistd_32.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>

char vecname[VECTOR_NAME_LEN];
void *arr[NUM_SYS_CALLS];
int b_wrap_override[NUM_SYS_CALLS];

int add_syscall_vector(char *, void *, void *);
int delete_syscall_vector(char *);

/* Define Custom Syscalls here and assign hooks in set_custom_syscalls func */

asmlinkage long open(char *buf, int flags)
{
	struct file *fptr;
	uid_t c_uid, o_uid;
	const struct cred *c;
	struct fown_struct owner;
	fptr = filp_open(buf, flags, 0);
	if (!fptr || IS_ERR(fptr)) {
		printk(KERN_ALERT "filp_open failed!!\n");
		return -EACCES;
	}

	c = fptr->f_cred;
	if (c != NULL)
		c_uid = c->uid;
	else
		return -EACCES;

	owner = fptr->f_owner;
	o_uid = owner.uid;

	if (o_uid != c_uid) {
		printk(KERN_ALERT "!!SNOOPING!!\n");
		printk(KERN_ALERT "file owner : %d, accessed by user : %d\n",
				(int)o_uid, (int)c_uid);
	}

	return 0;
}

/****************************************************************************/

void init_vector(void)
{
	int count = 0;
	for (; count < NUM_SYS_CALLS; count++) {
		arr[count] = NULL;
		b_wrap_override[count] = 0;
	}
}

void set_custom_syscalls(void)
{
	/*set custom function pointers*/
	arr[__NR_open] = open;

	/*set if they are overridden or wrapped*/
	b_wrap_override[__NR_open] = 1;
}

static int __init new_vector_init(void)
{
	int retval = 0;
	memset(vecname, 0x00, VECTOR_NAME_LEN);
	memcpy(vecname, THIS_MODULE->name, VECTOR_NAME_LEN);
	init_vector();
	set_custom_syscalls();
	retval = add_syscall_vector(vecname, (void **)arr,
			(void *)b_wrap_override);
	return retval;
}

static void __exit new_vector_exit(void)
{
	delete_syscall_vector(vecname);
}

MODULE_AUTHOR("Ram Maruthi Hema");
MODULE_DESCRIPTION("Module to add/remove Access Control Syscall Vector");
MODULE_LICENSE("GPL");

module_init(new_vector_init);
module_exit(new_vector_exit);

