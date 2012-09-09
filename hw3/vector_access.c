#include <linux/module.h>
#include <linux/sys_vector.h>
#include <linux/cred.h>
#include <linux/types.h>
#include <asm/unistd_32.h>
#include <linux/sched.h>

char vecname[VECTOR_NAME_LEN];
void *arr[NUM_SYS_CALLS];
int b_wrap_override[NUM_SYS_CALLS];

int add_syscall_vector(char *, void *, void *);
int delete_syscall_vector(char *);

/* Define Custom Syscalls here and assign hooks in set_custom_syscalls func */

int check_access(void)
{
	const struct cred *c = get_current()->cred;
	uid_t c_uid;

	if (c != NULL)
		c_uid = c->uid;
	else
		return -EACCES;

	if ((int)c_uid == 0) {
		/*printk(KERN_ALERT "c-UID : %d\n", (int)c_uid);*/
		return 0;
	}
	printk(KERN_ALERT "No permission to user. Only root access..\n");
	return -EACCES;
}

asmlinkage long write(int fd, const void *buf, size_t count)
{
	printk(KERN_ALERT "Access Control Vector : Write invoked.\n");
	if (fd == 1 || fd == 2)
		return 0;
	return check_access();
}

asmlinkage long create(void)
{
	printk(KERN_ALERT "Access Control Vector : Create invoked.\n");
	return check_access();
}

asmlinkage long unlink(void)
{
	printk(KERN_ALERT "Access Control Vector : Unlink invoked.\n");
	return check_access();
}

asmlinkage long mknod(void)
{
	printk(KERN_ALERT "Access Control Vector : Mknod invoked.\n");
	return check_access();
}

asmlinkage long mkdir(void)
{
	printk(KERN_ALERT "Access Control Vector : Mkdir invoked.\n");
	return check_access();
}

asmlinkage long rmdir(void)
{
	printk(KERN_ALERT "Access Control Vector : Rmdir invoked.\n");
	return check_access();
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
	arr[__NR_write] = write;
	arr[__NR_creat] = create;
	arr[__NR_unlink] = unlink;
	arr[__NR_mknod] = mknod;
	arr[__NR_mkdir] = mkdir;
	arr[__NR_rmdir] = rmdir;

	/*set if they are overridden or wrapped*/
	b_wrap_override[__NR_write] = 1;
	b_wrap_override[__NR_creat] = 1;
	b_wrap_override[__NR_unlink] = 1;
	b_wrap_override[__NR_mknod] = 1;
	b_wrap_override[__NR_mkdir] = 1;
	b_wrap_override[__NR_rmdir] = 1;
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

