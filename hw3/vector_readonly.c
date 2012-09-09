#include <linux/module.h>
#include <linux/sys_vector.h>
#include <asm/unistd_32.h>

char vecname[VECTOR_NAME_LEN];
void *arr[NUM_SYS_CALLS];
int b_wrap_override[NUM_SYS_CALLS];

int add_syscall_vector(char *, void *, void *);
int delete_syscall_vector(char *);

/* Define Custom Syscalls here and assign hooks in set_custom_syscalls func */
asmlinkage long write(int fd)
{
	printk(KERN_ALERT "Only writes to stdout or stderr are allowed.\n");
	if (fd == 1 || fd == 2) /* Allow writes only to stdout and stderr */
		return 0;
	printk(KERN_ALERT "Error : Read Only Vector : write invoked.\n");
	return -EACCES;
}

asmlinkage long create(void)
{
	printk(KERN_ALERT "Error : Read Only Vector : create invoked.\n");
	return -EACCES;
}

asmlinkage long unlink(void)
{
	printk(KERN_ALERT "Error : Read Only Vector : unlink invoked.\n");
	return -EACCES;
}

asmlinkage long mknod(void)
{
	printk(KERN_ALERT "Error : Read Only Vector : mknod invoked.\n");
	return -EACCES;
}

asmlinkage long mkdir(void)
{
	printk(KERN_ALERT "Error : Read Only Vector : mkdir invoked.\n");
	return -EACCES;
}

asmlinkage long rmdir(void)
{
	printk(KERN_ALERT "Error : Read Only Vector : rmdir invoked.\n");
	return -EACCES;
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
	b_wrap_override[__NR_creat] = 0;
	b_wrap_override[__NR_unlink] = 0;
	b_wrap_override[__NR_mknod] = 0;
	b_wrap_override[__NR_mkdir] = 0;
	b_wrap_override[__NR_rmdir] = 0;
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
MODULE_DESCRIPTION("Module to add/remove Read only Syscall Vector");
MODULE_LICENSE("GPL");

module_init(new_vector_init);
module_exit(new_vector_exit);

