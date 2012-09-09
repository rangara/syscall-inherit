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

asmlinkage long write(int fd, const void *buf, size_t count)
{
	printk(KERN_ALERT "Access Control Vector : Write system call invoked.\n");
	if (fd < 0 || strstr((char *)buf, "/root/")) {
		printk(KERN_ALERT "Access Control Vector : Parameter validation failed.\n");
		return -EACCES;
	}
	return 0;
}

asmlinkage long create(char *pathname, mode_t mode)
{
	printk(KERN_ALERT "Access Control Vector : Create system call invoked.\n");
	if (strstr(pathname, "/root/")) {
		printk(KERN_ALERT "Access Control Vector : Parameter validation failed.\n");
		return -EACCES;
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
	arr[__NR_write] = write;
	arr[__NR_creat] = create;

	/*set if they are overridden or wrapped*/
	b_wrap_override[__NR_write] = 1;
	b_wrap_override[__NR_creat] = 1;
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

