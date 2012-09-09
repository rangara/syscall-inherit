#include <linux/module.h>
#include <linux/sys_vector.h>
#include <asm/unistd_32.h>

char vecname[VECTOR_NAME_LEN];
void *arr[NUM_SYS_CALLS];
int b_wrap_override[NUM_SYS_CALLS];

int add_syscall_vector(char *, void *, void *);
int delete_syscall_vector(char *);

/* Define Custom Syscalls here and assign hooks in set_custom_syscalls func */
asmlinkage long read(void)
{
	printk(KERN_ALERT "Logging Vector : Read system call invoked.\n");
	return 0;
}

asmlinkage long write(void)
{
	printk(KERN_ALERT "Logging Vector : Write system call invoked.\n");
	return 0;
}

asmlinkage long open(char *buf, int flags)
{
	printk(KERN_ALERT "Logging vector : Open system call invoked.\n");
	return 0;
}

asmlinkage long close(void)
{
	printk(KERN_ALERT "Logging vector : Close system call invoked.\n");
	return 0;
}


asmlinkage long create(void)
{
	printk(KERN_ALERT "Logging Vector : Create system call invoked.\n");
	return 0;
}


asmlinkage long unlink(void)
{
	printk(KERN_ALERT "Logging Vector : Unlink system call invoked.\n");
	return 0;
}

asmlinkage long select(int nfds)
{
	printk(KERN_ALERT "Logging vector : Select System call invoked.\n");
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
	arr[__NR_read] = read;
	arr[__NR_write] = write;
	arr[__NR_open] = open;
	arr[__NR_close] = close;
	arr[__NR_creat] = create;
	arr[__NR_unlink] = unlink;

	arr[__NR__newselect] = select;

	/*set if they are overridden or wrapped*/
	b_wrap_override[__NR_read] = 1;
	b_wrap_override[__NR_write] = 1;
	b_wrap_override[__NR_open] = 1;
	b_wrap_override[__NR_close] = 1;
	b_wrap_override[__NR_creat] = 1;
	b_wrap_override[__NR_unlink] = 1;

	b_wrap_override[__NR__newselect] = 1;
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
MODULE_DESCRIPTION("Module to add/remove Logging Syscall Vector");
MODULE_LICENSE("GPL");

module_init(new_vector_init);
module_exit(new_vector_exit);

