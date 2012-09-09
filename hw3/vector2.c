#include <linux/module.h>
#include <linux/sys_vector.h>

char vecname[VECTOR_NAME_LEN];
void *arr[NUM_SYS_CALLS];
int b_wrap_override[NUM_SYS_CALLS];

int add_syscall_vector(char *, void *, void *);
int delete_syscall_vector(char *);

/* Define Custom Syscalls here and assign hooks in set_custom_syscalls func */
asmlinkage long open2(char *file, int flags)
{
	printk(KERN_ALERT "Open2 system call\n");
	return 0;
}

void set_custom_syscalls(void)
{
	arr[5] = open2;
	b_wrap_override[5] = 0;
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
MODULE_DESCRIPTION("Module to add/remove new Syscall Vector");
MODULE_LICENSE("GPL");

module_init(new_vector_init);
module_exit(new_vector_exit);

