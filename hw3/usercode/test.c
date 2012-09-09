#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sys_vector.h>
#include <sys/syscall.h>

int main(int argc, char **argv)
{
	int retval;
	printf("In exec'ed process!!\n");
	retval = open("output.txt", O_RDONLY);
	printf("retval : %d\n", retval);
	return 0;
}
