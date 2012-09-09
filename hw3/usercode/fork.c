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
	char name[VECTOR_NAME_LEN] = {0x00,};
	int retval;

	if (argc >= 2) {
		memcpy(name, argv[1], VECTOR_NAME_LEN);
		retval = syscall(MYSYSCALL_NUM, OPT_VECTOR_LOAD, name);
		if (retval < 0) {
			printf("Error : %d - ", errno);
			fflush(stdout);
			perror("");
			return -1;
		}
	}

	if (fork() == 0) {
		retval = syscall(MYSYSCALL_NUM, OPT_VECTOR_LOAD, "vector2");
		retval = open("output.txt", O_RDONLY);
	} else
		retval = open("output.txt", O_RDONLY);
	if (retval < 0) {
		printf("Error : %d - ", errno);
		fflush(stdout);
		perror("");
		return -1;
	}

	return 0;
}
