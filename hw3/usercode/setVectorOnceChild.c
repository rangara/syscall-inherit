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

	retval = open("output.txt", O_RDONLY);

	if (fork() == 0) {
		if (argc >= 3) {
			memset(name, 0x00, VECTOR_NAME_LEN);
			memcpy(name, argv[2], VECTOR_NAME_LEN);
			printf("Child sleeping 10 secs..\n");
			sleep(10);
			printf("Child wokeup.. setting syscall vector %s\n",
					name);
			retval = syscall(MYSYSCALL_NUM, OPT_VECTOR_LOAD, name);
			if (retval < 0) {
				printf("Error : %d - ", errno);
				fflush(stdout);
				perror("");
				return -1;
			}
			printf("Child successfully set new vector.\n");
			printf("Child again sleeping 10 seconds..\n");
			sleep(10);
			retval = open("output.txt", O_RDONLY);
		}
	} else {
		printf("parent sleeping for 20 secs\n");
		sleep(20);
		retval = open("output.txt", O_RDONLY);
	}
	if (retval < 0) {
		printf("Error : %d - ", errno);
		fflush(stdout);
		perror("");
		return -1;
	}

	return 0;
}
