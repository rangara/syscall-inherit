#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sys_vector.h>
#include <sys/syscall.h>

#define STDIN 0

int main(int argc, char **argv)
{
	struct timeval tv;
	fd_set readfds;
	char name[VECTOR_NAME_LEN] = {0x00,};
	int retval;

	if (argc >= 2) {
		memcpy(name, argv[1], VECTOR_NAME_LEN);
		retval = syscall(MYSYSCALL_NUM, OPT_VECTOR_LOAD, name);
		if (retval < 0) {
			printf("Error: Unable to set syscall vector\n");
			return -1;
		}
	}
	tv.tv_sec = 2;
	tv.tv_usec = 500000;

	FD_ZERO(&readfds);
	FD_SET(STDIN, &readfds);

	select(STDIN+1, &readfds, NULL, NULL, &tv);

	if (FD_ISSET(STDIN, &readfds))
		printf("A key was pressed!\n");
	else
		printf("Timed out.\n");

	return 0;
}

