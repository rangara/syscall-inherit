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
	int fd, bytes, retval;
	char buf[11] = {0x00,};
	if (argc >= 2) {
		memcpy(name, argv[1], VECTOR_NAME_LEN);
		retval = syscall(MYSYSCALL_NUM, OPT_VECTOR_LOAD, name);
		if (retval < 0) {
			printf("Error: Unable to set syscall vector\n");
			return -1;
		}
	}

	/* write, creat, unlink, mknod, mkdir, rmdir */
	fd = open("output.txt", O_RDWR);
	if (fd < 0) {
		printf("open error\n");
		return -1;
	}

	bytes = read(fd, buf, 10);
	if (bytes < 0) {
		printf("read error\n");
		return -1;
	}
	printf("Read from file : %s\n", buf);

	bytes = write(fd, "Writing..", 10);
	if (bytes < 0)
		printf("write error\n");

	close(fd);

	fd = creat("testFile", O_CREAT);
	if (fd < 0)
		printf("creat error\n");

	retval = unlink("testFile");
	if (retval < 0)
		printf("unlink error\n");

	retval = mknod("output", S_IFREG, 0);
	if (retval < 0)
		printf("mknod error\n");

	retval = mkdir("testdir", 0777);
	if (retval < 0)
		printf("mkdir error\n");

	retval = rmdir("testdir");
	if (retval < 0)
		printf("rmdir error\n");

	return 0;
}
