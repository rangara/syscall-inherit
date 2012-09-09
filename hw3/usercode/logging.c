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
			perror("");
			return -1;
		}
	}

	/* read, write, open, close, creat, unlink */
	fd = open("output.txt", O_RDWR);
	if (fd < 0) {
		printf("error : %d\n", fd);
		perror("open: ");
		return -1;
	}
	printf("open success!!\n");

	bytes = read(fd, buf, 10);
	if (bytes < 0) {
		perror("read: ");
		return -1;
	}
	printf("read success!!\n");

	bytes = write(fd, "Writing.", 10);
	if (bytes < 0) {
		perror("write: ");
		return -1;
	}
	printf("write success!!\n");

	close(fd);

	fd = creat("testFile", O_CREAT);
	if (fd < 0) {
		perror("creat: ");
		return -1;
	}
	printf("creat success!!\n");

	retval = unlink("testFile");
	if (retval < 0) {
		perror("unlink: ");
		return -1;
	}
	printf("unlink success!!\n");

	return 0;
}
