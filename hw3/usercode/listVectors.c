#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/sys_vector.h>

int main(int argc, char **argv)
{
	int retval, vec_count;
	struct vector_names veclist;

	/* Get vector count */
	retval = syscall(MYSYSCALL_NUM, OPT_VECTOR_COUNT, &vec_count);
	if (retval < 0) {
		printf("Failed to obtain vector count. Error : %d - ", errno);
		fflush(stdout);
		perror(" obtain");
		return -1;
	}
	veclist.count = vec_count;

	/* Get vector list */
	veclist.list = calloc(vec_count, sizeof(char *));
	for (vec_count = 0; vec_count < veclist.count; vec_count++)
		veclist.list[vec_count] = calloc(1, VECTOR_NAME_LEN);
	retval = syscall(MYSYSCALL_NUM, OPT_VECTOR_LIST, &veclist);
	if (retval < 0) {
		printf("Error : %d - ", errno);
		fflush(stdout);
		perror("");
		return -1;
	}

	/* Print vector list */
	printf("------------ Vector List ------------\n");
	for (vec_count = 0; vec_count < veclist.count; vec_count++)
		printf("%d. %s\n", vec_count+1, veclist.list[vec_count]);
	return 0;
}
