#define NUM_SYS_CALLS 350
#define MYSYSCALL_NUM 349

#define OPT_VECTOR_LIST 0
#define OPT_VECTOR_LOAD 1
#define OPT_VECTOR_COUNT 2

#define VECTOR_NAME_LEN 60

extern void *my_syscall_ptr;
extern void *my_fork_func_ptr;
extern void *my_exit_func_ptr;
extern void *my_exec_func_ptr;

struct vector_names{
	int count;
	char **list;
};
