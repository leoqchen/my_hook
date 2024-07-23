#include <stdio.h>
#include <unistd.h>

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;
static unsigned int systemCallCount = 0;

#include "syscall_64.inl"
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

static long hook_function(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    systemCallCount++;

    if( a1 == 16 ){ // ioctl
        printf(YEL "hook: %5u, syscall %3ld \"%s( fd=%ld, request=%ld, arg=%ld )\"\n" RESET, systemCallCount, a1,
               syscall_name(a1), a2, a3, a4);
    }else{
        printf(YEL "hook: %5u, syscall %3ld \"%s\"\n" RESET, systemCallCount, a1, syscall_name(a1));
    }

	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
	printf(YEL "__hook_init: we can do some init work here\n" RESET);

	next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

	return 0;
}
