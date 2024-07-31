#include <stdio.h>
#include <stdlib.h>
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

static void onExit(void)
{
    printf("syscall count: %d\n", systemCallCount);
}

static void getPathFromFileDescriptor( int fd, char *buf, int bufsize )
{
    char path[64];
    sprintf( path, "/proc/self/fd/%d", fd );
    ssize_t count = readlink( path, buf, bufsize-1 );
    if( count > 0 )
        buf[count] = '\0';
    else
        buf[0] = '\0';
}

static long hook_function(long a1, long a2, long a3,
                          long a4, long a5, long a6,
                          long a7)
{
    char path[128];
    switch( a1 ){
        case 3: // close
            getPathFromFileDescriptor( a2, path, sizeof(path) );
            break;

        default:
            break;
    }

    long ret = next_sys_call(a1, a2, a3, a4, a5, a6, a7);

    systemCallCount++;
    const char* name = syscall_name(a1);
    switch( a1 ){
        case 2: // open
            printf(YEL "hook: %5u, syscall %3ld \"%s( pathname=%s, flags=0x%lx, mode=0x%lx ), return fd=%ld\"\n" RESET, systemCallCount, a1, name, (const char*)a2, a3, a4, ret);
            break;

        case 3: // close
            printf(YEL "hook: %5u, syscall %3ld \"%s( fd=%ld, path=%s ), return %ld\"\n" RESET, systemCallCount, a1, name, a2, path, ret);
            break;

        case 16: // ioctl
            getPathFromFileDescriptor( a2, path, sizeof(path) );
            printf(YEL "hook: %5u, syscall %3ld \"%s( fd=%ld, path=%s, request=0x%lx, arg=0x%lx ), return %ld\"\n" RESET, systemCallCount, a1,
                   name, a2, path, a3, a4, ret);
            break;

        case 32: // dup
            getPathFromFileDescriptor( a2, path, sizeof(path) );
            printf(YEL "hook: %5u, syscall %3ld \"%s( fd=%ld, path=%s ), return %ld\"\n" RESET, systemCallCount, a1, name, a2, path, ret);
            break;

        case 257: // openat
            printf(YEL "hook: %5u, syscall %3ld \"%s( dirfd=0x%lx, pathname=%s, flags=0x%lx, mode=0x%lx ), return fd=%ld\"\n" RESET, systemCallCount, a1, name, a2, (const char*)a3, a4, a5, ret);
            break;

        default:
            printf(YEL "hook: %5u, syscall %3ld \"%s, return %ld\"\n" RESET, systemCallCount, a1, name, ret);
            break;
    }

    return ret;
}

int __hook_init(long placeholder __attribute__((unused)),
                void *sys_call_hook_ptr)
{
    printf(YEL "__hook_init: we can do some init work here\n" RESET);
    atexit( onExit );

    next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
    *((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

    return 0;
}
