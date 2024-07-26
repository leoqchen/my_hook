#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <map>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#include "syscall_64.inl"

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;
static unsigned int systemCallCount = 0;
static std::map<int, std::string> fdMap;

static void panic( const char *format, ... )
{
    va_list ap;
    va_start( ap, format );
    printf( RED "***PANIC***: " RESET );
    vprintf( format, ap );
    va_end( ap );

    exit( 1 );
}


static void fdMap_add( int fd, std::string pathname )
{
    auto pair = fdMap.try_emplace( fd, pathname );

    if( !pair.second ){
        panic("%s: ignore insert, this should not happen. fd=%d, pathname=%s\n", __func__, fd, pathname.c_str());
    }
}

static void fdMap_remove( int fd )
{
    int n = fdMap.erase( fd );

    if( n != 1 ){
        //panic("%s: ignore erase, this should not happen. fd=%d\n", __func__, fd);
        printf(RED "%s: ignore erase, this should not happen. fd=%d\n" RESET, __func__, fd);
    }
}

std::string fdMap_query( int fd )
{
    auto it = fdMap.find( fd );

    if( it != fdMap.end() ) {
        return it->second;
    }else{
        //panic("%s: not found fd=%d, this should not happen\n", __func__, fd);
        printf("%s: not found fd=%d, this should not happen\n", __func__, fd);
        return "";
    }
}


static void onExit(void)
{
    printf("syscall count: %d\n", systemCallCount);
}

static long hook_function(long a1, long a2, long a3,
                          long a4, long a5, long a6,
                          long a7)
{
    long ret = next_sys_call(a1, a2, a3, a4, a5, a6, a7);

    systemCallCount++;
    const char* name = syscall_name(a1);
    switch( a1 ){
        case 2: // open
            printf(YEL "hook: %5u, syscall %3ld \"%s( pathname=%s, flags=0x%lx, mode=0x%lx ), return fd=%ld\"\n" RESET, systemCallCount, a1, name, (const char*)a2, a3, a4, ret);
            break;

        case 3: // close
            printf(YEL "hook: %5u, syscall %3ld \"%s( fd=%ld ), return %ld\"\n" RESET, systemCallCount, a1, name, a2, ret);

            if( a2 > 0 )
                fdMap_remove( a2 );
            break;

        case 16: // ioctl
            printf(YEL "hook: %5u, syscall %3ld \"%s( fd=%ld \"%s\", request=%ld, arg=%ld ), return %ld\"\n" RESET, systemCallCount, a1, name, a2,
                   fdMap_query(a2).c_str(), a3, a4, ret);
            break;

        case 32: // dup
            printf(YEL "hook: %5u, syscall %3ld \"%s( fd=%ld ), return %ld\"\n" RESET, systemCallCount, a1, name, a2, ret);
            break;

        case 257: // openat
            printf(YEL "hook: %5u, syscall %3ld \"%s( dirfd=0x%lx, pathname=%s, flags=0x%lx, mode=0x%lx ), return fd=%ld\"\n" RESET, systemCallCount, a1, name, a2, (const char*)a3, a4, a5, ret);

            if( ret > 0 )
                fdMap_add( ret, (const char*)a3 );
            break;

        default:
            printf(YEL "hook: %5u, syscall %3ld \"%s, return %ld\"\n" RESET, systemCallCount, a1, name, ret);
            break;
    }

    return ret;
}

extern "C"
int __hook_init(long placeholder __attribute__((unused)),
                void *sys_call_hook_ptr)
{
    printf(YEL "__hook_init: we can do some init work here\n" RESET);
    atexit( onExit );

    next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
    *((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

    return 0;
}
