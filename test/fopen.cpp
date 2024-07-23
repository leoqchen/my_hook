#include <stdio.h>
#include <sys/ioctl.h>

int main( int argc, char* argv[] )
{
    for( int i=0; i < 4; i++ ){
        FILE *fp = fopen( "/tmp/t.txt", "w" );
        if( fp != NULL ){
            int fd = fileno( fp );
            ioctl( fd, i, i*10 );

            fclose( fp );
        }else{
            printf("fopen failed!!!\n");
        }
    }

    return 0;
}
