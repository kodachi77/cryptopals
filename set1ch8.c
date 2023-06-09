#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 16

typedef struct result
{
    int max_repetitions;
    int max_line;

} result_t;

void
my_line_callback( const char* line, size_t len, void* arg, int line_idx )
{
    int    ret, reps;
    size_t i, j, n_chunks;
    char   key = '\0';
    size_t n1 = 0, n2 = 0;
    char*  s1 = NULL;

    result_t* r = (result_t*) arg;

    ret = hex2bytes( &s1, &n1, line, len, MODE_BINARY );
    assert( ret == ERR_OK && s1 && n1 );

    if( ret ) return;

    n_chunks = n1 / AES_KEY_SIZE;
    assert( n1 % AES_KEY_SIZE == 0 );

    reps = 1;
    for( i = 0; i < n_chunks - 1; i++ )
    {
        for( j = i + 1; j < n_chunks; j++ )
        {
            ret = memcmp( (const char*) line + i * AES_KEY_SIZE, (const char*) line + j * AES_KEY_SIZE, AES_KEY_SIZE );
            if( !ret ) reps += 1;
        }
    }

    if( reps > r->max_repetitions )
    {
        r->max_repetitions = reps;
        r->max_line        = line_idx;
    }

    free( s1 );
}

int
main( void )
{
    result_t r;

    memset( &r, 0, sizeof( result_t ) );

    int ret = read_lines( "set1ch8.txt", &my_line_callback, &r );
    if( ret ) return -1;

    printf( "line:                %d\n", r.max_line );
    printf( "max_repetitions:     %d\n", r.max_repetitions );

    return 0;
}