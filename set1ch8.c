#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

typedef struct result
{
    int max_repetitions;
    int line;

} result_t;

void
my_line_callback( const char* line, size_t len, void* arg, int line_idx )
{
    result_t* r = (result_t*) arg;

    char*  s1  = NULL;
    size_t n1  = 0;
    int    ret = cp_hex2bytes( &s1, &n1, line, len, MODE_BINARY );
    assert( ret == ERR_OK && s1 && n1 );

    if( ret != ERR_OK ) return;

    size_t n_chunks = n1 / AES_BLOCK_SIZE;
    assert( n1 % AES_BLOCK_SIZE == 0 );

    size_t i, j;
    int    reps = 0;
    for( i = 0; i < n_chunks - 1; i++ )
    {
        for( j = i + 1; j < n_chunks; j++ )
        {
            ret = memcmp( (const char*) line + i * AES_BLOCK_SIZE, (const char*) line + j * AES_BLOCK_SIZE,
                          AES_BLOCK_SIZE );
            if( !ret ) reps += 1;
        }
    }

    if( reps > r->max_repetitions )
    {
        r->max_repetitions = reps;
        r->line            = line_idx;
    }

    free( s1 );
}

int
main( void )
{
    result_t r;
    memset( &r, 0, sizeof( result_t ) );
    int ret = cp_read_lines( "set1ch8.txt", &my_line_callback, &r );
    assert( ret == ERR_OK && r.max_repetitions > 1 );

    printf( "line:                %d\n", r.line );
    printf( "max_repetitions:     %d\n", r.max_repetitions );

    return 0;
}