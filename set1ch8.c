#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
#include <emmintrin.h>
#include <math.h>
#include <pmmintrin.h>
#include <smmintrin.h>

union vector128
{
    __m128i          i128;
    unsigned __int64 u64[2];
    unsigned char    u8[16];
};
static const unsigned char* key1 = "YELLOW SUBMARINE";
static const unsigned char* key2 = "YELLOW SUBMARINE";

__m128i         x = _mm_lddqu_si128 / better _mm_loadu_si128 ( (__m128i const*) key1 );
__m128i         y = _mm_lddqu_si128 / better _mm_loadu_si128 ( (__m128i const*) key2 );
union vector128 z = { .i128 = _mm_cmpeq_epi64( x, y ) };
//__m128i z = _mm_xor_si128( x, y );

for( int i = 0; i < 2; i++ ) { printf( "0x%016I64x ", z.u64[i] ); }
printf( "\n" );
*/

#define AES_KEY_SIZE 16

typedef struct result
{
    int max_repetitions;
    int max_line;

} result_t;

void
my_line_callback( const char* line, size_t len, void* arg, int line_idx )
{
    int    i, j, ret, n_chunks, reps;
    char   key = '\0';
    size_t n1 = 0, n2 = 0;
    char * s1 = NULL, *plaintext = NULL;

    double score;

    result_t* r = (result_t*) arg;

    ret = hex2bytes( &s1, &n1, line, len, MODE_BINARY );
    assert( !ret && s1 && n1 );
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

    if( s1 ) free( s1 );
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