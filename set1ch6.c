#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

#include "utils.h"

#ifdef __GNUC__
#define __popcnt __builtin_popcount
#endif

#define MAX_KEY_LENGTH 42
#define N_CHUNKS       4

static inline int
hamming_distance( const char* buf1, const char* buf2, size_t len )
{
    int r = 0;
    for( size_t i = 0; i < len; i++ ) r += __popcnt( buf1[i] ^ buf2[i] );
    return r;
}

int
break_repeating_xor_key( char* dst, size_t dst_len, char* key, size_t key_len )
{
    assert( key && key_len );
    assert( dst_len > MAX_KEY_LENGTH * N_CHUNKS );

    char   chunks[N_CHUNKS][MAX_KEY_LENGTH] = { 0 };
    double hamming_dist[MAX_KEY_LENGTH]     = { 0 };

    size_t i, j, k;

    const size_t N_COMBINATIONS = N_CHUNKS * ( N_CHUNKS - 1 ) / 2;

    hamming_dist[0] = INT_MAX;
    hamming_dist[1] = INT_MAX;

    for( k = 2; k < MAX_KEY_LENGTH; ++k )
    {
        for( i = 0; i < N_CHUNKS; ++i ) { memcpy( &chunks[i][0], &dst[i * k], k ); }

        hamming_dist[k] = 0;
        for( i = 0; i < N_CHUNKS - 1; i++ )
        {
            for( j = i + 1; j < N_CHUNKS; j++ ) { hamming_dist[k] += hamming_distance( chunks[i], chunks[j], k ); }
        }
        hamming_dist[k] /= 1.0 * N_COMBINATIONS * k;
    }

    double min_score        = INT_MAX;
    int    detected_key_len = -1;
    for( i = 0; i < MAX_KEY_LENGTH; i++ )
    {
        if( hamming_dist[i] < min_score )
        {
            min_score        = hamming_dist[i];
            detected_key_len = (int) i;
        }
    }
    assert( detected_key_len > 0 );
    assert( detected_key_len + 1 <= key_len );

    if( detected_key_len <= 0 || detected_key_len + 1 > key_len ) return ERR_GENERIC_ERROR;

    char* block = (char*) malloc( dst_len / detected_key_len + 1 );
    if( !block ) return ERR_INSUFFICIENT_MEMORY;

    int ret = ERR_OK;
    for( i = 0; i < detected_key_len; ++i )
    {
        k = 0;
        for( j = i; j < dst_len; j += detected_key_len ) { block[k++] = dst[j]; }

        double score = 0.0;
        ret          = cp_break_single_char_xor( block, k, &key[i], &score );
        if( ret != ERR_OK ) break;
    }
    free( block );

    key[detected_key_len] = 0;

    if( ret == ERR_OK && detected_key_len > 0 )
    {
        ret          = cp_repeating_xor( dst, dst_len, key, detected_key_len );
        dst[dst_len] = 0;
    }

    return ret;
}

int
main( void )
{
    assert( hamming_distance( "this is a test", "wokka wokka!!!", 14 ) == 37 );

    char * b1 = NULL, *b2 = NULL;
    size_t n1 = 0, n2 = 0;

    int ret = cp_read_all( &b1, &n1, "set1ch6.txt", MODE_BINARY );
    assert( ret == ERR_OK && b1 && n1 );

    ret = cp_base64_decode( &b2, &n2, b1, n1, MODE_TEXT );
    assert( ret == ERR_OK && b2 && n2 );

    char key[MAX_KEY_LENGTH] = { 0 };
    ret                      = break_repeating_xor_key( b2, n2, key, ARRAY_SIZE( key ) );
    assert( ret == ERR_OK );

    printf( "----------------------------\n" );
    printf( "Key: %s\n", key );
    printf( "----------------------------\n" );
    printf( "%s\n", b2 );

    free( b2 );
    free( b1 );

    return 0;
}