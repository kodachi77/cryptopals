#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <intrin.h>

//> __builtin_popcount()

#define MAX_KEY_LENGTH 42
#define N_CHUNKS       4

static inline int
hamming_distance( const char* buf1, const char* buf2, size_t len )
{
    size_t i;

    int r = 0;
    for( i = 0; i < len; i++ ) r += __popcnt( buf1[i] ^ buf2[i] );
    return r;
}

int
break_repeating_xor_key( char** out_plaintext, char** out_key, const char* src, size_t src_len )
{
    assert( src_len > MAX_KEY_LENGTH * N_CHUNKS );

    char   chunks[N_CHUNKS][MAX_KEY_LENGTH] = { 0 };
    double hamming_dist[MAX_KEY_LENGTH]     = { 0 };

    char key[MAX_KEY_LENGTH + 1] = { 0 };

    size_t i, j, k, n = 0, key_size;

    char *block, *out_buf;

    double score, min_score;
    int    ret, key_len_candidate;

    const size_t N_COMBINATIONS = N_CHUNKS * ( N_CHUNKS - 1 ) / 2;

    hamming_dist[0] = INT_MAX;
    hamming_dist[1] = INT_MAX;

    for( key_size = 2; key_size < MAX_KEY_LENGTH; ++key_size )
    {
        for( i = 0; i < N_CHUNKS; ++i ) { memcpy( &chunks[i][0], &src[i * key_size], key_size ); }

        hamming_dist[key_size] = 0;
        for( i = 0; i < N_CHUNKS - 1; i++ )
        {
            for( j = i + 1; j < N_CHUNKS; j++ )
            {
                hamming_dist[key_size] += hamming_distance( chunks[i], chunks[j], key_size );
            }
        }
        hamming_dist[key_size] /= 1.0 * N_COMBINATIONS * key_size;
    }

    min_score         = INT_MAX;
    key_len_candidate = -1;
    for( i = 0; i < MAX_KEY_LENGTH; i++ )
    {
        if( hamming_dist[i] < min_score )
        {
            min_score         = hamming_dist[i];
            key_len_candidate = (int) i;
        }
    }
    assert( key_len_candidate >= 0 );

    block = (char*) malloc( src_len / key_len_candidate + 1 );
    if( !block ) return ERR_INSUFFICIENT_MEMORY;

    for( i = 0; i < key_len_candidate; ++i )
    {
        k = 0;
        for( j = i; j < src_len; j += key_len_candidate ) { block[k++] = src[j]; }

        ret = break_single_char_xor( NULL, NULL, &key[i], &score, block, k, MODE_BINARY );
        if( ret ) break;
    }
    free( block );

    key[key_len_candidate] = 0;

    if( !ret )
    {
        ret = apply_repeating_xor( &out_buf, &n, src, src_len, key, key_len_candidate, MODE_TEXT );
        if( ret == ERR_OK )
        {
            *out_plaintext = out_buf;
            *out_key       = _strdup( key );
        }
    }
    return ret;
}

int
main( void )
{
    assert( hamming_distance( "this is a test", "wokka wokka!!!", 14 ) == 37 );

    size_t blen = 0, read = 0;

    char * base64_data = NULL, *binary_data = NULL, *plaintext = NULL, *key = NULL;
    size_t b64len = 0;
    int    ret;

    ret = read_all( &base64_data, &b64len, "set1ch6.txt", MODE_BINARY );
    assert( ret == ERR_OK && base64_data && b64len );

    ret = b64_decode( &binary_data, &blen, base64_data, b64len, MODE_BINARY );
    assert( ret == ERR_OK && binary_data && blen );

    ret = break_repeating_xor_key( &plaintext, &key, binary_data, blen );
    assert( ret == ERR_OK && plaintext && key );

    printf( "----------------------------\n" );
    printf( "Key: %s\n", key );
    printf( "----------------------------\n" );
    printf( "%s\n", plaintext );

    free( plaintext );
    free( key );

    free( binary_data );
    free( base64_data );

    return 0;
}