#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#define ALIGN_UP( x, n ) ( size_t )( ( ~( n - 1 ) ) & ( ( x ) + ( n - 1 ) ) )

typedef struct block
{
    char*  bytes;
    size_t len;
} block_t;

static int
blackbox_encrypt( block_t* res, const char* random_prefix, size_t prefix_len, const char* user_input, size_t input_len,
                  const char* target_bytes, size_t target_len, const char* key, size_t key_len )
{
    size_t len, padded_len;
    int    ret;
    char*  buffer = NULL;
    len           = prefix_len + input_len + target_len + AES_BLOCK_SIZE;
    buffer        = (char*) malloc( len );
    if( !buffer ) return ERR_INSUFFICIENT_MEMORY;

    assert( res );
    assert( random_prefix && target_bytes );
    assert( prefix_len && target_len );
    assert( key && key_len );

    memcpy( buffer, random_prefix, prefix_len );
    if( input_len && user_input ) memcpy( buffer + prefix_len, user_input, input_len );
    memcpy( buffer + prefix_len + input_len, target_bytes, target_len );

    ret = cp_pkcs7_pad_inplace( &padded_len, buffer, len, len - AES_BLOCK_SIZE, AES_BLOCK_SIZE );
    if( ret != ERR_OK ) goto end;

    ret = cp_aes_ecb_encrypt( &res->bytes, &res->len, buffer, padded_len, key, key_len, MODE_BINARY );
    if( ret != ERR_OK ) goto end;

    assert( ret == ERR_OK && res->bytes && res->len );
end:
    free( buffer );
    return ret;
}

static int
oracle( block_t* res, const char* user_input, size_t input_len )
{
    static char   unknown_key[AES_BLOCK_SIZE]        = { 0 };
    static char   unknown_prefix[4 * AES_BLOCK_SIZE] = { 0 };
    static char*  target_string                      = NULL;
    static size_t target_len                         = 0;

    static size_t prefix_len  = 0;
    static int    initialized = 0;

    static const char* TARGET_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                       "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                       "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                       "YnkK";

    if( !initialized )
    {
        /* we are going to ignore the target_string leak. */
        int ret = cp_base64_decode( &target_string, &target_len, TARGET_STRING, strlen( TARGET_STRING ), MODE_TEXT );
        assert( ret == ERR_OK && target_string && target_len );
        if( ret != ERR_OK ) return ret;

        prefix_len = AES_BLOCK_SIZE + cp_randint( 3 * AES_BLOCK_SIZE );
        ret        = cp_generate_random_string( unknown_key, AES_BLOCK_SIZE, AES_BLOCK_SIZE );
        assert( ret == ERR_OK );
        if( ret != ERR_OK ) return ret;

        ret = cp_generate_random_string( unknown_prefix, 4 * AES_BLOCK_SIZE, (int) prefix_len );
        assert( ret == ERR_OK );
        if( ret != ERR_OK ) return ret;

        initialized = 1;
    }
    return blackbox_encrypt( res, unknown_prefix, prefix_len, user_input, input_len, target_string, target_len,
                             unknown_key, AES_BLOCK_SIZE );
}

#define MAX_BLOCK_SIZE ( 4 * AES_BLOCK_SIZE )

static size_t
determine_aes_block_size()
{
    char    input[MAX_BLOCK_SIZE] = { 0 };
    block_t res;
    size_t  i, len = 0, block_size = 0;

    for( i = 0; i < MAX_BLOCK_SIZE; i++ )
    {
        input[i] = 'A';
        memset( &res, 0, sizeof( block_t ) );
        if( oracle( &res, input, i + 1 ) != ERR_OK ) return 0;
        free( res.bytes );

        if( len > 0 && res.len > len )
        {
            block_size = res.len - len;
            break;
        }
        len = res.len;
    }
    return block_size;
}

static size_t
count_consecutive_blocks( size_t* block_idx, const block_t* src )
{
    size_t i, count = 1;

    assert( block_idx && src && src->bytes && src->len );
    if( !block_idx || !src || !src->bytes || !src->len ) return count;

    for( i = 0; i < src->len; i += AES_BLOCK_SIZE )
    {
        if( i + 2 * AES_BLOCK_SIZE < src->len )
        {
            if( !memcmp( src->bytes + i, src->bytes + i + AES_BLOCK_SIZE, AES_BLOCK_SIZE ) )
            {
                *block_idx = i / AES_BLOCK_SIZE;
                count += 1;
                break;
            }
        }
    }
    return count;
}

static size_t
determine_cbc_prefix_length()
{
    char    input[3 * AES_BLOCK_SIZE] = { 0 };
    block_t res;
    size_t  i, n_blocks = 0, block_idx = 0, prefix_len = 0;

    memset( input, 'A', 2 * AES_BLOCK_SIZE );
    for( i = 0; i < AES_BLOCK_SIZE; i++ )
    {
        input[2 * AES_BLOCK_SIZE + i] = 'A';

        memset( &res, 0, sizeof( block_t ) );
        if( oracle( &res, input, 2 * AES_BLOCK_SIZE + i ) != ERR_OK ) return 0;
        n_blocks = count_consecutive_blocks( &block_idx, &res );
        free( res.bytes );

        if( n_blocks == 2 )
        {
            prefix_len = block_idx ? block_idx * AES_BLOCK_SIZE - i : i;
            break;
        }
    }

    return prefix_len;
}

static size_t
determine_padding_size()
{
    char    input[MAX_BLOCK_SIZE] = { 0 };
    block_t res;
    size_t  i, zero_message_len = 0, string_size = 0;

    if( oracle( &res, NULL, 0 ) != ERR_OK ) return 0;
    free( res.bytes );

    zero_message_len = res.len;

    for( i = 0; i < AES_BLOCK_SIZE; i++ )
    {
        input[i] = 'A';
        if( oracle( &res, input, i + 1 ) != ERR_OK ) return 0;
        free( res.bytes );

        if( res.len > zero_message_len )
        {
            string_size = i;
            break;
        }
    }
    return string_size;
}

int
main( void )
{
    int     ret, reps;
    block_t res, outer_res;

    char * secret_string = NULL;
    size_t i, k;


    char input[1024]     = { 0 };
    char plaintext[1024] = { 0 };

    /* 1. Determine size of the cypher. */
    size_t block_size = determine_aes_block_size();
    assert( block_size == AES_BLOCK_SIZE );
    printf( "1. block size: %zu\n", block_size );

    /* 2. Detect that function uses ECB. */
    memset( &input, 0, ARRAY_SIZE( input ) );
    reps = cp_count_ecb_repetitions( input, ARRAY_SIZE( input ), block_size );
    assert( reps > 0 );
    printf( "2. %s detected\n", reps ? "ECB" : "CBC" );

    /* 3. Calculate prefix length. */
    size_t prefix_len = determine_cbc_prefix_length();
    assert( prefix_len > 0);
    printf( "3. prefix length: %zu\n", prefix_len );

    size_t padding_size = determine_padding_size();
    assert( padding_size > 0 );
    printf( "4. padding length: %zu\n", padding_size );

    ret = oracle( &res, NULL, 0 );
    assert( ret == ERR_OK && res.bytes && res.len );
    free( res.bytes );
    size_t secret_len = res.len - prefix_len - padding_size;
    printf( "5. target string length: %zu\n", secret_len );

    /* 3. Decipher string */
    size_t curr_i = 0;
    for( k = 0; k < secret_len; k++ )
    {
        size_t plen = ( ALIGN_UP( prefix_len, AES_BLOCK_SIZE ) - prefix_len )
               + ( block_size - ( curr_i + 1 ) ) % block_size;

        memset( &input, 'A', plen );

        memset( &outer_res, 0, sizeof( block_t ) );
        ret = oracle( &outer_res, input, plen );
        assert( ret == ERR_OK && outer_res.bytes && outer_res.len );

        for( i = 0; i < 256; i++ )
        {
            memset( &input, 'A', plen );
            if( curr_i ) memcpy( input + plen, plaintext, curr_i );
            input[plen + curr_i] = (char) i;

            memset( &res, 0, sizeof( block_t ) );
            ret = oracle( &res, input, plen + curr_i + 1 );
            assert( ret == ERR_OK && res.bytes && res.len );

            if( !memcmp( res.bytes, outer_res.bytes, prefix_len + plen + curr_i + 1 ) )
            {
                plaintext[curr_i] = (char) i;
                ++curr_i;
                free( res.bytes );
                break;
            }
            free( res.bytes );
        }
        free( outer_res.bytes );
    }

    plaintext[curr_i] = 0;

    printf( "6. discovered secret string:\n\n%s\n\n", plaintext );

    free( secret_string );

    return 0;
}