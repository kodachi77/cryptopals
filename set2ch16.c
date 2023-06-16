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

static char IV[AES_BLOCK_SIZE]          = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15 };
static char unknown_key[AES_BLOCK_SIZE] = { 0 };

static int
blackbox_encrypt( block_t* res, const char* prefix, size_t prefix_len, const char* user_input, size_t input_len,
                  const char* postfix, size_t postfix_len, const char* key, size_t key_len, const char* iv,
                  size_t iv_len )
{
    size_t len, padded_len;
    int    ret;
    char*  buffer = NULL;
    len           = prefix_len + input_len + postfix_len + AES_BLOCK_SIZE;
    buffer        = (char*) malloc( len );
    if( !buffer ) return ERR_INSUFFICIENT_MEMORY;

    assert( res );
    assert( prefix && postfix );
    assert( prefix_len && postfix_len );
    assert( key && key_len );

    memcpy( buffer, prefix, prefix_len );
    if( input_len && user_input ) memcpy( buffer + prefix_len, user_input, input_len );
    memcpy( buffer + prefix_len + input_len, postfix, postfix_len );

    ret = cp_pkcs7_pad_inplace( &padded_len, buffer, len, len - AES_BLOCK_SIZE, AES_BLOCK_SIZE );
    if( ret != ERR_OK ) goto end;

    ret = cp_aes_cbc_encrypt( &res->bytes, &res->len, buffer, padded_len, key, key_len, iv, iv_len, MODE_BINARY );
    if( ret != ERR_OK ) goto end;

    assert( ret == ERR_OK && res->bytes && res->len );
end:
    free( buffer );
    return ret;
}

static int
oracle( block_t* res, const char* user_input, size_t input_len )
{
    static const char* prefix      = "comment1=cooking%20MCs;userdata=";
    static const char* postfix     = ";comment2=%20like%20a%20pound%20of%20bacon";
    static int         initialized = 0;

    if( !initialized )
    {
        int ret = cp_generate_random_string( unknown_key, AES_BLOCK_SIZE, AES_BLOCK_SIZE );
        assert( ret == ERR_OK );
        if( ret != ERR_OK ) return ret;

        initialized = 1;
    }
    return blackbox_encrypt( res, prefix, strlen( prefix ), user_input, input_len, postfix, strlen( postfix ),
                             unknown_key, AES_BLOCK_SIZE, IV, AES_BLOCK_SIZE );
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
determine_cbc_prefix_length()
{
    block_t res1, res2;
    size_t  i, n_blocks = 0, block_idx = 0, prefix_len = 0;

    if( oracle( &res1, "A", 1 ) != ERR_OK ) return 0;
    if( oracle( &res2, "B", 1 ) != ERR_OK ) return 0;

    char* s1 = res1.bytes;
    char* s2 = res2.bytes;
    while( *s1++ == *s2++ )
        ;

    free( res1.bytes );
    free( res2.bytes );

    size_t block_aligned_len = s1 - res1.bytes - 1;
    assert( block_aligned_len % AES_BLOCK_SIZE == 0 );

    char input1[AES_BLOCK_SIZE + 1] = { 'A' };
    char input2[AES_BLOCK_SIZE + 1] = { 'A' };

    prefix_len = block_aligned_len;
    for( i = 0; i <= AES_BLOCK_SIZE; i++ )
    {
        input1[i] = 'A';
        input2[i] = 'A';

        input1[i + 1] = 'Z';
        input2[i + 1] = 'z';

        if( oracle( &res1, input1, i + 1 + 1 ) != ERR_OK ) return 0;
        if( oracle( &res2, input2, i + 1 + 1 ) != ERR_OK ) return 0;

        if( !memcmp( res1.bytes + block_aligned_len, res2.bytes + block_aligned_len, AES_BLOCK_SIZE ) )
        {
            prefix_len = block_aligned_len + ( AES_BLOCK_SIZE - i - 1 );
            free( res1.bytes );
            free( res2.bytes );
            break;
        }

        free( res1.bytes );
        free( res2.bytes );
    }

    return prefix_len;
}

int
main( void )
{
    block_t res;

    /* 1. Determine size of the cypher. */
    size_t block_size = determine_aes_block_size();
    assert( block_size == AES_BLOCK_SIZE );
    printf( "1. block size: %zu\n", block_size );

    /* 2. Detect that function uses CBC. */
    char input[1024] = { 0 };

    memset( &input, 0, ARRAY_SIZE( input ) );
    int ret  = oracle( &res, input, ARRAY_SIZE( input ) );
    int reps = cp_count_ecb_repetitions( res.bytes, res.len, block_size );
    assert( reps == 0 );
    printf( "2. %s detected\n", reps ? "ECB" : "CBC" );

    /* 3. Calculate prefix length. */
    size_t prefix_len = determine_cbc_prefix_length();
    printf( "3. prefix length: %zu\n", prefix_len );

    size_t      block_aligned_prefix_len  = block_size + ( block_size - ( prefix_len % block_size ) ) % block_size;
    const char* attack_value              = "AadminAtrue";
    size_t      block_aligned_postfix_len = ( block_size - ( strlen( attack_value ) % block_size ) ) % block_size;

    size_t total_prefix_length = block_aligned_prefix_len + block_aligned_postfix_len;
    if( total_prefix_length ) { memset( input, 'A', total_prefix_length ); }
    memcpy( input + total_prefix_length, attack_value, strlen( attack_value ) );

    ret = oracle( &res, input, total_prefix_length + strlen( attack_value ) );
    assert( ret == ERR_OK );
    res.bytes[prefix_len / AES_BLOCK_SIZE * AES_BLOCK_SIZE + ( AES_BLOCK_SIZE - 11 )] =
        res.bytes[prefix_len / AES_BLOCK_SIZE * AES_BLOCK_SIZE + ( AES_BLOCK_SIZE - 11 )] ^ 'A' ^ ';';

    res.bytes[prefix_len / AES_BLOCK_SIZE * AES_BLOCK_SIZE + ( AES_BLOCK_SIZE - 5 )] =
        res.bytes[prefix_len / AES_BLOCK_SIZE * AES_BLOCK_SIZE + ( AES_BLOCK_SIZE - 5 )] ^ 'A' ^ '=';

    char*  plaintext = NULL;
    size_t pt_len    = 0;
    ret = cp_aes_cbc_decrypt( &plaintext, &pt_len, res.bytes, res.len, unknown_key, AES_BLOCK_SIZE, IV, AES_BLOCK_SIZE,
                              MODE_TEXT );

    cp_dump_bytes( "4. Attacked value: ", plaintext, pt_len );

    assert( strstr( plaintext, ";admin=true;" ) );

    free( plaintext );

    return 0;
}