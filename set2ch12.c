#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

typedef struct result
{
    char*  cipher_text;
    size_t ct_len;
} result_t;

static int
blackbox_encrypt( result_t* res, const char* src, size_t src_len, const char* secret, size_t secret_len,
                  const char* key, size_t key_len )
{
    size_t len, padded_len;
    int    ret;
    char*  buffer = NULL;
    len           = src_len + secret_len + AES_BLOCK_SIZE;
    buffer        = (char*) malloc( len );
    if( !buffer ) return ERR_INSUFFICIENT_MEMORY;

    static const char IV[AES_BLOCK_SIZE] = { 0 };

    assert( res );
    assert( src );

    if( src_len ) { memcpy( buffer, src, src_len ); }

    memcpy( buffer + src_len, secret, secret_len );
    ret = cp_pkcs7_pad_inplace( &padded_len, buffer, len, src_len + secret_len, AES_BLOCK_SIZE );
    if( ret == ERR_OK )
    {
        ret = cp_aes_ecb_encrypt( &res->cipher_text, &res->ct_len, buffer, padded_len, key, key_len, MODE_BINARY );
    }

    return ret;
}

int
main( void )
{
    size_t i, k;

    char input[1024]     = { 0 };
    char plaintext[1024] = { 0 };

    char unknown_key[AES_KEY_SIZE] = { 0 };

    static const char* SECRET_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                       "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                       "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                       "YnkK";
    char*  secret_string = NULL;
    size_t ss_len        = 0;
    int    ret = cp_base64_decode( &secret_string, &ss_len, SECRET_STRING, strlen( SECRET_STRING ), MODE_TEXT );
    assert( ret == ERR_OK && secret_string && ss_len );
    ret = cp_generate_random_string( unknown_key, AES_KEY_SIZE, AES_KEY_SIZE );
    assert( ret == ERR_OK );

    /* Step 1. determine size of the cypher */
    size_t ct_len = 0, block_size = 0;
    for( i = 0; i < 64; i++ )
    {
        input[i] = 'A';
        result_t res;
        memset( &res, 0, sizeof( result_t ) );
        ret = blackbox_encrypt( &res, input, i + 1, secret_string, ss_len, unknown_key, ARRAY_SIZE(unknown_key) );
        assert( ret == ERR_OK && res.cipher_text && res.ct_len );

        if( ct_len > 0 && res.ct_len > ct_len )
        {
            block_size = res.ct_len - ct_len;
            free( res.cipher_text );
            break;
        }
        ct_len = res.ct_len;
        free( res.cipher_text );
    }

    assert( block_size == AES_BLOCK_SIZE );
    printf( "1. block size: %zu\n", block_size );

    /* Step 2. Detect that function uses ECB. */
    memset( &input, 0, ARRAY_SIZE( input ) );
    int reps = cp_count_ecb_repetitions( input, ARRAY_SIZE( input ), block_size );
    assert( reps > 0 );
    printf( "2. %s detected\n", reps ? "ECB" : "CBC" );

    /* 3. Decipher string */
    size_t prefix_len, curr_i;
    curr_i = 0;
    for( k = 0; k < ss_len; k++ )
    {
        prefix_len = ( block_size - ( curr_i + 1 ) ) % block_size;
        memset( &input, 'A', prefix_len );

        result_t res_outer;
        memset( &res_outer, 0, sizeof( result_t ) );
        ret = blackbox_encrypt( &res_outer, input, prefix_len, secret_string, ss_len, unknown_key,
                                ARRAY_SIZE( unknown_key ) );
        assert( ret == ERR_OK && res_outer.cipher_text && res_outer.ct_len );

        for( i = 0; i < 256; i++ )
        {
            memset( &input, 'A', prefix_len );
            if( curr_i ) memcpy( input + prefix_len, plaintext, curr_i );
            input[prefix_len + curr_i] = (char) i;
            result_t res_inner;
            memset( &res_inner, 0, sizeof( result_t ) );
            ret = blackbox_encrypt( &res_inner, input, prefix_len + curr_i + 1, secret_string, ss_len, unknown_key,
                                    ARRAY_SIZE( unknown_key ) );
            assert( ret == ERR_OK && res_inner.cipher_text && res_inner.ct_len );

            if( !memcmp( res_inner.cipher_text, res_outer.cipher_text, prefix_len + curr_i + 1 ) )
            {
                plaintext[curr_i] = (char) i;
                ++curr_i;
                free( res_inner.cipher_text );
                break;
            }
            free( res_inner.cipher_text );
        }
        free( res_outer.cipher_text );
    }
    plaintext[curr_i] = 0;

    printf( "3. real secret string:\n\n%s\n\n", secret_string );
    printf( "3. discovered secret string:\n\n%s\n\n", plaintext );

    free( secret_string );

    return 0;
}