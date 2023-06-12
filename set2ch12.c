#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

typedef struct result
{
    char*  encrypted_text;
    size_t elen;
} result_t;

static void
blackbox_encrypt( result_t* res, const char* src, size_t src_len, const char* secret, size_t secret_len,
                  const char* key, size_t key_len )
{
    size_t len, padded_len;
    int    ret;
    char*  buffer = NULL;
    len           = src_len + secret_len + AES_BLOCK_SIZE;
    buffer        = (char*) malloc( len );
    if( !buffer ) return;

    static const char IV[AES_BLOCK_SIZE] = { 0 };

    assert( res );
    assert( src );

    if( src_len ) { memcpy( buffer, src, src_len ); }

    memcpy( buffer + src_len, secret, secret_len );
    cp_pkcs7_pad_inplace( &padded_len, buffer, len, src_len + secret_len, AES_BLOCK_SIZE );

    ret = cp_aes_ecb_encrypt( &res->encrypted_text, &res->elen, buffer, padded_len, key, key_len, MODE_BINARY );
    assert( ret == ERR_OK && res->encrypted_text && res->elen );
}

int
main( void )
{
    int      ret, reps;
    result_t res, my_res;

    char*  secret_string = NULL;
    size_t i, k, ss_len, elen = 0, block_size = 0;

    size_t prefix_len, curr_byte;

    char input[1024]     = { 0 };
    char plaintext[1024] = { 0 };

    char unknown_key[AES_BLOCK_SIZE];

    static const char* SECRET_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                       "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                       "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                       "YnkK";

    ret = cp_base64_decode( &secret_string, &ss_len, SECRET_STRING, strlen( SECRET_STRING ), MODE_TEXT );
    cp_generate_random_string( unknown_key, AES_BLOCK_SIZE, AES_BLOCK_SIZE );

    /* Step 1. determine size of the cypher */
    for( i = 0; i < 64; i++ )
    {
        input[i] = 'A';
        memset( &res, 0, sizeof( result_t ) );
        blackbox_encrypt( &res, input, i + 1, secret_string, strlen( secret_string ), unknown_key,
                          sizeof( unknown_key ) / sizeof( char ) );
        if( elen > 0 && res.elen > elen )
        {
            block_size = res.elen - elen;
            free( res.encrypted_text );
            break;
        }
        elen = res.elen;
        free( res.encrypted_text );
    }

    assert( block_size == AES_BLOCK_SIZE );
    printf( "1. block size: %zu\n", block_size );

    /* Step 2. Detect that function uses ECB. */
    memset( &input, 0, sizeof( input ) / sizeof( char ) );
    reps = cp_count_ecb_repetitions( input, 1024, block_size );
    assert( reps > 0 );
    printf( "2. %s detected\n", reps ? "ECB" : "CBC" );

    /* 3. Decipher string */
    curr_byte = 0;
    for( k = 0; k < strlen( secret_string ); k++ )
    {
        prefix_len = ( block_size - ( curr_byte + 1 ) ) % block_size;
        memset( &input, 'A', prefix_len );

        memset( &my_res, 0, sizeof( result_t ) );
        blackbox_encrypt( &my_res, input, prefix_len, secret_string, strlen( secret_string ), unknown_key,
                          sizeof( unknown_key ) / sizeof( char ) );

        for( i = 0; i < 256; i++ )
        {
            memset( &input, 'A', prefix_len );
            if( curr_byte ) memcpy( input + prefix_len, plaintext, curr_byte );
            input[prefix_len + curr_byte] = (char) i;

            memset( &res, 0, sizeof( result_t ) );
            blackbox_encrypt( &res, input, prefix_len + curr_byte + 1, secret_string, strlen( secret_string ),
                              unknown_key, sizeof( unknown_key ) / sizeof( char ) );

            if( !memcmp( res.encrypted_text, my_res.encrypted_text, prefix_len + curr_byte + 1 ) )
            {
                plaintext[curr_byte] = (char) i;
                ++curr_byte;
                break;
            }
        }
    }
    plaintext[curr_byte] = 0;

    printf( "3. real secret string:\n\n%s\n\n", secret_string );
    printf( "3. discovered secret string:\n\n%s\n\n", plaintext );

    free( secret_string );

    return 0;
}