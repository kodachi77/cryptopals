#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#define CBC_ENCRYPTION 0
#define ECB_ENCRYPTION 1

#define MIN_PREFIX_LEN  5
#define MIN_POSTFIX_LEN 5

#define MAX_PREFIX_LEN  5
#define MAX_POSTFIX_LEN 5

typedef struct result
{
    int    encryption;
    char*  cipher_text;
    size_t ct_len;

} result_t;

static void
blackbox_encrypt( result_t* res, const char* src, size_t src_len )
{
    assert( res );
    assert( src && src_len );

    char              key[AES_KEY_SIZE]  = { 0 };
    static const char IV[AES_BLOCK_SIZE] = { 0 };

    int    n1     = MIN_PREFIX_LEN + cp_randint( MAX_PREFIX_LEN );
    int    n2     = MIN_POSTFIX_LEN + cp_randint( MAX_POSTFIX_LEN );
    size_t len    = n1 + src_len + n2 + AES_BLOCK_SIZE;
    char*  buffer = (char*) malloc( len );
    assert( buffer );
    if( !buffer ) return;

    int ret = cp_generate_random_string( buffer, len, n1 );
    assert( ret == ERR_OK );

    memcpy( buffer + n1, src, src_len );
    ret = cp_generate_random_string( buffer + n1 + src_len, len - n1 - src_len, n2 );
    assert( ret == ERR_OK );

    size_t padded_len;
    ret = cp_pkcs7_pad_inplace( &padded_len, buffer, len, n1 + src_len + n2, AES_BLOCK_SIZE );
    assert( ret == ERR_OK );

    ret = cp_generate_random_string( key, AES_KEY_SIZE, AES_KEY_SIZE );
    assert( ret == ERR_OK );
    if( cp_randint( 2 ) == 0 )
    {
        res->encryption = CBC_ENCRYPTION;

        ret = cp_aes_cbc_encrypt( &res->cipher_text, &res->ct_len, buffer, padded_len, key, AES_KEY_SIZE, IV,
                                  AES_BLOCK_SIZE, MODE_BINARY );
        assert( ret == ERR_OK && res->cipher_text && res->ct_len );
    }
    else
    {
        res->encryption = ECB_ENCRYPTION;
        ret = cp_aes_ecb_encrypt( &res->cipher_text, &res->ct_len, buffer, padded_len, key, AES_KEY_SIZE, MODE_BINARY );
        assert( ret == ERR_OK && res->cipher_text && res->ct_len );
    }
}

int
main( void )
{
    int                i, reps;
    result_t           res;
    static const char* INPUT = "Write a function to generate a random AES key; that's just 16 random bytes.\n"
                               "Write a function to generate a random AES key; that's just 16 random bytes.\n"
                               "Write a function to generate a random AES key; that's just 16 random bytes.\n"
                               "Write a function to generate a random AES key; that's just 16 random bytes.\n"
                               "Write a function to generate a random AES key; that's just 16 random bytes.\n";

    for( i = 0; i < 100; i++ )
    {
        memset( &res, 0, sizeof( result_t ) );
        blackbox_encrypt( &res, INPUT, strlen( INPUT ) );
        reps = cp_count_ecb_repetitions( res.cipher_text, res.ct_len, AES_BLOCK_SIZE );
        assert( ( reps > 0 && res.encryption == ECB_ENCRYPTION ) || ( !reps && res.encryption == CBC_ENCRYPTION ) );

        printf( "detected: %s, used: %s\n", ( reps > 0 ? "ECB" : "CBC" ),
                ( res.encryption == ECB_ENCRYPTION ? "ECB" : "CBC" ) );

        free( res.cipher_text );
    }

    return 0;
}