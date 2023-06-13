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
    char*  encrypted_text;
    size_t elen;

} result_t;

static void
blackbox_encrypt( result_t* res, const char* src, size_t src_len )
{
    size_t len, padded_len;
    int    n1, n2, ret;
    char*  buffer              = NULL;
    char   key[AES_BLOCK_SIZE] = { 0 };

    static const char IV[AES_BLOCK_SIZE] = { 0 };

    n1     = MIN_PREFIX_LEN + cp_randint( MAX_PREFIX_LEN );
    n2     = MIN_POSTFIX_LEN + cp_randint( MAX_POSTFIX_LEN );
    len    = n1 + src_len + n2 + AES_BLOCK_SIZE;
    buffer = (char*) malloc( len );

    assert( res );
    assert( src && src_len );

    cp_generate_random_string( buffer, len, n1 );
    memcpy( buffer + n1, src, src_len );
    cp_generate_random_string( buffer + n1 + src_len, len - n1 - src_len, n2 );
    cp_pkcs7_pad_inplace( &padded_len, buffer, len, n1 + src_len + n2, AES_BLOCK_SIZE );

    cp_generate_random_string( key, AES_BLOCK_SIZE, AES_BLOCK_SIZE );
    if( cp_randint( 2 ) == 0 )
    {
        res->encryption = CBC_ENCRYPTION;

        ret = cp_aes_cbc_encrypt( &res->encrypted_text, &res->elen, buffer, padded_len, key, AES_BLOCK_SIZE, IV,
                                  AES_BLOCK_SIZE, MODE_BINARY );
        assert( ret == ERR_OK && res->encrypted_text && res->elen );
    }
    else
    {
        res->encryption = ECB_ENCRYPTION;
        ret             = cp_aes_ecb_encrypt( &res->encrypted_text, &res->elen, buffer, padded_len, key, AES_BLOCK_SIZE,
                                  MODE_BINARY );
        assert( ret == ERR_OK && res->encrypted_text && res->elen );
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
        reps = cp_count_ecb_repetitions( res.encrypted_text, res.elen, AES_BLOCK_SIZE );
        assert( ( reps > 0 && res.encryption == ECB_ENCRYPTION ) || ( !reps && res.encryption == CBC_ENCRYPTION ) );

        printf( "detected: %s, used: %s\n", ( reps > 0 ? "ECB" : "CBC" ),
                ( res.encryption == ECB_ENCRYPTION ? "ECB" : "CBC" ) );

        free( res.encrypted_text );
    }

    return 0;
}