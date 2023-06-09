#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

/*
* See https://stackoverflow.com/questions/822323/how-to-generate-a-random-int-in-c
*/
static int
randint( int n )
{
    int r, end;
    assert( n > 0 && n <= RAND_MAX );

    if( ( n - 1 ) == RAND_MAX ) { return rand(); }
    else
    {
        end = RAND_MAX / n;
        end *= n;

        while( ( r = rand() ) >= end )
            ;

        return r % n;
    }
}

static void
generate_random_sequence( char* dst, size_t dst_len, int seq_len )
{
    int i;
    assert( dst && dst_len );
    assert( dst_len >= seq_len );

    static const char* s_lookup = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]";

    for( i = 0; i < seq_len; i++ ) dst[i] = s_lookup[randint( 64 )];
}

void
pkcs7_pad_inplace( char* buffer, size_t* out_len, size_t buffer_len, size_t src_len, size_t blk_len )
{
    size_t pad_len;

    //assert( dst && dst_len );
    //assert( src && src_len && blk_len );
    //assert( mode == MODE_BINARY || mode == MODE_TEXT );

    //if( !dst || !dst_len || !src || !src_len || !blk_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    //{
    //    return ERR_INVALID_ARGUMENT;
    //}

    pad_len = src_len % blk_len ? blk_len - src_len % blk_len : 0;
    assert( src_len + pad_len <= buffer_len );

    if( pad_len ) { memset( buffer + src_len, (int) pad_len, pad_len ); }
    *out_len = src_len + pad_len;
}

#define CBC_ENCRYPTION 0
#define ECB_ENCRYPTION 1

#define MAX_PREFIX_LEN  5
#define MAX_POSTFIX_LEN 5

typedef struct result
{
    char   key[AES_BLOCK_SIZE];
    int    encryption;
    char*  encrypted_text;
    size_t elen;

} result_t;

static void
encryption_oracle( result_t* res, const char* src, size_t src_len )
{
    size_t len, xlen;
    int    n1, n2, ret;
    char*  buffer = NULL;
    n1            = 5 + randint( MAX_PREFIX_LEN );
    n2            = 5 + randint( MAX_POSTFIX_LEN );
    len           = n1 + src_len + n2 + AES_BLOCK_SIZE;
    buffer        = (char*) malloc( len );

    static const char IV[AES_BLOCK_SIZE] = { 0 };

    assert( res );
    assert( src && src_len );

    generate_random_sequence( buffer, len, n1 );
    memcpy( buffer + n1, src, src_len );
    generate_random_sequence( buffer + n1 + src_len, len - n1 - src_len, n2 );
    pkcs7_pad_inplace( buffer, &xlen, len, n1 + src_len + n2, AES_BLOCK_SIZE );

    generate_random_sequence( res->key, AES_BLOCK_SIZE, AES_BLOCK_SIZE );
    if( randint( 2 ) == 0 )
    {
        res->encryption = CBC_ENCRYPTION;

        ret = CP_aes_cbc_encrypt( &res->encrypted_text, &res->elen, buffer, xlen, res->key, AES_BLOCK_SIZE, IV,
                                  strlen( IV ), MODE_BINARY );
        assert( ret == ERR_OK && res->encrypted_text && res->elen );
    }
    else
    {
        res->encryption = ECB_ENCRYPTION;
        ret =
            CP_aes_ecb_encrypt( &res->encrypted_text, &res->elen, buffer, xlen, res->key, AES_BLOCK_SIZE, MODE_BINARY );
        assert( ret == ERR_OK && res->encrypted_text && res->elen );
    }
}

static int
count_ecb_repetitions( const char* line, size_t n1 )
{
    int    ret, reps;
    size_t i, j, n_chunks;
    char   key = '\0';
    size_t n2  = 0;
    char*  s1  = NULL;

    assert( n1 && line );

    n_chunks = n1 / AES_BLOCK_SIZE;
    assert( n1 % AES_BLOCK_SIZE == 0 );

    reps = 1;
    for( i = 0; i < n_chunks - 1; i++ )
    {
        for( j = i + 1; j < n_chunks; j++ )
        {
            ret = memcmp( (const char*) line + i * AES_BLOCK_SIZE, (const char*) line + j * AES_BLOCK_SIZE,
                          AES_BLOCK_SIZE );
            if( !ret ) reps += 1;
        }
    }
    return reps;
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
        encryption_oracle( &res, INPUT, strlen( INPUT ) );
        reps = count_ecb_repetitions( res.encrypted_text, res.elen );

        if( reps > 1 ) { assert( res.encryption == ECB_ENCRYPTION ); }

        printf( "detected: %s, used: %s\n", ( reps > 1 ? "ECB" : "CBC" ),
                ( res.encryption == ECB_ENCRYPTION ? "ECB" : "CBC" ) );

        free( res.encrypted_text );
    }

    return 0;
}