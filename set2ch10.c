#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
aes_cbc_encrypt( char** dst, size_t* dst_len, const char* data, size_t data_len, const char* key, size_t key_len,
                 const char* iv, size_t iv_len, int mode )
{
    char*       encrypted = NULL;
    size_t      i, n1 = 0, n2 = 0, n3 = 0, rem = 0, len = 0;
    int         ret;
    const char *s = NULL, *prev = NULL;
    char *      b1 = NULL, *b2 = NULL, *b3 = NULL;

    encrypted = (char*) malloc( data_len + AES_BLOCK_SIZE + mode );
    if( !encrypted ) return ERR_INSUFFICIENT_MEMORY;

    len  = 0;
    prev = iv;
    for( i = 0; i < data_len; i += AES_BLOCK_SIZE )
    {
        s   = data + i;
        rem = i + AES_BLOCK_SIZE < data_len ? AES_BLOCK_SIZE : data_len - i;
        ret = pkcs7_pad( &b1, &n1, s, rem, AES_BLOCK_SIZE, mode );
        ret = apply_repeating_xor( &b2, &n2, b1, n1, prev, AES_BLOCK_SIZE, mode );
        ret = CP_aes_ecb_encrypt( &b3, &n3, b2, n2, key, key_len, mode );
        memcpy( encrypted + i, b3, n3 );
        len += n3;

        free( b1 );
        free( b2 );
        free( b3 );

        prev = encrypted + i;
    }

    if( mode == MODE_TEXT ) { encrypted[len] = 0; }

    *dst     = encrypted;
    *dst_len = len;

    return ERR_OK;
}

int
aes_cbc_decrypt( char** dst, size_t* dst_len, const char* data, size_t data_len, const char* key, size_t key_len,
                 const char* iv, size_t iv_len, int mode )
{
    char*       plaintext = NULL;
    size_t      i, n1 = 0, n2 = 0, n3 = 0, rem = 0, len = 0;
    int         ret;
    const char *s = NULL, *prev = NULL;
    char *      b1 = NULL, *b2 = NULL, *b3 = NULL;

    plaintext = (char*) malloc( data_len + mode );
    if( !plaintext ) return ERR_INSUFFICIENT_MEMORY;

    len  = 0;
    prev = iv;
    for( i = 0; i < data_len; i += AES_BLOCK_SIZE )
    {
        s   = data + i;
        ret = CP_aes_ecb_decrypt( &b1, &n1, s, AES_BLOCK_SIZE, key, key_len, mode );
        ret = apply_repeating_xor( &b2, &n2, b1, n1, prev, AES_BLOCK_SIZE, mode );
        ret = pkcs7_unpad( &b3, &n3, b2, n2, mode );
        memcpy( plaintext + i, b3, n3 );
        len += n3;

        free( b1 );
        free( b2 );
        free( b3 );

        prev = s;
    }

    if( mode == MODE_TEXT ) { plaintext[len] = 0; }

    *dst     = plaintext;
    *dst_len = len;

    return ERR_OK;
}

int
main( void )
{
    char * b1 = NULL, *b2 = NULL, *b3 = NULL;
    size_t n1 = 0, n2 = 0, n3 = 0;
    int    ret;

    /* encrypt-decrypt the same data with padding. */

    static const char* KEY                = "YELLOW SUBMARINE";
    static const char* DATA               = "Simple data whatever we say here.";
    static const char  IV[AES_BLOCK_SIZE] = { 0 };

    char * base64_data = NULL, *binary_data = NULL, *plaintext = NULL;
    size_t b64len = 0, blen = 0, txt_len = 0;

    ret = aes_cbc_encrypt( &b1, &n1, DATA, strlen( DATA ), KEY, strlen( KEY ), IV, strlen( IV ), MODE_TEXT );
    assert( ret == ERR_OK && b1 && n1 );

    ret = aes_cbc_decrypt( &b2, &n2, b1, n1, KEY, strlen( KEY ), IV, strlen( IV ), MODE_TEXT );
    assert( ret == ERR_OK && b1 && n1 );

    assert( !strcmp( DATA, b2 ) );

    /* decrypt the text from the file */

    ret = read_all( &base64_data, &b64len, "set2ch10.txt", MODE_BINARY );
    assert( ret == ERR_OK && base64_data && b64len );

    ret = b64_decode( &binary_data, &blen, base64_data, b64len, MODE_BINARY );
    assert( ret == ERR_OK && binary_data && blen );

    ret = aes_cbc_decrypt( &b3, &n3, binary_data, blen, KEY, strlen( KEY ), IV, strlen( IV ), MODE_TEXT );
    assert( ret == ERR_OK && b3 && n3 );

    printf( "%s\n", b3 );

    free( b1 );
    free( b2 );
    free( b3 );

    return 0;
}