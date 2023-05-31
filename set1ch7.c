#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tomcrypt.h>

#define KEY_LENGTH 16

int
main( void )
{
    int           cipher, ret, read;
    symmetric_ECB ecb;

    char * base64_data, *binary_data, *plaintext;
    size_t b64len;
    size_t blen;

    ret = read_all( &base64_data, &b64len, "set1ch7.txt", MODE_BINARY );
    assert( !ret );

    ret = b64_decode( &binary_data, &blen, base64_data, b64len, MODE_BINARY );
    assert( !ret && binary_data && blen );

    static const unsigned char* key = "YELLOW SUBMARINE";

    cipher = register_cipher( &aes_desc );
    if( cipher == -1 ) return -1;

    ret = ecb_start( cipher, key, KEY_LENGTH, 0 /* num rounds */, &ecb );
    if( ret != CRYPT_OK ) return -1;

    plaintext = (char*) malloc( blen + 1 );
    memset( plaintext, 0, blen + 1 );

    ret = ecb_decrypt( binary_data, plaintext, blen, &ecb );
    if( ret != CRYPT_OK ) return -1;

    printf( "%s\n", plaintext );

    ecb_done( &ecb );

    free( base64_data );
    free( binary_data );
    free( plaintext );

    return 0;
}