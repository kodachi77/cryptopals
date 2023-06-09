#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    int ret;

    char * base64_data = NULL, *binary_data = NULL, *plaintext = NULL;
    size_t b64len = 0, blen = 0, txt_len = 0;

    ret = read_all( &base64_data, &b64len, "set1ch7.txt", MODE_BINARY );
    assert( ret == ERR_OK && base64_data && b64len );

    ret = b64_decode( &binary_data, &blen, base64_data, b64len, MODE_BINARY );
    assert( ret == ERR_OK && binary_data && blen );

    static const unsigned char* key = "YELLOW SUBMARINE";

    ret = CP_aes_ecb_decrypt( &plaintext, &txt_len, binary_data, blen, key, strlen( key ), MODE_TEXT );
    assert( ret == ERR_OK && plaintext && txt_len );
    printf( "%s\n", plaintext );

    free( plaintext );
    free( binary_data );
    free( base64_data );

    return 0;
}