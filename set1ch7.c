#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    char * base64_data = NULL, *binary_data = NULL, *plaintext = NULL;
    size_t b64_len = 0, b_len = 0, pt_len = 0;

    int ret = cp_read_all( &base64_data, &b64_len, "set1ch7.txt", MODE_BINARY );
    assert( ret == ERR_OK && base64_data && b64_len );

    ret = cp_base64_decode( &binary_data, &b_len, base64_data, b64_len, MODE_BINARY );
    assert( ret == ERR_OK && binary_data && b_len );

    static const unsigned char* AES_KEY = "YELLOW SUBMARINE";

    ret = cp_aes_ecb_decrypt( &plaintext, &pt_len, binary_data, b_len, AES_KEY, strlen( AES_KEY ), MODE_TEXT );
    assert( ret == ERR_OK && plaintext && pt_len );
    printf( "%s\n", plaintext );

    free( plaintext );
    free( binary_data );
    free( base64_data );

    return 0;
}