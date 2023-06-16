#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    char * b1 = NULL, *b2 = NULL, *b3 = NULL;
    size_t n1 = 0, n2 = 0, n3 = 0;

    /* encrypt-decrypt the same data with padding. */

    static const char* KEY                = "YELLOW SUBMARINE";
    static const char* DATA               = "Simple data whatever we say here.";
    static const char  IV[AES_BLOCK_SIZE] = { 0 };

    int ret = cp_aes_cbc_encrypt( &b1, &n1, DATA, strlen( DATA ), KEY, strlen( KEY ), IV, strlen( IV ), MODE_BINARY );
    assert( ret == ERR_OK && b1 && n1 );

    ret = cp_aes_cbc_decrypt( &b2, &n2, b1, n1, KEY, strlen( KEY ), IV, strlen( IV ), MODE_TEXT );
    assert( ret == ERR_OK && b1 && n1 );

    assert( !strcmp( DATA, b2 ) );

    free( b1 );
    free( b2 );

    /* decrypt the text from the file */

    ret = cp_read_all( &b1, &n1, "set2ch10.txt", MODE_BINARY );
    assert( ret == ERR_OK && b1 && n1 );

    ret = cp_base64_decode( &b2, &n2, b1, n1, MODE_BINARY );
    assert( ret == ERR_OK && b2 && n2 );

    ret = cp_aes_cbc_decrypt( &b3, &n3, b2, n2, KEY, strlen( KEY ), IV, strlen( IV ), MODE_TEXT );
    assert( ret == ERR_OK && b3 && n3 );

    printf( "%s\n", b3 );

    free( b1 );
    free( b2 );
    free( b3 );

    return 0;
}