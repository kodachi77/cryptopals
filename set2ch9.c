#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    char * b1 = NULL, *b2 = NULL;
    size_t n1 = 0, n2 = 0;

    static const char* BLOCK = "YELLOW SUBMARINE";

    int ret = cp_pkcs7_pad( &b1, &n1, BLOCK, strlen( BLOCK ), 20, MODE_BINARY );
    assert( ret == ERR_OK && b1 && n1 );

    ret = cp_pkcs7_unpad( &b2, &n2, b1, n1, MODE_TEXT );
    assert( ret == ERR_OK && b2 && n2 );

    assert( n2 == strlen( BLOCK ) );
    assert( !strcmp( b2, BLOCK ) );

    cp_dump_bytes( "padded string: ", b1, n1 );

    return 0;
}
