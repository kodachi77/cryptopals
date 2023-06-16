#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main( void )
{
    char*  b1  = strdup( "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" );
    size_t n1  = strlen( b1 );
    int    ret = cp_repeating_xor( b1, n1, "ICE", 3 );
    assert( ret == ERR_OK );

    char*  b2 = NULL;
    size_t n2 = 0;
    ret       = cp_bytes2hex( &b2, &n2, b1, n1, MODE_TEXT );
    assert( ret == ERR_OK && b2 && n2 );

    assert( !strcmp( b2,
                     "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c6"
                     "52a3124333a653e2b2027630c692b20283165286326302e27282f" ) );

    printf( "%s\n", b2 );

    free( b1 );
    free( b2 );

    return 0;
}