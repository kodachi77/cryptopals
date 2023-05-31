#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main( void )
{
    char * byte_buffer, *encoded_buffer;
    size_t i, blen, elen;
    int    ret;

    // first 5 test strings are from wiki
    static const char* s_hexString[] = {
        "6c696768742077",
        "6c6967687420776f",
        "6c6967687420776f72",
        "6c6967687420776f726b",
        "6c6967687420776f726b2e",
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    };

    static const char* s_base64String[] = {
        "bGlnaHQgdw==",     "bGlnaHQgd28=",     "bGlnaHQgd29y",
        "bGlnaHQgd29yaw==", "bGlnaHQgd29yay4=", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" };

    for( i = 0; i < 6; i++ )
    {
        ret = hex2bytes( &byte_buffer, &blen, s_hexString[i], strlen( s_hexString[i] ), MODE_BINARY );
        assert( !ret );

        ret = b64_encode( &encoded_buffer, &elen, byte_buffer, blen, MODE_TEXT );
        assert( !ret );
        assert( !strcmp( encoded_buffer, s_base64String[i] ) );

        if( i == 5 ) printf( "%s\n", encoded_buffer );

        free( byte_buffer );
        free( encoded_buffer );
    }

    return 0;
}