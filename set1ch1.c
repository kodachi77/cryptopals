#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    /* The first 5 test strings are examples from Wikipedia. */
    static const char* const HEX_STRING[] = {
        "6c696768742077",
        "6c6967687420776f",
        "6c6967687420776f72",
        "6c6967687420776f726b",
        "6c6967687420776f726b2e",
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    };

    static const char* const BASE64_STRING[] = {
        "bGlnaHQgdw==",     "bGlnaHQgd28=",     "bGlnaHQgd29y",
        "bGlnaHQgd29yaw==", "bGlnaHQgd29yay4=", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" };

    static_assert( ARRAY_SIZE( HEX_STRING ) == ARRAY_SIZE( BASE64_STRING ), "Array sizes must match." );

    for( size_t i = 0; i < ARRAY_SIZE( HEX_STRING ); i++ )
    {
        char * byte_buffer = NULL, *encoded_buffer = NULL;
        size_t bb_len = 0, eb_len = 0;

        int ret = cp_hex2bytes( &byte_buffer, &bb_len, HEX_STRING[i], strlen( HEX_STRING[i] ), MODE_BINARY );
        assert( ret == ERR_OK && byte_buffer && bb_len );

        ret = cp_base64_encode( &encoded_buffer, &eb_len, byte_buffer, bb_len, MODE_TEXT );
        assert( ret == ERR_OK && encoded_buffer && eb_len );

        assert( !strcmp( encoded_buffer, BASE64_STRING[i] ) );

        if( i == ARRAY_SIZE( HEX_STRING ) - 1 ) printf( "%s\n", encoded_buffer );

        free( byte_buffer );
        free( encoded_buffer );
    }

    return 0;
}