#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    char * b1 = NULL, *b2 = NULL, *hex_string = NULL;
    size_t n1 = 0, n2 = 0, hs_len = 0;
    int    ret;

    static const char* const HEX_STRING1 = "1c0111001f010100061a024b53535009181c";
    static const char* const HEX_STRING2 = "686974207468652062756c6c277320657965";

    ret = cp_hex2bytes( &b1, &n1, HEX_STRING1, strlen( HEX_STRING1 ), MODE_BINARY );
    ret += cp_hex2bytes( &b2, &n2, HEX_STRING2, strlen( HEX_STRING2 ), MODE_BINARY );
    assert( ret == ERR_OK && b1 && n1 && b2 && n2 && n1 == n2 );

    ret = cp_block_xor( b1, b2, n1 );
    assert( ret == ERR_OK );

    ret = cp_bytes2hex( &hex_string, &hs_len, b1, n1, MODE_TEXT );
    assert( ret == ERR_OK && hex_string && hs_len );

    assert( !strcmp( hex_string, "746865206b696420646f6e277420706c6179" ) );

    printf( "%s\n", hex_string );

    free( b1 );
    free( b2 );
    free( hex_string );

    return 0;
}