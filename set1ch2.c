#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main( void )
{
    char * s1 = NULL, *s2 = NULL, *text_buffer = NULL, *hex_buffer = NULL;
    size_t n1 = 0, n2 = 0, tlen = 0, hlen = 0;
    int    ret;

    static const char* s_String1 = "1c0111001f010100061a024b53535009181c";
    static const char* s_String2 = "686974207468652062756c6c277320657965";

    ret = hex2bytes( &s1, &n1, s_String1, strlen( s_String1 ), MODE_BINARY );
    ret += hex2bytes( &s2, &n2, s_String2, strlen( s_String2 ), MODE_BINARY );
    assert( ret == ERR_OK && s1 && n1 && s2 && n2 );

    ret = apply_repeating_xor( &text_buffer, &tlen, s1, n1, s2, n2, MODE_TEXT );
    assert( ret == ERR_OK && text_buffer && tlen );
    ret = bytes2hex( &hex_buffer, &hlen, text_buffer, tlen, MODE_TEXT );
    assert( ret == ERR_OK && hex_buffer && hlen );

    assert( !strcmp( hex_buffer, "746865206b696420646f6e277420706c6179" ) );

    printf( "%s\n", hex_buffer );

    free( s1 );
    free( s2 );
    free( text_buffer );
    free( hex_buffer );

    return 0;
}