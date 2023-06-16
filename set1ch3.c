#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    char   key = 0;
    char*  b1  = NULL;
    size_t n1  = 0;
    int    ret;

    static const char* CIPHER_STRING = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    ret = cp_hex2bytes( &b1, &n1, CIPHER_STRING, strlen( CIPHER_STRING ), MODE_TEXT );
    assert( ret == ERR_OK && b1 && n1 );

    ret = cp_break_single_char_xor( b1, n1, &key, NULL );
    assert( ret == ERR_OK );

    assert( key == 'X' );
    assert( !strcmp( b1, "Cooking MC's like a pound of bacon" ) );

    printf( "key: '%c'\n", key );
    printf( "decrypted text: %s\n\n", b1 );

    free( b1 );

    return 0;
}