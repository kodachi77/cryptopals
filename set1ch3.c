#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    char   key = 0;
    char * s1 = NULL, *plaintext = NULL;
    size_t n1 = 0, text_len = 0;
    int    ret;

    static const char* s_cipherString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    ret = hex2bytes( &s1, &n1, s_cipherString, strlen( s_cipherString ), MODE_BINARY );
    assert( ret == ERR_OK && s1 && n1 );

    ret = break_single_char_xor( &plaintext, &text_len, &key, NULL, s1, n1, MODE_TEXT );
    assert( ret == ERR_OK && plaintext && text_len );

    assert( key == 'X' );
    assert( !strcmp( plaintext, "Cooking MC's like a pound of bacon" ) );

    printf( "key: %c\n", key );
    printf( "decrypted text: %s", plaintext );

    free( s1 );
    free( plaintext );

    return 0;
}